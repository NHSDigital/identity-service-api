from api_tests.scripts.generic_request import GenericRequest
from json import loads, JSONDecodeError
from uuid import uuid4
from requests import Response
from typing import Union


class PdsRecord:
    """This class turns a PDS response into a object."""
    def __init__(self, response: Response):

        if type(response) is dict:
            self.response = response
        else:
            self.status_code = response.status_code
            self.headers = dict(response.headers.items())
            self.redirects = self._get_redirects(response)
            self.url = response.url

            try:
                self.response = loads(response.text)
            except JSONDecodeError:
                raise Exception(f'UNEXPECTED RESPONSE {response.text}:')

        # if the response is a list of entries i.e. a response from a search
        if 'entry' in self.response:
            self.records = [PdsRecord(entry) for entry in self.response.get('entry')]

        # if response is an error
        elif "issue" in self.response:
            self.error = self._parse_error(self.response)

        # if it is not a search or an error then it must be a single retrieve
        else:
            self._construct(self.response)

    @property
    def is_sensitive(self):
        """Stored boolean to identify if patient record is considered sensitive"""
        security = getattr(self, 'security', None)
        if security:
            return (False, True)[security[0]['code'].lower() == 'r' and security[0]['display'].lower() == 'restricted']

    def _construct(self, obj: dict):
        """A recursive method for setting attributes to the instance from a given dictionary"""
        for k, v in obj.items():
            if isinstance(v, dict):
                setattr(self, k, self._construct(v))
            else:
                setattr(self, k, v)

    @staticmethod
    def _get_redirects(response: Response) -> dict:
        redirects = {}
        if response.history:
            for i, resp in enumerate(response.history):
                redirects[i] = {'status_code': resp.status_code, 'url': resp.url, 'headers': resp.headers}
        return redirects

    @staticmethod
    def _parse_error(response: dict) -> dict:
        return {response['resourceType']: response['issue'][0]}

    def _get_error_resource_type(self) -> dict:
        return self.response['resourceType']

    def check_error(self, expected_status_code: int, expected_error_message: str) -> bool:
        if not self.error['status_code'] == expected_status_code:
            return False
        if not self.error['details']['display'] == expected_error_message:
            return False
        return True

    def get_extension_by_url(self, url_contains: str) -> dict:
        """This will return the first match it find."""
        for extension in getattr(self, "extension", {}):
            if url_contains.lower() in extension.get('url', '').lower():
                return extension
            for ext in extension.get('extension', {}):
                if url_contains.lower() in ext.get('url', '').lower():
                    return ext

    def get_consolidated_error(self):
        """Returns a simplified and cleaner version of the error response"""
        details = self.error[self._get_error_resource_type()]['details']['coding'][0]
        details['diagnostics'] = self.error[self._get_error_resource_type()]['diagnostics']
        details['error_resource_type'] = self._get_error_resource_type()
        details['status_code'] = self.status_code
        return details


class PdsRequest(GenericRequest):
    """Send a request to PDS."""
    def __init__(self, token: str, patient_id: Union[int, str] = None, search_params: dict = None, headers: dict = None,
                 base_uri: str = None, proxy: str = None):
        super(PdsRequest, self).__init__()

        self.base_uri = base_uri
        self.proxy = proxy

        if patient_id and search_params:
            raise ValueError('Can only use either a patient ID or Search Params, cant use both')
        if not (patient_id or search_params):
            raise ValueError('Either a patient ID or Search Params must be provided')

        self.base_url = f'{self.base_uri}/{self.proxy}'
        self.patient_id = str(patient_id)
        self._is_patient_valid(self.patient_id)

        if headers:
            self._headers = headers
        else:
            self._headers = {
                'Authorization': f'Bearer {token}',
                'NHSD-Session-URID': 'ROLD-ID',
                'X-Request-ID': str(uuid4()),
            }

        url = (f'{self.base_url}/Patient/{self.patient_id}',
               f'{self.base_url}/Patient?{self.convert_dict_into_params(search_params)}')[search_params is not None]

        self.record = self._get_record(url=url, headers=self._headers)
        self.patched_record = None

    @staticmethod
    def _is_patient_valid(patient_id: Union[int, str]) -> None:
        """Verify if the patient_id provided is characteristically valid"""
        if patient_id != 'None':
            if not patient_id.isdigit():
                raise Exception("Patient id can only contain numbers")
            if len(patient_id) != 10:
                raise Exception("Patient id must be a 10 digit number")

    @staticmethod
    def _is_operation_valid(operation: str) -> None:
        """Confirm operation is valid"""
        if operation.lower() not in {'add', 'remove', 'replace', 'test'}:
            raise Exception("Operation {operation} is invalid")

    def _get_record(self, url: str, **kwargs) -> PdsRecord:
        """Return a PDS record as an object"""
        response = self.get(url, **kwargs)
        return PdsRecord(response)

    def _build_patch_request(self, op: str, path: str, value: Union[int, str, dict]) -> tuple:
        """
        This private method builds the headers and the request body for a patch request to PDS.
        """
        self._is_operation_valid(op)

        # Update headers
        headers = self._headers.copy()
        headers['If-Match'] = f'W/"{getattr(self.record, "versionId")}"'
        headers['Content-Type'] = 'application/json-patch+json'

        # Build payload
        payload = {
            "patches": [{
                "op": op.lower(),
                "path": path,
                "value": value
            }]
        }

        if op == 'remove':
            payload['patches'].insert(0, {
                "op": "test",
                "path": path,
                "value": value
            })

        return payload, headers

    def _poll_patch_request(self, location: str) -> PdsRecord:
        # Polling for fresh data
        response = self.get(f"{self.base_url}{location}",
                            headers=self._headers)
        updated_record = PdsRecord(response)

        if self.patched_record is not None:
            # Not your first patch?
            # Then it will assign the previous patch to self.record to preserve the last 2 records
            self.record = self.patched_record
        self.patched_record = updated_record
        return updated_record

    def patch_record(self, op: str, path: str, value: Union[int, str, dict]) -> None:
        """Send a PATCH request to update the patient"""
        payload, headers = self._build_patch_request(op, path, value)

        # Make patch request
        patch_response = self.patch(f"{self.base_url}/Patient/{self.patient_id}", headers=headers, json=payload)

        if patch_response.status_code in {401, 403, 405}:
            # Access related error response
            self.patched_record = PdsRecord(patch_response)
            return
        elif patch_response.status_code != 202:
            raise Exception(f"UNEXPECTED RESPONSE {patch_response.status_code}: {patch_response.text}")

        try:
            location = patch_response.headers.get('Content-Location')
        except KeyError:
            raise Exception("Patch failed")

        self._poll_patch_request(location)
