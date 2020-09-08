from api_tests.scripts.generic_request import GenericRequest
from api_tests.config_files.config import APIGEE_API_URL, APIGEE_AUTHENTICATION, APIGEE_ENVIRONMENT
import json
import uuid


class ApigeeDebugApi(GenericRequest):
    def __init__(self, proxy: str):
        super(ApigeeDebugApi, self).__init__()
        self.session_name = self._generate_uuid()
        self.proxy = proxy
        self.headers = {'Authorization': 'Basic ' + APIGEE_AUTHENTICATION}

        self.revision = self._get_latest_revision()
        self.create_debug_session()

    @staticmethod
    def _generate_uuid():
        unique_id = uuid.uuid4()
        return str(unique_id)

    def _get_latest_revision(self) -> str:
        url = f"{APIGEE_API_URL}/apis/{self.proxy}/revisions"

        response = self.get(url, headers=self.headers)
        revisions = response.text.strip('[]').replace("\"", "").strip().split(', ')
        return revisions[-1]

    def create_debug_session(self):
        url = f"{APIGEE_API_URL}/environments/{APIGEE_ENVIRONMENT}/apis/{self.proxy}/revisions/{self.revision}/" \
              f"debugsessions?session={self.session_name}"

        response = self.post(url, headers=self.headers)
        assert self.check_status_code(response, 201), f"Unable to create apigee debug session {self.session_name}"

    def _get_transaction_id(self) -> str:
        url = f"{APIGEE_API_URL}/environments/{APIGEE_ENVIRONMENT}/apis/{self.proxy}/revisions/{self.revision}/" \
              f"debugsessions/{self.session_name}/data"

        response = self.get(url, headers=self.headers)
        assert self.check_status_code(response, 200), f"Unable to get apigee transaction id for {self.session_name}"
        return response.text.strip('[]').replace("\"", "").strip().split(', ')[0]

    def _get_transaction_data(self) -> dict:
        transaction_id = self._get_transaction_id()
        url = f"{APIGEE_API_URL}/environments/{APIGEE_ENVIRONMENT}/apis/{self.proxy}/revisions/{self.revision}/" \
              f"debugsessions/{self.session_name}/data/{transaction_id}"

        response = self.get(url, headers=self.headers)
        assert self.check_status_code(response, 200), f"Unable to get apigee transaction {transaction_id}"

        return json.loads(response.text)

    def get_asid(self) -> list:
        asid = []

        data = self._get_transaction_data()
        executions = [x.get('results', None) for x in data['point'] if x.get('id', "") == "Execution"]

        executions = list(filter(lambda x: x != [], executions))

        request_messages = []
        variable_accesses = []

        for result in executions:
            for item in result:
                if item.get('ActionResult', '') == 'RequestMessage':
                    request_messages.append(item)

        for result in executions:
            for item in result:
                if item.get('ActionResult', '') == 'VariableAccess':
                    variable_accesses.append(item)

        for x in request_messages:
            for y in x['headers']:
                if y['name'] == 'NHSD-ASID':
                    asid.append(y['value'])
                    break
            if len(asid) > 0:
                break

        for x in variable_accesses:
            for y in x['accessList']:
                if y.get('Get', {}).get('name', '') == 'app.asid':
                    asid.append(y.get('Get', {}).get('value', None))
                    break
        return asid
