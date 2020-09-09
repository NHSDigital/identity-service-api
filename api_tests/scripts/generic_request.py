import requests
import json
from urllib import parse
import re
from api_tests.config_files import config


class GenericRequest:
    """ This is a base class for OAuth requests used for holding
    reusable components & functions that can be shared between test cases"""
    def __init__(self):
        self.session = requests.Session()
        self.endpoints = config.ENDPOINTS

    def get_response(self, verb: str, endpoint: str, **kwargs) -> 'response type':
        """Verify the arguments and then send a request and return the response"""
        # Verify endpoint exists
        try:
            self.endpoints[endpoint]
        except KeyError:
            raise Exception("Endpoint not found")

        # Verify http verb is valid
        if verb.lower() not in ['post', 'get']:
            raise Exception(f"Verb: {verb} is invalid")

        func = (self.get, self.post)[verb.lower() == 'post']

        # Get response
        return func(self.endpoints[endpoint], **kwargs)

    @staticmethod
    def _validate_response(response: 'response type') -> None:
        """Verifies the response provided is of a valid response type"""
        if not type(response) == requests.models.Response:
            raise TypeError("Expected response type object for response argument")

    @staticmethod
    def _verify_status_code(status_code: int or str) -> None:
        """Verifies the status code provided is a valid status code"""
        if not type(status_code) == int:
            try:
                int(status_code)
            except ValueError:
                raise TypeError('Status code must only consist of numbers')
        else:
            if len(str(status_code)) != 3:
                raise TypeError('Status code must be a 3 digit number')

    def get(self, url: str, **kwargs) -> 'response type':
        """Sends a get request and returns the response"""
        try:
            return self.session.get(url, **kwargs)
        except requests.ConnectionError:
            raise Exception(f"the url: {url} does not exist or is invalid")

    def post(self, url: str, **kwargs) -> 'response type':
        """Sends a post request and returns the response"""
        try:
            return self.session.post(url, **kwargs)
        except requests.ConnectionError:
            raise Exception(f"the url: {url} does not exist or is invalid")

    def get_redirects(self, response: 'response type') -> dict:
        """Returns a list of response objects holding the history of request (url)"""
        self._validate_response(response)

        redirects = {}
        if response.history:
            for i, resp in enumerate(response.history):
                redirects[i] = {'status_code': resp.status_code, 'url': resp.url, 'headers': resp.headers}
        return redirects

    def verify_response_keys(self, response: 'response type', expected_status_code: int, expected_keys: list) -> bool:
        """Check a given response is returning the correct keys.
        In case the content is dynamic we can only check the keys and not the values"""
        self._validate_response(response)

        data = json.loads(response.text)

        if 'error' in data:
            assert data == expected_keys
        else:
            actual_keys = list(data.keys())
            assert sorted(actual_keys) == sorted(expected_keys), \
                "Expected: {sorted(expected_keys)} but got: {sorted(actual_keys)}"

        assert response.status_code == expected_status_code, f"Status code is incorrect, " \
                                                             f"expected {expected_status_code} " \
                                                             f"but got {response.status_code}"
        return True

    def check_status_code(self, response: 'response type', expected_status_code: int) -> bool:
        """Compare the actual and expected status code for a given response"""
        self._validate_response(response)
        self._verify_status_code(expected_status_code)
        return response.status_code == expected_status_code

    def check_endpoint(self, verb: str, endpoint: str, expected_status_code: int,
                       expected_response: dict or str or list, **kwargs) -> bool:
        """Check a given request is returning the expected values. NOTE the expected response can be either a dict,
        a string or a list this is because we can expect either json, html or a list of keys from a json response
        respectively."""
        response = self.get_response(verb, endpoint, **kwargs)

        if type(expected_response) is list:
            return self.verify_response_keys(response, expected_status_code, expected_keys=expected_response)

        # Check response
        return self.verify_response(response, expected_status_code, expected_response=expected_response)

    def check_response_history(self, verb: str, endpoint: str,
                               expected_redirects: dict, **kwargs) -> bool:
        """Check the response redirects for a given request is returning the expected values"""
        response = self.get_response(verb, endpoint, **kwargs)
        actual_redirects = self.get_redirects(response)

        for actual, expected in zip(actual_redirects.values(), expected_redirects.values()):
            url = self.remove_param_from_url(actual['url'], 'state')
            location = self.remove_param_from_url(actual['headers']['Location'], 'state')

            assert actual['status_code'] == expected['status_code'], f"Redirect failed with {expected['status_code']}"
            assert url == expected['url'], "Redirect url not as expected"
            assert location == expected['headers']['Location'], "Location header not as expected"
        return True

    def verify_response(self, response: 'response type', expected_status_code: int,
                        expected_response: dict or str) -> bool:
        """Check a given response has returned the expected key value pairs"""

        assert self.check_status_code(response, expected_status_code), f"Status code is incorrect, " \
                                                                       f"expected {expected_status_code} " \
                                                                       f"but got {response.status_code}"

        try:
            data = json.loads(response.text)
            # Strip out white spaces
            actual_response = dict(
                (k.strip() if isinstance(k, str) else k,
                 v.strip() if isinstance(v, str) else v
                 ) for k, v in data.items()
            )
            assert actual_response == expected_response, "Actual response is different from the expected response"
        except json.JSONDecodeError:
            # Might be HTML
            # We need to get rid of the dynamic state here so we can compare the text to the stored value
            actual_response = re.sub(r'<input name="state" type="hidden" value="\d*">', '', response.text)

            assert actual_response.replace('\n', '').replace(' ', '').strip() == expected_response.replace('\n', '')\
                .replace(' ', '').strip(), "Actual response is different from the expected response"

        return True

    def has_header(self, response: 'response type', header_key: str) -> bool:
        """Confirm if a header exists in the provided response"""
        self._validate_response(response)
        headers = [header.lower() for header in response.headers.keys()]
        return header_key.lower() in headers

    @staticmethod
    def get_params_from_url(url: str) -> dict:
        """Returns all the params and param values from a given url as a dictionary"""
        return dict(parse.parse_qsl(parse.urlsplit(url).query))

    def get_param_from_url(self, url: str, param: str) -> str:
        """Returns a single param and its value as a dictionary"""
        params = self.get_params_from_url(url)
        return params[param]

    def get_all_values_from_json_response(self, response: 'response type') -> dict:
        """Convert json response string into a python dictionary"""
        self._validate_response(response)
        return json.loads(response.text)

    def get_value_from_json_response(self, response: 'response type', key: str) -> str:
        """Returns the content of the response, in unicode"""
        data = self.get_all_values_from_json_response(response)
        try:
            return data[key]
        except KeyError:
            raise Exception(f"Value: {key} not found in response")

    @staticmethod
    def remove_param_from_url(url: str, param_to_remove: str) -> str:
        """This method will remove a given param from a url
        and reconstruct the url before returning it to the user """
        url, query = url.split('?')
        params = query.split('&')

        for i, param in enumerate(params):
            if param.startswith(param_to_remove):
                continue
            if i == 0:
                url += f'?{param}'
            elif param.startswith('goto'):
                key, val = param.split('=')
                # Assuming state is the last param in the goto value url
                # which seems to be the case in all the testing done so far.
                url += f'&{key}={val[:val.index("%26state")]}'
            else:
                url += f'&{param}'
        return url
