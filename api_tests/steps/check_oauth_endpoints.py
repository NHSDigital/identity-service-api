from api_tests.scripts.generic_request import GenericRequest
from api_tests.config_files import config
from api_tests.scripts.authenticator import Authenticator


class CheckOauthEndpoints(GenericRequest):
    def __init__(self):
        super(CheckOauthEndpoints, self).__init__()
        self.endpoints = {
            'authorize': config.AUTHORIZE_URL,
            'token': config.TOKEN_URL,
            'authenticate': config.AUTHENTICATE_URL,
            'api': config.API_URL
        }

    def get_response(self, verb: str, expected_status_code: int, endpoint: str, **kwargs) -> 'response type':
        """Verify the arguments and then send a request and return the response"""
        # Verify status code is a number and of length 3
        if not type(expected_status_code) == int:
            try:
                int(expected_status_code)
            except ValueError:
                raise TypeError('Status code must only consist of numbers')
        if len(str(expected_status_code)) != 3:
            raise TypeError('Status code must be a 3 digit number')

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

    def _get_authorized(self) -> str:
        # Get authorized
        authorize_response = self.get_response('GET', 200, 'authorize', params={
            'client_id': config.CLIENT_ID,
            'redirect_uri': config.REDIRECT_URI,
            'response_type': 'code',
            'state': ''
        }, allow_redirects=False)

        # Confirm request was successful
        assert authorize_response.status_code == 302, f"Authorize request failed with {authorize_response.status_code}"

        # Get login url
        redirect_url = authorize_response.headers['Location']

        # Navigate to Login Page and complete the request
        self.get(redirect_url)
        return self.get_param_from_url(redirect_url, 'state')

    def get_authenticated(self, provider: str) -> str:
        """Get the code parameter value required to post to the oauth /token endpoint"""
        state = self._get_authorized()
        authenticator = Authenticator(self, provider, config.USERNAME, config.PASSWORD, state)
        response = authenticator.authenticate()
        code = authenticator.get_code_from_provider(response)
        return code

    def get_token_response(self, timeout: int = 3000, grant_type: str = 'authorization_code', refresh_token: str = None):
        data = {
            'client_id': config.CLIENT_ID,
            'client_secret': config.CLIENT_SECRET,
            'grant_type': grant_type,
        }
        if refresh_token is not None:
            data['refresh_token'] = refresh_token
            data['_refresh_token_expiry_ms'] = timeout
        else:
            data['redirect_uri'] = config.REDIRECT_URI
            data['code'] = self.get_authenticated(config.AUTHENTICATION_PROVIDER)
            data['_access_token_expiry_ms'] = timeout

        response = self.post(self.endpoints['token'], data=data)
        return self.get_all_values_from_json_response(response)

    def check_endpoint(self, verb: str, endpoint: str, expected_status_code: int,
                       expected_response: dict or str or list, **kwargs) -> bool:
        """Check a given request is returning the expected values. NOTE the expected response can be either a dict,
        a string or a list this is because we can expect either json, html or a list of keys from a json response
        respectively."""
        response = self.get_response(verb, expected_status_code, endpoint, **kwargs)

        if endpoint == 'token':
            return self.verify_response_keys(response, expected_status_code, expected_keys=expected_response)

        # Check response
        return self.verify_response(response, expected_status_code, expected_response=expected_response)

    def check_response_history(self, verb: str, endpoint: str, expected_status_code: int,
                               expected_redirects: dict, **kwargs) -> bool:
        """Check the response redirects for a given request is returning the expected values"""
        response = self.get_response(verb, expected_status_code, endpoint, **kwargs)
        actual_redirects = self.get_redirects(response)

        for actual, expected in zip(actual_redirects.values(), expected_redirects.values()):
            url = self.remove_param_from_url(actual['url'], 'state')
            location = self.remove_param_from_url(actual['headers']['Location'], 'state')

            assert actual['status_code'] == expected['status_code'], f"Redirect failed with {expected['status_code']}"
            assert url == expected['url'], "Redirect url not as expected"
            assert location == expected['headers']['Location'], "Location header not as expected"
        return True
