from api_tests.scripts.base import Base
from api_tests.config_files import config


class CheckOauthEndpoints(Base):
    def __init__(self):
        super(CheckOauthEndpoints, self).__init__()
        self.endpoints = {
            'authorize': config.AUTHORIZE_URL,
            'token': config.TOKEN_URL,
            'authenticate': config.AUTHENTICATE_URL,
        }

    def _get_response(self, verb: str, expected_status_code: int, endpoint: str,
                      params: dict, headers: dict = None, allow_redirects: bool = True) -> 'response type':
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
        return func(self.endpoints[endpoint], params=params, headers=headers, allow_redirects=allow_redirects)

    def _get_auth_id(self, state: str) -> str:
        """Send a request to return the authId required for authenticating a user"""
        params = {
            'goto': "https://am.nhsspit-2.ptl.nhsd-esa.net:443/openam/oauth2/realms/root/realms/oidc/authorize?"
                    "response_type=code"
                    "&client_id=969567331415.apps.national"
                    "&redirect_uri=https://internal-dev.api.service.nhs.uk/oauth2/v1/callback"
                    "&scope=openid"
                    "&state=" + state
        }

        response = self._get_response('POST', expected_status_code=200, endpoint='authenticate',
                                      params=params, headers={'Accept-API-Version': 'protocol=1.0,resource=2.1'})
        return self.get_value_from_response(response, 'authId')

    def _nhs_sign_in(self, auth_id: str, url: str, username: str = config.USERNAME,
                     password: str = config.PASSWORD) -> 'response type':
        """Send a sign in request to get authenticated for a given user"""
        state = self.get_param_from_url(url, 'state')

        payload = {
            "authId": auth_id,
            "template": "",
            "stage": "DataStore1",
            "header": "Sign in",
            "callbacks": [
                {
                    "type": "NameCallback",
                    "output": [{"name": "prompt", "value": "User Name:"}],
                    "input": [{"name": "IDToken1", "value": f"{username}"}]
                },
                {
                    "type": "PasswordCallback",
                    "output": [{"name": "prompt", "value": "Password:"}],
                    "input": [{"name": "IDToken2", "value": f"{password}"}]
                }
            ]
        }

        headers = {
            'Connection': 'keep-alive',
            'Accept-API-Version': 'protocol=1.0,resource=2.1',
            'Content-Type': 'application/json',
            'Referer': 'https://am.nhsspit-2.ptl.nhsd-esa.net/openam/XUI/'
                       '?realm=/oidc'
                       '&goto=https://am.nhsspit-2.ptl.nhsd-esa.net:443/openam/oauth2/realms/root/realms/oidc/authorize'
                       '?response_type=code&client_id=969567331415.apps.national'
                       '&redirect_uri=https%3A%2F%2Finternal-dev.api.service.nhs.uk%2Foauth2%2Fcallback'
                       '&scope=openid&state=' + state
        }

        return self.post(url, headers=headers, json=payload)

    def _get_code(self) -> str:
        """Get the code parameter value required to post to the oauth /token endpoint"""
        # Get authorized
        authorize_response = self._get_response('GET', 200, 'authorize', params={
            'client_id': config.CLIENT_ID,
            'redirect_uri': config.REDIRECT_URI,
            'response_type': 'code',
        }, allow_redirects=False)

        # Confirm request was successful
        assert authorize_response.status_code == 302, f"Authorize request failed with {authorize_response.status_code}"

        # Get login url
        login_url = authorize_response.headers['Location']

        # Get state
        state = self.get_param_from_url(login_url, 'state')

        # Get authId and then get authenticated
        auth_id = self._get_auth_id(state)
        sign_in_response = self._nhs_sign_in(auth_id, login_url)

        # Confirm request was successful
        assert sign_in_response.status_code == 200, f"Sign in failed with {sign_in_response.status_code}"

        # Extract & follow success url from login response
        success_url = self.get_value_from_response(sign_in_response, 'successUrl')
        success_response = self.get(success_url, allow_redirects=False)

        # Confirm request was successful
        assert success_response.status_code == 302, f"Success url request failed with {sign_in_response.status_code}"

        # Extract url from location header and make the call back request
        callback_url = success_response.headers.get('Location')
        callback_response = self.get(callback_url, allow_redirects=False)

        # Confirm request was successful
        assert callback_response.status_code == 302, f"Location request failed with {sign_in_response.status_code}"

        return self.get_param_from_url(callback_response.header.get('Location'), 'code')

    def check_endpoint(self, verb: str, endpoint: str, expected_status_code: int, params: dict,
                       expected_response: dict or str or list,
                       headers: dict = None, allow_redirects: bool = True) -> bool:
        """Check a given request is returning the expected values. NOTE the expected response can be either a dict,
        a string or a list this is because we can expect either json, html or a list of keys from a json response
        respectively."""
        if endpoint == 'token':
            params['code'] = self._get_code()

        response = self._get_response(verb, expected_status_code, endpoint, params, headers, allow_redirects)

        if endpoint == 'token':
            return self.verify_response_keys(response, expected_status_code, expected_keys=expected_response)

        # Check response
        return self.verify_response(response, expected_status_code, expected_response=expected_response)

    def check_response_history(self, verb: str, endpoint: str, params: dict,
                               expected_status_code: int, expected_redirects: dict) -> bool:
        """Check the response redirects for a given request is returning the expected values"""
        response = self._get_response(verb, expected_status_code, endpoint, params)
        actual_redirects = self.get_redirects(response)

        for actual, expected in zip(actual_redirects.values(), expected_redirects.values()):
            url = self.remove_param_from_url(actual['url'], 'state')
            location = self.remove_param_from_url(actual['headers']['Location'], 'state')

            assert actual['status_code'] == expected['status_code'], f"Redirect failed with {expected['status_code']}"
            assert url == expected['url'], "Redirect url not as expected"
            assert location == expected['headers']['Location'], "Location header not as expected"
        return True
