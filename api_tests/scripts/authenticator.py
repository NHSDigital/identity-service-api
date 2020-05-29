from api_tests.config_files import config


class Authenticator:
    def __init__(self, session, provider, username, password, state):
        self.session = session
        self.data = self._get_request_data(provider, username, password, state)

    def _get_auth_id(self, state: str) -> str:
        """Get NHS Auth ID required for authentication"""
        url, _ = config.AUTHENTICATE_URL.split('/openam')
        params = {

            'goto': f"{url}:443/openam/oauth2/realms/root/realms/oidc/authorize"
                    "?response_type=code"
                    f"&client_id={config.APIGEE_CLIENT_ID}"
                    f"&redirect_uri={config.BASE_URL}/v1/callback"
                    "&scope=openid"
                    f"&state={state}"
        }

        response = self.session.get_response('POST', expected_status_code=200, endpoint='authenticate',
                                             params=params, headers={'Accept-API-Version': 'protocol=1.0,resource=2.1'})
        return self.session.get_value_from_json_response(response, 'authId')

    def _get_request_data(self, provider: str, username: str, password: str, state: str) -> dict:
        provider = provider.lower().replace(' ', '_')  # Format value
        url, _ = config.AUTHENTICATE_URL.split('/openam')

        return {
            'nhs_identity': {
                'payload': {
                    "authId": f"{self._get_auth_id(state)}",
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
                },
                'headers': {
                    'Connection': 'keep-alive',
                    'Accept-API-Version': 'protocol=1.0,resource=2.1',
                    'Content-Type': 'application/json',
                },
                'params': {
                    'goto': f'{url}:443/openam/oauth2/realms/root/realms/oidc/authorize'
                            f'?response_type=code&client_id={config.APIGEE_CLIENT_ID}&'
                            f'redirect_uri={config.BASE_URL}/callback'
                            f'&scope=openid&state={state}'
                }
            },
        }.get(provider.lower())

    def authenticate(self) -> 'response type':
        sign_in_response = self.session.post(
            config.AUTHENTICATE_URL,
            headers=self.data['headers'],
            params=self.data['params'],
            json=self.data['payload']
        )

        # Confirm request was successful
        assert sign_in_response.status_code == 200, f"Failed to get authenticated " \
                                                    f"with error {sign_in_response.status_code}"
        return sign_in_response

    def get_code_from_provider(self, sign_in_response: 'response type') -> str:
        # Extract & follow success url from login response
        success_url = self.session.get_value_from_json_response(sign_in_response, 'successUrl')
        success_response = self.session.get(success_url, allow_redirects=False)

        # Confirm request was successful
        assert success_response.status_code == 302, f"Success url request failed with {sign_in_response.status_code}"

        # Extract url from location header and make the call back request
        callback_url = success_response.headers.get('Location')
        callback_response = self.session.get(callback_url, allow_redirects=False)

        # Confirm request was successful
        assert callback_response.status_code == 302, f"Callback request failed with {sign_in_response.status_code}"

        # Return code param from location header
        return self.session.get_param_from_url(callback_response.headers.get('Location'), 'code')
