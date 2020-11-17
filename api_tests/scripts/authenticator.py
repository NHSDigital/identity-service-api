import uuid
import requests
from api_tests.config_files import config


class Authenticator:
    def __init__(self, session):
        self.session = session

    def _get_state(self, request_state: str = str(uuid.uuid4())) -> str:
        params = {
            "client_id": config.CLIENT_ID,
            "redirect_uri": config.REDIRECT_URI,
            "response_type": "code",
            "state": request_state
        }
        with self.session.get(config.AUTHORIZE_URL, params=params) as response:

            # Confirm request was successful
            assert response.status_code == 200

            state = self.session.get_param_from_url(response.url, 'state')

            # Confirm state is converted to a cryptographic value
            assert state != request_state
            return state

    def authenticate(self) -> requests.Response:
        request_state = self._get_state()
        params = {
            "response_type": "code",
            "client_id": config.CLIENT_ID,
            "redirect_uri": config.REDIRECT_URI,
            "scope": "openid",
            "state": request_state
        }
        headers = {
            "Content-Type": "application/x-www-form-urlencoded"
        }
        payload = {
            "state": request_state
        }
        with self.session.post(
            url=config.SIM_AUTH_URL,
            params=params,
            data=payload,
            headers=headers,
            allow_redirects=False
        ) as response:
            assert response.status_code == 302, f"Failed to get authenticated " \
                                                        f"with error {response.status_code}"
            redirect_uri = response.headers['Location']
            response.headers['Location'] = redirect_uri.replace("oauth2", config.IDENTITY_PROXY)
            return response

    def get_code_from_provider(self, sign_in_response: requests.Response) -> str:
        """Retrieve the code value from an authentication response"""

        callback_url = sign_in_response.headers.get('Location')
        callback_response = self.session.get(callback_url, allow_redirects=False)

        # Confirm request was successful
        assert callback_response.status_code == 302, f"Callback request failed with {callback_response.status_code}"

        # Return code param from location header
        return self.session.get_param_from_url(callback_response.headers.get('Location'), 'code')
