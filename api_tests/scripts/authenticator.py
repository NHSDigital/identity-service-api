from api_tests.config_files import config


class Authenticator:
    def __init__(self, session):
        self.session = session
        self.data = self._get_request_data()

    def _simulated_oauth_prerequisite(self):
        """Request the login page and retrieve the callback url and assigned state"""
        login_page_response = self.session.get(config.AUTHENTICATE_URL)
        assert login_page_response.status_code == 200

        # Login
        params = {
            'client_id': config.CLIENT_ID,
            'redirect_uri': config.REDIRECT_URI,
            'response_type': 'code',
            'state': '1234567890'
        }

        success_response = self.session.get(config.AUTHORIZE_URL, params=params, allow_redirects=False)

        # Confirm request was successful
        assert success_response.status_code == 302, f"Getting an error: {success_response.text}"

        call_back_url = success_response.headers.get('Location')
        state = self.session.get_param_from_url(call_back_url, 'state')
        return call_back_url, state

    def _get_request_data(self) -> dict:
        """Get the request data required for authenticating with a given provider"""
        url, state = self._simulated_oauth_prerequisite()

        return {
            'url': url,
            'headers': {'Content-Type': 'application/x-www-form-urlencoded'},
            'params': {},
            'payload': {'state': state}
        }

    def authenticate(self) -> 'response type':
        """Send authentication request"""
        sign_in_response = self.session.post(
            self.data['url'],
            headers=self.data['headers'],
            params=self.data['params'],
            data=self.data['payload'],
            allow_redirects=False
        )

        # Confirm request was successful
        assert sign_in_response.status_code == 302, f"Failed to get authenticated " \
                                                    f"with error {sign_in_response.status_code}"
        return sign_in_response

    def get_code_from_provider(self, sign_in_response: 'response type') -> str:
        """Retrieve the code value from an authentication response"""
        # Extract url from location header and make the call back request
        callback_url = sign_in_response.headers.get('Location')
        callback_response = self.session.get(callback_url, allow_redirects=False)

        # Confirm request was successful
        assert callback_response.status_code == 302, f"Callback request failed with {callback_response.status_code}"

        # Return code param from location header
        return self.session.get_param_from_url(callback_response.headers.get('Location'), 'code')
