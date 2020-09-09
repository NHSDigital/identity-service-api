from api_tests.scripts.generic_request import GenericRequest
from api_tests.config_files import config
from api_tests.scripts.authenticator import Authenticator


class CheckOauth(GenericRequest):
    def __init__(self):
        super(CheckOauth, self).__init__()

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

    def get_token_response(self, timeout: int = 5000000, grant_type: str = 'authorization_code', refresh_token: str = ""):
        data = {
            'client_id': config.CLIENT_ID,
            'client_secret': config.CLIENT_SECRET,
            'grant_type': grant_type,
        }
        if refresh_token != "":
            data['refresh_token'] = refresh_token
            data['_refresh_token_expiry_ms'] = timeout
        else:
            data['redirect_uri'] = config.REDIRECT_URI
            data['code'] = self.get_authenticated(config.AUTHENTICATION_PROVIDER)
            data['_access_token_expiry_ms'] = timeout

        response = self.post(self.endpoints['token'], data=data)
        return self.get_all_values_from_json_response(response)
