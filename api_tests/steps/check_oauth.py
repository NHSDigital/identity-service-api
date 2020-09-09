from api_tests.scripts.generic_request import GenericRequest
from api_tests.config_files import config
from api_tests.scripts.authenticator import Authenticator


class CheckOauth(GenericRequest):
    def __init__(self):
        super(CheckOauth, self).__init__()

    def get_authenticated(self) -> str:
        """Get the code parameter value required to post to the oauth /token endpoint"""
        authenticator = Authenticator(self)
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
            data['code'] = self.get_authenticated()
            data['_access_token_expiry_ms'] = timeout

        response = self.post(self.endpoints['token'], data=data)
        return self.get_all_values_from_json_response(response)
