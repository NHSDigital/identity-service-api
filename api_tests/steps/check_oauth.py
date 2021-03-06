from api_tests.scripts.generic_request import GenericRequest
from api_tests.config_files import config
from api_tests.scripts.authenticator import Authenticator
import jwt  # pyjwt
from uuid import uuid4
from time import time


class CheckOauth(GenericRequest):
    def __init__(self):
        super(CheckOauth, self).__init__()

    def get_authenticated(self) -> str:
        """Get the code parameter value required to post to the oauth /token endpoint"""
        authenticator = Authenticator(self)
        response = authenticator.authenticate()
        return authenticator.get_code_from_provider(response)

    def get_custom_token_response(self, request_data: dict, timeout: int = 5000):
        data = request_data
        if data.get('refresh_token'):
            data['_refresh_token_expiry_ms'] = timeout
        else:
            data['code'] = self.get_authenticated()
            data['_access_token_expiry_ms'] = timeout

        return self.post(self.endpoints['token'], data=data)

    def get_token_response(self, timeout: int = 5000, grant_type: str = 'authorization_code', refresh_token: str = ""):
        """Send a request for an access or refresh token"""
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

    @staticmethod
    def create_jwt(kid: str, signing_key=config.JWT_PRIVATE_KEY, algorithm: str = "RS512",
                   claims: dict = None) -> bytes:
        """Create a Json Web Token"""
        if not claims:
            # Get default claims
            claims = {
                "sub": config.JWT_APP_KEY,
                "iss": config.JWT_APP_KEY,
                "jti": str(uuid4()),
                "aud": config.TOKEN_URL,
                "exp": int(time()) + 5,
            }

        additional_headers = ({}, {"kid": kid})[kid is not None]
        if algorithm is not None:
            return jwt.encode(claims, signing_key, algorithm=algorithm, headers=additional_headers)
        return jwt.encode(claims, signing_key, headers=additional_headers)

    def get_jwt_token_response(self, jwt: bytes, form_data: dict = None) -> tuple:
        """Send a request for an access token using a JWT for authentication"""
        if not form_data:
            form_data = {
                "client_assertion_type": "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
                "client_assertion": jwt,
                "grant_type": "client_credentials",
            }
        else:
            if 'client_assertion' not in form_data.keys():
                form_data['client_assertion'] = jwt
            elif form_data['client_assertion'] is None:
                del form_data['client_assertion']
        response = self.post(config.TOKEN_URL, data=form_data)
        return self.get_all_values_from_json_response(response), response.status_code

    def modified_jwt(self, jwt_component_name: str) -> bytes:
        """A test method to modify a given JWTs' header, data or signature."""
        if jwt_component_name not in ['header', 'data', 'signature']:
            raise ValueError("jwt_component_name is not Valid, must be either header, data or signature")

        _jwt = self.create_jwt(kid='test-1')

        try:
            jwt_components = _jwt.decode("utf-8").split('.')
        except AttributeError:
            jwt_components = str(_jwt)[2:].split('.')

        index = 0

        if jwt_component_name == 'data':
            index = 1
        elif jwt_component_name == 'signature':
            index = 2

        jwt_components[index] = jwt_components[index] + 'invalid'
        _jwt = '.'.join(jwt_components).encode('utf-8')
        return _jwt

    def check_jwt_token_response(self, jwt: bytes, expected_response: dict, expected_status_code: int,
                                 form_data: dict = None):
        """Make a token request using a JWT and confirm the response"""
        response, status_code = self.get_jwt_token_response(jwt, form_data)
        _ = response.pop('message_id', None)
        assert response == expected_response, f"UNEXPECTED RESPONSE: {status_code}: {response}"
        assert status_code == expected_status_code, f"UNEXPECTED STATUS CODE {status_code}"
        return True
