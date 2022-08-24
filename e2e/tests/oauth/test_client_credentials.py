from e2e.scripts.config import OAUTH_URL, ID_TOKEN_NHS_LOGIN_PRIVATE_KEY_ABSOLUTE_PATH
import pytest
from uuid import uuid4
from time import time
from random import choice
from string import ascii_letters


@pytest.mark.asyncio
class TestClientCredentials:
    """ A test suit to test the client credentials flow """
    def _update_secrets(self, request):
        if request.get("claims", None):
            if request["claims"].get("sub", None) == "/replace_me":
                request["claims"]['sub'] = self.oauth.client_id

            if request["claims"].get("iss", None) == "/replace_me":
                request["claims"]['iss'] = self.oauth.client_id
        else:
            if request.get("sub", None) == "/replace_me":
                request['sub'] = self.oauth.client_id
            if request.get("iis", None) == "/replace_me":
                request["iis"] = self.oauth.client_id
    
    @pytest.mark.happy_path
    async def test_successful_jwt_token_response(self):
        jwt = self.oauth.create_jwt(kid="test-1")
        resp = await self.oauth.get_token_response("client_credentials", _jwt=jwt)

        assert resp['status_code'] == 200
        assert resp['body'].get('expires_in') == '599', f"UNEXPECTED 'expires_in' {resp.get('expires_in')} {resp['body']}"

        assert list(resp['body'].keys()) == ['access_token', 'expires_in', 'token_type', 'issued_at'], \
            f'UNEXPECTED RESPONSE: {list(resp["body"].keys())}'

    @pytest.mark.apm_1521
    @pytest.mark.errors
    async def test_incorrect_jwt_algorithm(self, helper):

        # Given
        jwt_claims= {
                        'kid': 'test-1',
                        'algorithm': 'HS256',
                     }
        expected_response = {
                            'error': 'invalid_request',
                              'error_description': "Invalid 'alg' header in JWT - unsupported JWT algorithm - must be 'RS512'"
                            }
        expected_status_code = 400

        self._update_secrets(jwt_claims)
        jwt = self.oauth.create_jwt(**jwt_claims)

        # When
        resp = await self.oauth.get_token_response(grant_type='client_credentials', _jwt=jwt)

        # Then
        assert helper.check_response(resp, expected_status_code, expected_response)

    @pytest.mark.apm_1521
    @pytest.mark.errors
    async def test_invalid_sub_and_iss(self, helper):

        # # Given
        jwt_claims= {
                        'kid': 'test-1',
                        'claims': {
                            "sub": 'INVALID',
                            "iss": 'INVALID',
                            "jti": str(uuid4()),
                            "aud": f"{OAUTH_URL}/token",
                            "exp": int(time()) + 10,
                                }
                    }

        expected_response = {
                        'error': 'invalid_request', 
                        'error_description': 'Invalid iss/sub claims in JWT'
                        }

        expected_status_code = 401

        self._update_secrets(jwt_claims)
        jwt = self.oauth.create_jwt(**jwt_claims)

        # When
        resp = await self.oauth.get_token_response(grant_type='client_credentials', _jwt=jwt)

        # Then
        assert helper.check_response(resp, expected_status_code, expected_response)

    @pytest.mark.apm_1521
    @pytest.mark.errors
    async def test_invalid_sub_different_to_iss(self, helper):

        # Given
        jwt_claims={
                'kid': 'test-1',
                'claims': {
                    "sub": 'INVALID',
                    "iss": "/replace_me",
                    "jti": str(uuid4()),
                    "aud": f"{OAUTH_URL}/token",
                    "exp": int(time()) + 10,
                }
            }

        expected_response = {'error': 'invalid_request', 'error_description': 'Missing or non-matching iss/sub claims in JWT'}

        expected_status_code = 400

        self._update_secrets(jwt_claims)
        jwt = self.oauth.create_jwt(**jwt_claims)

        # When
        resp = await self.oauth.get_token_response(grant_type='client_credentials', _jwt=jwt)

        # Then
        assert helper.check_response(resp, expected_status_code, expected_response)

    @pytest.mark.apm_1521
    @pytest.mark.errors
    async def test_invalid_iss_different_to_sub(self, helper):

        # Given
        jwt_claims={
                'kid': 'test-1',
                'claims': {
                    "sub": "/replace_me",
                    "iss": 'INVALID',
                    "jti": str(uuid4()),
                    "aud": f"{OAUTH_URL}/token",
                    "exp": int(time()) + 10,
                }
            }

        expected_response = {'error': 'invalid_request', 'error_description': 'Missing or non-matching iss/sub claims in JWT'}

        expected_status_code = 400

        self._update_secrets(jwt_claims)
        jwt = self.oauth.create_jwt(**jwt_claims)

        # When
        resp = await self.oauth.get_token_response(grant_type='client_credentials', _jwt=jwt)

        # Then
        assert helper.check_response(resp, expected_status_code, expected_response)

    @pytest.mark.apm_1521
    @pytest.mark.errors
    async def test_missing_sub(self, helper):

        # Given
        jwt_claims=  {
                'kid': 'test-1',
                'claims': {
                    "iss": "/replace_me",
                    "jti": str(uuid4()),
                    "aud": f"{OAUTH_URL}/token",
                    "exp": int(time()) + 10,
                }
            }

        expected_response = {'error': 'invalid_request', 'error_description': 'Missing or non-matching iss/sub claims in JWT'}

        expected_status_code = 400

        self._update_secrets(jwt_claims)
        jwt = self.oauth.create_jwt(**jwt_claims)

        # When
        resp = await self.oauth.get_token_response(grant_type='client_credentials', _jwt=jwt)

        # Then
        assert helper.check_response(resp, expected_status_code, expected_response)

    @pytest.mark.apm_1521
    @pytest.mark.errors
    async def test_missing_iss(self, helper):

        # Given       
        jwt_claims=  {
                'kid': 'test-1',
                'claims': {
                    "sub": "/replace_me",
                    "jti": str(uuid4()),
                    "aud": f"{OAUTH_URL}/token",
                    "exp": int(time()) + 10,
                }
            }

        expected_response = {'error': 'invalid_request', 'error_description': 'Missing or non-matching iss/sub claims in JWT'}

        expected_status_code = 400

        self._update_secrets(jwt_claims)
        jwt = self.oauth.create_jwt(**jwt_claims)

        # When
        resp = await self.oauth.get_token_response(grant_type='client_credentials', _jwt=jwt)

        # Then
        assert helper.check_response(resp, expected_status_code, expected_response)

    @pytest.mark.apm_1521
    @pytest.mark.errors
    async def test_invalid_jti(self, helper):

        # Given  
        jwt_claims=  {
                'kid': 'test-1',
                'claims': {
                    "sub": "/replace_me",
                    "iss": "/replace_me",
                    "jti": 1234567890,
                    "aud": f"{OAUTH_URL}/token",
                    "exp": int(time()) + 10,
                }
            }

        expected_response = {'error': 'invalid_request', 'error_description': 'Failed to decode JWT'}

        expected_status_code = 400

        self._update_secrets(jwt_claims)
        jwt = self.oauth.create_jwt(**jwt_claims)

        # When
        resp = await self.oauth.get_token_response(grant_type='client_credentials', _jwt=jwt)

        # Then
        assert helper.check_response(resp, expected_status_code, expected_response)

    @pytest.mark.apm_1521
    @pytest.mark.errors
    async def test_missing_jti(self, helper):

        # Given  
        jwt_claims=   {
                'kid': 'test-1',
                'claims': {
                    "sub": "/replace_me",
                    "iss": "/replace_me",
                    "aud": f"{OAUTH_URL}/token",
                    "exp": int(time()) + 10,
                }
            }

        expected_response = {'error': 'invalid_request', 'error_description': 'Missing jti claim in JWT'}

        expected_status_code = 400

        self._update_secrets(jwt_claims)
        jwt = self.oauth.create_jwt(**jwt_claims)

        # When
        resp = await self.oauth.get_token_response(grant_type='client_credentials', _jwt=jwt)

        # Then
        assert helper.check_response(resp, expected_status_code, expected_response)
        
    @pytest.mark.apm_1521
    @pytest.mark.errors
    async def test_invalid_aud(self, helper):

        # Given  
        jwt_claims=    {
                'kid': 'test-1',
                'claims': {
                    "sub": "/replace_me",
                    "iss": "/replace_me",
                    "jti": str(uuid4()),
                    "aud": f"{OAUTH_URL}/token" + 'INVALID',
                    "exp": int(time()) + 60,
                }
            }

        expected_response = {'error': 'invalid_request', 'error_description': 'Missing or invalid aud claim in JWT'}

        expected_status_code = 401

        self._update_secrets(jwt_claims)
        jwt = self.oauth.create_jwt(**jwt_claims)

        # When
        resp = await self.oauth.get_token_response(grant_type='client_credentials', _jwt=jwt)

        # Then
        assert helper.check_response(resp, expected_status_code, expected_response)

    @pytest.mark.apm_1521
    @pytest.mark.errors
    async def test_missing_aud(self, helper):

        # Given  
        jwt_claims=    {
                'kid': 'test-1',
                'claims': {
                    "sub": "/replace_me",
                    "iss": "/replace_me",
                    "jti": str(uuid4()),
                    "exp": int(time()) + 60,
                }
            }

        expected_response = {'error': 'invalid_request', 'error_description': 'Missing or invalid aud claim in JWT'}

        expected_status_code = 401

        self._update_secrets(jwt_claims)
        jwt = self.oauth.create_jwt(**jwt_claims)

        # When
        resp = await self.oauth.get_token_response(grant_type='client_credentials', _jwt=jwt)

        # Then
        assert helper.check_response(resp, expected_status_code, expected_response)

    @pytest.mark.apm_1521
    @pytest.mark.errors
    async def test_invalid_exp(self, helper):

        # Given  
        jwt_claims=    {
                'kid': 'test-1',
                'claims': {
                    "sub": "/replace_me",
                    "iss": "/replace_me",
                    "jti": str(uuid4()),
                    "aud": f"{OAUTH_URL}/token",
                    "exp": 'INVALID',
                }
            }

        expected_response = {'error': 'invalid_request', 'error_description': 'Failed to decode JWT'}

        expected_status_code = 400

        self._update_secrets(jwt_claims)
        jwt = self.oauth.create_jwt(**jwt_claims)

        # When
        resp = await self.oauth.get_token_response(grant_type='client_credentials', _jwt=jwt)

        # Then
        assert helper.check_response(resp, expected_status_code, expected_response)

    @pytest.mark.apm_1521
    @pytest.mark.errors
    async def test_missing_exp(self, helper):

        # Given  
        jwt_claims=    {
                'kid': 'test-1',
                'claims': {
                    "sub": "/replace_me",
                    "iss": "/replace_me",
                    "jti": str(uuid4()),
                    "aud": f"{OAUTH_URL}/token",
                }
            }

        expected_response = {'error': 'invalid_request', 'error_description': 'Missing exp claim in JWT'}

        expected_status_code = 400

        self._update_secrets(jwt_claims)
        jwt = self.oauth.create_jwt(**jwt_claims)

        # When
        resp = await self.oauth.get_token_response(grant_type='client_credentials', _jwt=jwt)

        # Then
        assert helper.check_response(resp, expected_status_code, expected_response)

    @pytest.mark.apm_1521
    @pytest.mark.errors
    async def test_exp_in_the_past(self, helper):

        # Given  
        jwt_claims=    {
                'kid': 'test-1',
                'claims': {
                    "sub": "/replace_me",
                    "iss": "/replace_me",
                    "jti": str(uuid4()),
                    "aud": f"{OAUTH_URL}/token",
                    "exp": int(time()) - 20,
                }
            }

        expected_response = {'error': 'invalid_request', 'error_description': 'Invalid exp claim in JWT - JWT has expired'}

        expected_status_code = 400

        self._update_secrets(jwt_claims)
        jwt = self.oauth.create_jwt(**jwt_claims)

        # When
        resp = await self.oauth.get_token_response(grant_type='client_credentials', _jwt=jwt)

        # Then
        assert helper.check_response(resp, expected_status_code, expected_response)

    @pytest.mark.apm_1521
    @pytest.mark.errors
    async def test_exp_far_in_future(self, helper):

        # Given  
        jwt_claims=    {
                'kid': 'test-1',
                'claims': {
                    "sub": "/replace_me",
                    "iss": "/replace_me",
                    "jti": str(uuid4()),
                    "aud": f"{OAUTH_URL}/token",
                    "exp": int(time()) + 360,  # this includes the +30 seconds grace
                }
            }

        expected_response = {'error': 'invalid_request',
             'error_description': 'Invalid exp claim in JWT - more than 5 minutes in future'}

        expected_status_code = 400

        self._update_secrets(jwt_claims)
        jwt = self.oauth.create_jwt(**jwt_claims)

        # When
        resp = await self.oauth.get_token_response(grant_type='client_credentials', _jwt=jwt)

        # Then
        assert helper.check_response(resp, expected_status_code, expected_response)

    @pytest.mark.apm_1521
    @pytest.mark.errors
    async def test_reusing_same_jti(self, helper):
        jwt = self.oauth.create_jwt(claims={
            "sub": self.oauth.client_id,
            "iss": self.oauth.client_id,
            "jti": '6cd46139-af51-4f78-b850-74fcdf70c75b',
            "aud": f"{OAUTH_URL}/token",
            "exp": int(time()) + 10,
        },
            kid="test-1",
        )
        resp = await self.oauth.get_token_response(grant_type='client_credentials', _jwt=jwt)

        if resp['status_code'] == 200:
            resp = await self.oauth.get_token_response(grant_type='client_credentials', _jwt=jwt)
        assert helper.check_response(
            resp, 400, {'error': 'invalid_request', 'error_description': 'Non-unique jti claim in JWT'})

    @pytest.mark.errors
    async def test_invalid_client_assertion_type(self, helper):

        # Given
        form_data = {
                "client_assertion_type": "INVALID",
                "grant_type": "client_credentials",
            }
        expected_response = {
                'error': 'invalid_request',
                'error_description': "Missing or invalid client_assertion_type - "
                                     "must be 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer"
            }
        expected_status_code = 400

        jwt = self.oauth.create_jwt(kid="test-1")

        # When
        resp = await self.oauth.get_token_response("client_credentials", _jwt=jwt, data=form_data)

        # Then
        assert helper.check_response(resp, expected_status_code, expected_response)

    @pytest.mark.errors
    async def test_missing_client_assertion_type(self, helper):

        # Given
        form_data = {
                "grant_type": "client_credentials",
            }
        expected_response = {
                'error': 'invalid_request',
                'error_description': "Missing or invalid client_assertion_type - "
                                     "must be 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer"
            }
        expected_status_code = 400

        jwt = self.oauth.create_jwt(kid="test-1")

        # When
        resp = await self.oauth.get_token_response("client_credentials", _jwt=jwt, data=form_data)

        # Then
        assert helper.check_response(resp, expected_status_code, expected_response)

    @pytest.mark.errors
    async def test_invalid_client_assertion(self, helper):

        # Given
        form_data = {
                "client_assertion_type": "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
                "client_assertion": "INVALID",
                "grant_type": "client_credentials",
            }
        expected_response = {'error': 'invalid_request', 'error_description': 'Malformed JWT in client_assertion'}
        expected_status_code = 400

        jwt = self.oauth.create_jwt(kid="test-1")

        # When
        resp = await self.oauth.get_token_response("client_credentials", _jwt=jwt, data=form_data)

        # Then
        assert helper.check_response(resp, expected_status_code, expected_response)

    @pytest.mark.errors
    async def test_missing_client_assertion(self, helper):

        # Given
        form_data = {
                "client_assertion_type": "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
                "grant_type": "client_credentials",
            }
        expected_response = {'error': 'invalid_request', 'error_description': 'Missing client_assertion'}
        expected_status_code = 400

        jwt = self.oauth.create_jwt(kid="test-1")

        # When
        resp = await self.oauth.get_token_response("client_credentials", _jwt=jwt, data=form_data)

        # Then
        assert helper.check_response(resp, expected_status_code, expected_response)

    @pytest.mark.errors
    async def test_invalid_grant_type(self, helper):

        # Given
        form_data = {
                "client_assertion_type": "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
                "grant_type": "INVALID",
            }
        expected_response = {'error': 'unsupported_grant_type', 'error_description': 'grant_type is invalid'}
        expected_status_code = 400

        jwt = self.oauth.create_jwt(kid="test-1")

        # When
        resp = await self.oauth.get_token_response("client_credentials", _jwt=jwt, data=form_data)

        # Then
        assert helper.check_response(resp, expected_status_code, expected_response)

    @pytest.mark.errors
    async def test_missing_grant_type(self, helper):

        # Given
        form_data = {
                "client_assertion_type": "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
            }
        expected_response = {
                'error': 'invalid_request',
                'error_description': 'grant_type is missing'
            }
        expected_status_code = 400

        jwt = self.oauth.create_jwt(kid="test-1")

        # When
        resp = await self.oauth.get_token_response("client_credentials", _jwt=jwt, data=form_data)

        # Then
        assert helper.check_response(resp, expected_status_code, expected_response)

    @pytest.mark.errors
    async def test_invalid_kid(self, helper):

        # Given
        jwt_headers = {
                'kid': 'INVALID'
            }
        expected_response = {'error': 'invalid_request', 'error_description': "Invalid 'kid' header in JWT - no matching public key"}
        expected_status_code = 401

        jwt = self.oauth.create_jwt(**jwt_headers)

        # When
        resp = await self.oauth.get_token_response("client_credentials", _jwt=jwt)

        # Then
        assert helper.check_response(resp, expected_status_code, expected_response)

    @pytest.mark.errors
    async def test_missing_kid(self, helper):

        # Given
        jwt_headers = {
                'kid': None
            }
        expected_response = {'error': 'invalid_request', 'error_description': "Missing 'kid' header in JWT"}
        expected_status_code = 400

        jwt = self.oauth.create_jwt(**jwt_headers)

        # When
        resp = await self.oauth.get_token_response("client_credentials", _jwt=jwt)

        # Then
        assert helper.check_response(resp, expected_status_code, expected_response)

    @pytest.mark.skip("Fails in the pipeline")
    async def test_manipulated_jwt_json(self):
        jwt = self.oauth.create_jwt(kid='test-1')
        chars = choice(ascii_letters) + choice(ascii_letters)

        resp = await self.oauth.get_token_response(grant_type="client_credentials", _jwt=f"{jwt[:-2]}{chars}")
        assert resp['status_code'] == 400
        assert resp['body'] == {'error': 'invalid_request', 'error_description': 'Malformed JWT in client_assertion'}

    @pytest.mark.errors
    async def test_no_jwks_resource_url_set(self, test_product, test_application):
        await test_application.add_api_product([test_product.name])

        jwt = self.oauth.create_jwt(kid='test-1', client_id=test_application.client_id)
        resp = await self.oauth.get_token_response("client_credentials", _jwt=jwt)

        assert resp['status_code'] == 403
        assert resp['body'] == {
                'error': 'public_key error',
                'error_description': "You need to register a public key to use this authentication method"
                                     " - please contact support to configure"
            }

    @pytest.mark.errors
    async def test_invalid_jwks_resource_url(self, test_product, test_application):
        await test_application.add_api_product([test_product.name])
        await test_application.set_custom_attributes(attributes={"jwks-resource-url": "http://invalid_url"})

        jwt = self.oauth.create_jwt(kid='test-1', client_id=test_application.client_id)
        resp = await self.oauth.get_token_response("client_credentials", _jwt=jwt)

        assert resp['status_code'] == 403
        assert resp['body'] == {
                'error': 'public_key error',
                'error_description': "The JWKS endpoint, for your client_assertion can't be reached"
            }