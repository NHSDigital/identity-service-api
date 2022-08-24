from e2e.scripts.config import OAUTH_URL, ID_TOKEN_NHS_LOGIN_PRIVATE_KEY_ABSOLUTE_PATH
import pytest
from uuid import uuid4
from time import time
from random import choice
from string import ascii_letters


@pytest.mark.asyncio
class TestTokenExchange:
    """ A test suit to test the token exchange flow """
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

    @pytest.mark.simulated_auth
    @pytest.mark.happy_path
    @pytest.mark.token_exchange
    async def test_token_exchange_happy_path(self):
        # Given
        expected_status_code = 200
        expected_expires_in = '599'
        expected_token_type = 'Bearer'
        expected_issued_token_type = 'urn:ietf:params:oauth:token-type:access_token'

        id_token_jwt = self.oauth.create_id_token_jwt()
        client_assertion_jwt = self.oauth.create_jwt(kid='test-1')

        # When
        resp = await self.oauth.get_token_response(
            grant_type="token_exchange",
            _jwt=client_assertion_jwt,
            id_token_jwt=id_token_jwt
        )

        # Then
        assert expected_status_code == resp['status_code'], resp['body']
        assert 'access_token' in resp['body']
        assert expected_expires_in == resp['body']['expires_in']
        assert expected_token_type == resp['body']['token_type']
        assert expected_issued_token_type == resp['body']['issued_token_type']

    @pytest.mark.errors
    @pytest.mark.token_exchange
    async def test_token_exchange_invalid_client_assertion_type(self):
        # Given
        expected_status_code = 400
        expected_error = 'invalid_request'
        expected_error_description = "Missing or invalid client_assertion_type - " \
                                     "must be 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer"

        # When
        resp = await self.oauth.get_token_response(
            grant_type="token_exchange",
            data={
                'client_assertion_type': 'Invalid',
                'grant_type': 'urn:ietf:params:oauth:grant-type:token-exchange',
                'subject_token_type': 'urn:ietf:params:oauth:token-type:id_token'
            }
        )

        # Then
        assert expected_status_code == resp['status_code']
        assert expected_error == resp['body']['error']
        assert expected_error_description == resp['body']['error_description']

    @pytest.mark.errors
    @pytest.mark.token_exchange
    async def test_token_exchange_invalid_subject_token_type(self):
        # Given
        expected_status_code = 400
        expected_error = 'invalid_request'
        expected_error_description = "missing or invalid subject_token_type - " \
                                     "must be 'urn:ietf:params:oauth:token-type:id_token'"

        # When
        resp = await self.oauth.get_token_response(
            grant_type="token_exchange",
            data={
                'client_assertion_type': 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer',
                'subject_token_type': 'Invalid',
                'grant_type': 'urn:ietf:params:oauth:grant-type:token-exchange'
            }
        )

        # Then
        assert expected_status_code == resp['status_code']
        assert expected_error == resp['body']['error']
        assert expected_error_description == resp['body']['error_description']

    @pytest.mark.errors
    @pytest.mark.token_exchange
    async def test_token_exchange_claims_assertion_invalid_kid(self):
        # Given
        expected_status_code = 400
        expected_error = 'invalid_request'
        expected_error_description = "Missing 'kid' header in JWT"

        client_assertion_jwt = self.oauth.create_jwt(kid=None)

        # When
        resp = await self.oauth.get_token_response(
            grant_type="token_exchange",
            data={
                'client_assertion_type': 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer',
                'subject_token_type': 'urn:ietf:params:oauth:token-type:id_token',
                'grant_type': 'urn:ietf:params:oauth:grant-type:token-exchange',
                'client_assertion': client_assertion_jwt
            }
        )

        # Then
        assert expected_status_code == resp['status_code']
        assert expected_error == resp['body']['error']
        assert expected_error_description == resp['body']['error_description']

    @pytest.mark.errors
    @pytest.mark.token_exchange
    async def test_token_exchange_claims_assertion_invalid_typ_header(self):
        # Given
        expected_status_code = 400
        expected_error = 'invalid_request'
        expected_error_description = "Invalid 'typ' header in JWT - must be 'JWT'"

        client_assertion_jwt = self.oauth.create_jwt(kid="test-1", headers={'typ': 'invalid'})

        # When
        resp = await self.oauth.get_token_response(
            grant_type="token_exchange",
            data={
                'client_assertion_type': 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer',
                'subject_token_type': 'urn:ietf:params:oauth:token-type:id_token',
                'grant_type': 'urn:ietf:params:oauth:grant-type:token-exchange',
                'client_assertion': client_assertion_jwt
            }
        )

        # Then
        assert expected_status_code == resp['status_code']
        assert expected_error == resp['body']['error']
        assert expected_error_description == resp['body']['error_description']

    @pytest.mark.errors
    @pytest.mark.token_exchange
    async def test_token_exchange_claims_assertion_invalid_iss_claim(self):
        # Given
        expected_status_code = 400
        expected_error = 'invalid_request'
        expected_error_description = "Missing or non-matching iss/sub claims in JWT"

        client_assertion_jwt = self.oauth.create_jwt(kid="test-1", claims={
            "sub": '',
            "jti": str(uuid4()),
            "aud": f"{OAUTH_URL}/token",
            "exp": int(time()) + 5,
        })

        # When
        resp = await self.oauth.get_token_response(
            grant_type="token_exchange",
            data={
                'client_assertion_type': 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer',
                'subject_token_type': 'urn:ietf:params:oauth:token-type:id_token',
                'grant_type': 'urn:ietf:params:oauth:grant-type:token-exchange',
                'client_assertion': client_assertion_jwt
            }
        )

        # Then
        assert expected_status_code == resp['status_code']
        assert expected_error == resp['body']['error']
        assert expected_error_description == resp['body']['error_description']

    @pytest.mark.errors
    @pytest.mark.token_exchange
    async def test_token_exchange_claims_assertion_missing_jti_claim(self):
        # Given
        expected_status_code = 400
        expected_error = 'invalid_request'
        expected_error_description = "Missing jti claim in JWT"

        client_assertion_jwt = self.oauth.create_jwt(kid="test-1", claims={
            "sub": self.oauth.client_id,
            "iss": self.oauth.client_id,
            "jti": '',
            "aud": f"{OAUTH_URL}/token",
            "exp": int(time()) + 5,
        })

        # When
        resp = await self.oauth.get_token_response(
            grant_type="token_exchange",
            data={
                'client_assertion_type': 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer',
                'subject_token_type': 'urn:ietf:params:oauth:token-type:id_token',
                'grant_type': 'urn:ietf:params:oauth:grant-type:token-exchange',
                'client_assertion': client_assertion_jwt
            }
        )

        # Then
        assert expected_status_code == resp['status_code']
        assert expected_error == resp['body']['error']
        assert expected_error_description == resp['body']['error_description']

    @pytest.mark.errors
    @pytest.mark.token_exchange
    async def test_token_exchange_claims_assertion_missing_exp_claim(self):
        # Given
        expected_status_code = 400
        expected_error = 'invalid_request'
        expected_error_description = "Missing exp claim in JWT"

        client_assertion_jwt = self.oauth.create_jwt(kid="test-1", claims={
            "sub": self.oauth.client_id,
            "iss": self.oauth.client_id,
            "jti": str(uuid4()),
            "aud": f"{OAUTH_URL}/token",
        })

        # When
        resp = await self.oauth.get_token_response(
            grant_type="token_exchange",
            data={
                'client_assertion_type': 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer',
                'subject_token_type': 'urn:ietf:params:oauth:token-type:id_token',
                'grant_type': 'urn:ietf:params:oauth:grant-type:token-exchange',
                'client_assertion': client_assertion_jwt
            }
        )

        # Then
        assert expected_status_code == resp['status_code']
        assert expected_error == resp['body']['error']
        assert expected_error_description == resp['body']['error_description']

    @pytest.mark.errors
    @pytest.mark.token_exchange
    async def test_token_exchange_claims_assertion_invalid_exp_claim(self):
        # Given
        expected_status_code = 400
        expected_error = 'invalid_request'
        expected_error_description = "Invalid exp claim in JWT - more than 5 minutes in future"

        client_assertion_jwt = self.oauth.create_jwt(kid="test-1", claims={
            "sub": self.oauth.client_id,
            "iss": self.oauth.client_id,
            "jti": str(uuid4()),
            "aud": f"{OAUTH_URL}/token",
            "exp": int(time()) + 50000,
        })

        # When
        resp = await self.oauth.get_token_response(
            grant_type="token_exchange",
            data={
                'client_assertion_type': 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer',
                'subject_token_type': 'urn:ietf:params:oauth:token-type:id_token',
                'grant_type': 'urn:ietf:params:oauth:grant-type:token-exchange',
                'client_assertion': client_assertion_jwt
            }
        )

        # Then
        assert expected_status_code == resp['status_code']
        assert expected_error == resp['body']['error']
        assert expected_error_description == resp['body']['error_description']

    @pytest.mark.errors
    @pytest.mark.token_exchange
    async def test_token_exchange_claims_assertion_invalid_jti_claim(self):
        # Given
        expected_status_code = 400
        expected_error = 'invalid_request'
        expected_error_description = "Non-unique jti claim in JWT"

        id_token_claims = {
            'at_hash': 'tf_-lqpq36lwO7WmSBIJ6Q',
            'sub': '787807429511',
            'auditTrackingId': '91f694e6-3749-42fd-90b0-c3134b0d98f6-1546391',
            'amr': ['N3_SMARTCARD'],
            'iss': 'https://am.nhsint.auth-ptl.cis2.spineservices.nhs.uk:443/'
                   'openam/oauth2/realms/root/realms/NHSIdentity/realms/Healthcare',
            'tokenName': 'id_token',
            'aud': '969567331415.apps.national',
            'c_hash': 'bc7zzGkClC3MEiFQ3YhPKg',
            'acr': 'AAL3_ANY',
            'org.forgerock.openidconnect.ops': '-I45NjmMDdMa-aNF2sr9hC7qEGQ',
            's_hash': 'LPJNul-wow4m6Dsqxbning',
            'azp': '969567331415.apps.national',
            'auth_time': 1610559802,
            'realm': '/NHSIdentity/Healthcare',
            'exp': int(time()) + 600,
            'tokenType': 'JWTToken',
            'iat': int(time()) - 10
        }

        client_assertion_jwt = self.oauth.create_jwt(kid="test-1")
        id_token_jwt = self.oauth.create_id_token_jwt(kid="identity-service-tests-1", claims=id_token_claims)

        # When
        await self.oauth.get_token_response(
            grant_type="token_exchange",
            data={
                'grant_type': 'urn:ietf:params:oauth:grant-type:token-exchange',
                'subject_token_type': 'urn:ietf:params:oauth:token-type:id_token',
                'client_assertion_type': 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer',
                'subject_token': id_token_jwt,
                'client_assertion': client_assertion_jwt
            }
        )

        # Second request should fail
        resp = await self.oauth.get_token_response(
            grant_type="token_exchange",
            data={
                'grant_type': 'urn:ietf:params:oauth:grant-type:token-exchange',
                'subject_token_type': 'urn:ietf:params:oauth:token-type:id_token',
                'client_assertion_type': 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer',
                'subject_token': id_token_jwt,
                'client_assertion': client_assertion_jwt
            }
        )

        # Then
        assert expected_status_code == resp['status_code']
        assert expected_error == resp['body']['error']
        assert expected_error_description == resp['body']['error_description']

    @pytest.mark.errors
    @pytest.mark.token_exchange
    async def test_token_exchange_subject_token_missing_iss_or_sub_claim(self):
        # Given
        expected_status_code = 400
        expected_error = 'invalid_request'
        expected_error_description = "Missing or non-matching iss/sub claims in JWT"

        id_token_claims = {
            'at_hash': 'tf_-lqpq36lwO7WmSBIJ6Q',
            'sub': '787807429511',
            'auditTrackingId': '91f694e6-3749-42fd-90b0-c3134b0d98f6-1546391',
            'amr': ['N3_SMARTCARD'],
            'tokenName': 'id_token',
            'aud': '969567331415.apps.national',
            'c_hash': 'bc7zzGkClC3MEiFQ3YhPKg',
            'acr': 'AAL3_ANY',
            'org.forgerock.openidconnect.ops': '-I45NjmMDdMa-aNF2sr9hC7qEGQ',
            's_hash': 'LPJNul-wow4m6Dsqxbning',
            'azp': '969567331415.apps.national',
            'auth_time': 1610559802,
            'realm': '/NHSIdentity/Healthcare',
            'exp': int(time()) + 600,
            'tokenType': 'JWTToken',
            'iat': int(time()) - 10
        }

        client_assertion_jwt = self.oauth.create_jwt(kid="test-1")
        id_token_jwt = self.oauth.create_id_token_jwt(kid="identity-service-tests-1", claims=id_token_claims)

        # When
        resp = await self.oauth.get_token_response(
            grant_type="token_exchange",
            data={
                'grant_type': 'urn:ietf:params:oauth:grant-type:token-exchange',
                'subject_token_type': 'urn:ietf:params:oauth:token-type:id_token',
                'client_assertion_type': 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer',
                'subject_token': id_token_jwt,
                'client_assertion': client_assertion_jwt
            }
        )

        # Then
        assert expected_status_code == resp['status_code']
        assert expected_error == resp['body']['error']
        assert expected_error_description == resp['body']['error_description']


    @pytest.mark.simulated_auth
    @pytest.mark.errors
    @pytest.mark.token_exchange
    async def test_token_exchange_subject_token_missing_aud_claim(self):
        # Given
        expected_status_code = 400
        expected_error = 'invalid_request'
        expected_error_description = "Missing aud claim in JWT"

        id_token_claims = {
            'at_hash': 'tf_-lqpq36lwO7WmSBIJ6Q',
            'sub': '787807429511',
            'auditTrackingId': '91f694e6-3749-42fd-90b0-c3134b0d98f6-1546391',
            'iss': 'https://am.nhsint.auth-ptl.cis2.spineservices.nhs.uk:443'
                   '/openam/oauth2/realms/root/realms/NHSIdentity/realms/Healthcare',
            'amr': ['N3_SMARTCARD'],
            'tokenName': 'id_token',
            'c_hash': 'bc7zzGkClC3MEiFQ3YhPKg',
            'acr': 'AAL3_ANY',
            'org.forgerock.openidconnect.ops': '-I45NjmMDdMa-aNF2sr9hC7qEGQ',
            's_hash': 'LPJNul-wow4m6Dsqxbning',
            'azp': '969567331415.apps.national',
            'auth_time': 1610559802,
            'realm': '/NHSIdentity/Healthcare',
            'exp': int(time()) + 600,
            'tokenType': 'JWTToken',
            'iat': int(time()) - 10
        }

        client_assertion_jwt = self.oauth.create_jwt(kid="test-1")
        id_token_jwt = self.oauth.create_id_token_jwt(kid="identity-service-tests-1", claims=id_token_claims)

        # When
        resp = await self.oauth.get_token_response(
            grant_type="token_exchange",
            data={
                'grant_type': 'urn:ietf:params:oauth:grant-type:token-exchange',
                'subject_token_type': 'urn:ietf:params:oauth:token-type:id_token',
                'client_assertion_type': 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer',
                'subject_token': id_token_jwt,
                'client_assertion': client_assertion_jwt
            }
        )

        # Then
        assert expected_status_code == resp['status_code']
        assert expected_error == resp['body']['error']
        assert expected_error_description == resp['body']['error_description']

    @pytest.mark.errors
    @pytest.mark.token_exchange
    async def test_token_exchange_subject_token_missing_exp_claim(self):
        # Given
        expected_status_code = 400
        expected_error = 'invalid_request'
        expected_error_description = "Missing exp claim in JWT"

        id_token_claims = {
            'at_hash': 'tf_-lqpq36lwO7WmSBIJ6Q',
            'sub': '787807429511',
            'auditTrackingId': '91f694e6-3749-42fd-90b0-c3134b0d98f6-1546391',
            'amr': ['N3_SMARTCARD'],
            'iss': 'https://am.nhsint.auth-ptl.cis2.spineservices.nhs.uk:443'
                   '/openam/oauth2/realms/root/realms/NHSIdentity/realms/Healthcare',
            'tokenName': 'id_token',
            'aud': '969567331415.apps.national',
            'c_hash': 'bc7zzGkClC3MEiFQ3YhPKg',
            'acr': 'AAL3_ANY',
            'org.forgerock.openidconnect.ops': '-I45NjmMDdMa-aNF2sr9hC7qEGQ',
            's_hash': 'LPJNul-wow4m6Dsqxbning',
            'azp': '969567331415.apps.national',
            'auth_time': 1610559802,
            'realm': '/NHSIdentity/Healthcare',
            #'exp': int(time()) + 600,
            'tokenType': 'JWTToken',
            'iat': int(time()) - 10
        }

        client_assertion_jwt = self.oauth.create_jwt(kid="test-1")
        id_token_jwt = self.oauth.create_id_token_jwt(kid="identity-service-tests-1", claims=id_token_claims)

        # When
        resp = await self.oauth.get_token_response(
            grant_type="token_exchange",
            data={
                'grant_type': 'urn:ietf:params:oauth:grant-type:token-exchange',
                'subject_token_type': 'urn:ietf:params:oauth:token-type:id_token',
                'client_assertion_type': 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer',
                'subject_token': id_token_jwt,
                'client_assertion': client_assertion_jwt
            }
        )

        # Then
        assert expected_status_code == resp['status_code']
        assert expected_error == resp['body']['error']
        assert expected_error_description == resp['body']['error_description']

    @pytest.mark.simulated_auth
    @pytest.mark.errors
    @pytest.mark.token_exchange
    async def test_nhs_login_happy_path(self):
        # Given
        expected_status_code = 200
        expected_expires_in = '599'
        expected_token_type = 'Bearer'
        expected_issued_token_type = 'urn:ietf:params:oauth:token-type:access_token'

        id_token_claims = {
            'aud': 'tf_-APIM-1',
            'id_status': 'verified',
            'token_use': 'id',
            'auth_time': 1616600683,
            'iss': 'https://internal-dev.api.service.nhs.uk',
            'vot': 'P9.Cp.Cd',
            'exp': int(time()) + 600,
            'iat': int(time()) - 10,
            'vtm' : 'https://auth.sandpit.signin.nhs.uk/trustmark/auth.sandpit.signin.nhs.uk',
            'jti': 'b68ddb28-e440-443d-8725-dfe0da330118',
            "identity_proofing_level": "P9"
        }
        id_token_headers = {
            "sub": "49f470a1-cc52-49b7-beba-0f9cec937c46",
            "aud": "APIM-1",
            "kid": "nhs-login",
            "iss": "https://internal-dev.api.service.nhs.uk",
            "typ": "JWT",
            "exp": 1616604574,
            "iat": 1616600974,
            "alg": "RS512",
            "jti": "b68ddb28-e440-443d-8725-dfe0da330118"
        }

        with open(ID_TOKEN_NHS_LOGIN_PRIVATE_KEY_ABSOLUTE_PATH, "r") as f:
            contents = f.read()

        client_assertion_jwt = self.oauth.create_jwt(kid="test-1")
        id_token_jwt = self.oauth.create_id_token_jwt(algorithm='RS512',claims=id_token_claims, headers = id_token_headers, signing_key=contents)

        # When
        resp = await self.oauth.get_token_response(
            grant_type="token_exchange",
            data={
                'grant_type': 'urn:ietf:params:oauth:grant-type:token-exchange',
                'subject_token_type': 'urn:ietf:params:oauth:token-type:id_token',
                'client_assertion_type': 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer',
                'subject_token': id_token_jwt,
                'client_assertion': client_assertion_jwt
            }
        )

    #     # Then
        assert expected_status_code == resp['status_code'], resp['body']
        assert 'access_token' in resp['body']
        assert expected_expires_in == resp['body']['expires_in']
        assert expected_token_type == resp['body']['token_type']
        assert expected_issued_token_type == resp['body']['issued_token_type']

    @pytest.mark.errors
    @pytest.mark.token_exchange
    async def test_token_exchange_subject_token_nhs_login_missing_iss_claim(self):
        # Given
        expected_status_code = 400
        expected_error = 'invalid_request'
        expected_error_description = "Missing or non-matching iss/sub claims in JWT"

        id_token_claims = {
            'aud': 'tf_-APIM-1',
            'id_status': 'verified',
            'token_use': 'id',
            'auth_time': 1616600683,
            # 'iss': 'https://internal-dev.api.service.nhs.uk',
            'vot': 'P9.Cp.Cd',
            'exp': int(time()) + 600,
            'iat': int(time()) - 10,
            'vtm' : 'https://auth.sandpit.signin.nhs.uk/trustmark/auth.sandpit.signin.nhs.uk',
            'jti': 'b68ddb28-e440-443d-8725-dfe0da330118'
        }
        id_token_headers = {
            "sub": "49f470a1-cc52-49b7-beba-0f9cec937c46",
            "aud": "APIM-1",
            "kid": "nhs-login",
            "iss": "https://internal-dev.api.service.nhs.uk",
            "typ": "JWT",
            "exp": 1616604574,
            "iat": 1616600974,
            "alg": "RS512",
            "jti": "b68ddb28-e440-443d-8725-dfe0da330118"
        }

        with open(ID_TOKEN_NHS_LOGIN_PRIVATE_KEY_ABSOLUTE_PATH, "r") as f:
            contents = f.read()

        client_assertion_jwt = self.oauth.create_jwt(kid="test-1")
        id_token_jwt = self.oauth.create_id_token_jwt(algorithm='RS512',claims=id_token_claims, headers = id_token_headers, signing_key=contents)

        # When
        resp = await self.oauth.get_token_response(
            grant_type="token_exchange",
            data={
                'grant_type': 'urn:ietf:params:oauth:grant-type:token-exchange',
                'subject_token_type': 'urn:ietf:params:oauth:token-type:id_token',
                'client_assertion_type': 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer',
                'subject_token': id_token_jwt,
                'client_assertion': client_assertion_jwt
            }
        )

        # Then
        assert expected_status_code == resp['status_code']
        assert expected_error == resp['body']['error']
        assert expected_error_description == resp['body']['error_description']

    @pytest.mark.simulated_auth
    @pytest.mark.errors
    @pytest.mark.token_exchange
    async def test_token_exchange_subject_token_nhs_login_missing_aud_claim(self):
        # Given
        expected_status_code = 400
        expected_error = 'invalid_request'
        expected_error_description = "Missing aud claim in JWT"

        id_token_claims = {
            # 'aud': 'tf_-APIM-1',
            'id_status': 'verified',
            'token_use': 'id',
            'auth_time': 1616600683,
            'iss': 'https://internal-dev.api.service.nhs.uk',
            'vot': 'P9.Cp.Cd',
            'exp': int(time()) + 600,
            'iat': int(time()) - 10,
            'vtm' : 'https://auth.sandpit.signin.nhs.uk/trustmark/auth.sandpit.signin.nhs.uk',
            'jti': 'b68ddb28-e440-443d-8725-dfe0da330118'
        }
        id_token_headers = {
            "sub": "49f470a1-cc52-49b7-beba-0f9cec937c46",
            "aud": "APIM-1",
            "kid": "nhs-login",
            "iss": "https://internal-dev.api.service.nhs.uk",
            "typ": "JWT",
            "exp": 1616604574,
            "iat": 1616600974,
            "alg": "RS512",
            "jti": "b68ddb28-e440-443d-8725-dfe0da330118"
        }

        with open(ID_TOKEN_NHS_LOGIN_PRIVATE_KEY_ABSOLUTE_PATH, "r") as f:
            contents = f.read()

        client_assertion_jwt = self.oauth.create_jwt(kid="test-1")
        id_token_jwt = self.oauth.create_id_token_jwt(algorithm='RS512',claims=id_token_claims, headers = id_token_headers, signing_key=contents)

        # When
        resp = await self.oauth.get_token_response(
            grant_type="token_exchange",
            data={
                'grant_type': 'urn:ietf:params:oauth:grant-type:token-exchange',
                'subject_token_type': 'urn:ietf:params:oauth:token-type:id_token',
                'client_assertion_type': 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer',
                'subject_token': id_token_jwt,
                'client_assertion': client_assertion_jwt
            }
        )

        # Then
        assert expected_status_code == resp['status_code']
        assert expected_error == resp['body']['error']
        assert expected_error_description == resp['body']['error_description']

    @pytest.mark.errors
    @pytest.mark.token_exchange
    async def test_token_exchange_subject_token_nhs_login_missing_exp_claim(self):
        # Given
        expected_status_code = 400
        expected_error = 'invalid_request'
        expected_error_description = "Missing exp claim in JWT"

        id_token_claims = {
            'aud': 'tf_-APIM-1',
            'id_status': 'verified',
            'token_use': 'id',
            'auth_time': 1616600683,
            'iss': 'https://internal-dev.api.service.nhs.uk',
            'vot': 'P9.Cp.Cd',
            # 'exp': int(time()) + 600,
            'iat': int(time()) - 10,
            'vtm' : 'https://auth.sandpit.signin.nhs.uk/trustmark/auth.sandpit.signin.nhs.uk',
            'jti': 'b68ddb28-e440-443d-8725-dfe0da330118'
        }
        id_token_headers = {
            "sub": "49f470a1-cc52-49b7-beba-0f9cec937c46",
            "aud": "APIM-1",
            "kid": "nhs-login",
            "iss": "https://internal-dev.api.service.nhs.uk",
            "typ": "JWT",
            "exp": 1616604574,
            "iat": 1616600974,
            "alg": "RS512",
            "jti": "b68ddb28-e440-443d-8725-dfe0da330118"
        }

        with open(ID_TOKEN_NHS_LOGIN_PRIVATE_KEY_ABSOLUTE_PATH, "r") as f:
            contents = f.read()

        client_assertion_jwt = self.oauth.create_jwt(kid="test-1")
        id_token_jwt = self.oauth.create_id_token_jwt(algorithm='RS512',claims=id_token_claims, headers = id_token_headers, signing_key=contents)

        # When
        resp = await self.oauth.get_token_response(
            grant_type="token_exchange",
            data={
                'grant_type': 'urn:ietf:params:oauth:grant-type:token-exchange',
                'subject_token_type': 'urn:ietf:params:oauth:token-type:id_token',
                'client_assertion_type': 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer',
                'subject_token': id_token_jwt,
                'client_assertion': client_assertion_jwt
            }
        )

        # Then
        assert expected_status_code == resp['status_code']
        assert expected_error == resp['body']['error']
        assert expected_error_description == resp['body']['error_description']

    @pytest.mark.errors
    @pytest.mark.token_exchange
    async def test_token_exchange_subject_token_nhs_login_invalid_iss_claim(self):
        # Given
        expected_status_code = 400
        expected_error = 'invalid_request'
        expected_error_description = "Missing or non-matching iss/sub claims in JWT"

        id_token_claims = {
            'aud': 'tf_-APIM-1',
            'id_status': 'verified',
            'token_use': 'id',
            'auth_time': 1616600683,
            'iss': 'invalidIss',
            'vot': 'P9.Cp.Cd',
            'exp': int(time()) + 600,
            'iat': int(time()) - 10,
            'vtm' : 'https://auth.sandpit.signin.nhs.uk/trustmark/auth.sandpit.signin.nhs.uk',
            'jti': 'b68ddb28-e440-443d-8725-dfe0da330118'
        }
        id_token_headers = {
            "sub": "49f470a1-cc52-49b7-beba-0f9cec937c46",
            "aud": "APIM-1",
            "kid": "nhs-login",
            "iss": "InvalidIss",
            "typ": "JWT",
            "exp": 1616604574,
            "iat": 1616600974,
            "alg": "RS512",
            "jti": "b68ddb28-e440-443d-8725-dfe0da330118"
        }

        with open(ID_TOKEN_NHS_LOGIN_PRIVATE_KEY_ABSOLUTE_PATH, "r") as f:
            contents = f.read()

        client_assertion_jwt = self.oauth.create_jwt(kid="test-1")
        id_token_jwt = self.oauth.create_id_token_jwt(algorithm='RS512',claims=id_token_claims, headers = id_token_headers, signing_key=contents)

        # When
        resp = await self.oauth.get_token_response(
            grant_type="token_exchange",
            data={
                'grant_type': 'urn:ietf:params:oauth:grant-type:token-exchange',
                'subject_token_type': 'urn:ietf:params:oauth:token-type:id_token',
                'client_assertion_type': 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer',
                'subject_token': id_token_jwt,
                'client_assertion': client_assertion_jwt
            }
        )

        # Then
        assert expected_status_code == resp['status_code']
        assert expected_error == resp['body']['error']
        assert expected_error_description == resp['body']['error_description']

    @pytest.mark.errors
    @pytest.mark.token_exchange
    async def test_token_exchange_invalid_jwks_resource_url(self, test_product, test_application):
        # Given
        expected_status_code = 403
        expected_error = 'public_key error'
        expected_error_description = "The JWKS endpoint, for your client_assertion can't be reached"

        id_token_jwt = self.oauth.create_id_token_jwt()

        await test_application.add_api_product([test_product.name])
        await test_application.set_custom_attributes(attributes={"jwks-resource-url": "http://invalid_url"})

        client_assertion_jwt = self.oauth.create_jwt(kid='test-1', client_id=test_application.client_id)

        # When
        resp = await self.oauth.get_token_response(
            grant_type="token_exchange",
            _jwt=client_assertion_jwt,
            id_token_jwt=id_token_jwt
        )

        # Then
        assert expected_status_code == resp['status_code'], resp['body']
        assert expected_error == resp['body']['error']
        assert expected_error_description == resp['body']['error_description']

    @pytest.mark.errors
    @pytest.mark.token_exchange
    async def test_token_exchange_no_jwks_resource_url_set(self, test_product, test_application):
        # Given
        expected_status_code = 403
        expected_error = 'public_key error'
        expected_error_description = "You need to register a public key to use this authentication method " \
                                     "- please contact support to configure"

        id_token_jwt = self.oauth.create_id_token_jwt()

        await test_application.add_api_product([test_product.name])
        client_assertion_jwt = self.oauth.create_jwt(kid='test-1', client_id=test_application.client_id)

        # When
        resp = await self.oauth.get_token_response(
            grant_type="token_exchange",
            _jwt=client_assertion_jwt,
            id_token_jwt=id_token_jwt
        )

        # Then
        assert expected_status_code == resp['status_code'], resp['body']
        assert expected_error == resp['body']['error']
        assert expected_error_description == resp['body']['error_description']
