from e2e.scripts.config import (
    OAUTH_URL,
    ID_TOKEN_NHS_LOGIN_PRIVATE_KEY_ABSOLUTE_PATH,
    CANARY_API_URL
)
import pytest
from uuid import uuid4
from time import time, sleep
import requests
import sys


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

    # ############# JWT ###############

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
            # 'exp': int(time()) + 600,
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
            'vtm': 'https://auth.sandpit.signin.nhs.uk/trustmark/auth.sandpit.signin.nhs.uk',
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
        id_token_jwt = self.oauth.create_id_token_jwt(algorithm='RS512', claims=id_token_claims,
                                                      headers=id_token_headers, signing_key=contents)

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
            'vtm': 'https://auth.sandpit.signin.nhs.uk/trustmark/auth.sandpit.signin.nhs.uk',
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
        id_token_jwt = self.oauth.create_id_token_jwt(algorithm='RS512', claims=id_token_claims,
                                                      headers=id_token_headers, signing_key=contents)

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
            'vtm': 'https://auth.sandpit.signin.nhs.uk/trustmark/auth.sandpit.signin.nhs.uk',
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
        id_token_jwt = self.oauth.create_id_token_jwt(algorithm='RS512', claims=id_token_claims,
                                                      headers=id_token_headers, signing_key=contents)

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
            'vtm': 'https://auth.sandpit.signin.nhs.uk/trustmark/auth.sandpit.signin.nhs.uk',
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
        id_token_jwt = self.oauth.create_id_token_jwt(algorithm='RS512', claims=id_token_claims,
                                                      headers=id_token_headers, signing_key=contents)

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
            'vtm': 'https://auth.sandpit.signin.nhs.uk/trustmark/auth.sandpit.signin.nhs.uk',
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
        id_token_jwt = self.oauth.create_id_token_jwt(algorithm='RS512', claims=id_token_claims,
                                                      headers=id_token_headers, signing_key=contents)

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

    # ############ OAUTH ENDPOINTS ###########

    @pytest.mark.simulated_auth
    @pytest.mark.errors
    async def test_userinfo_cis2_exchanged_token(self):
        # Given
        expected_status_code = 400

        # When
        id_token_jwt = self.oauth.create_id_token_jwt()
        client_assertion_jwt = self.oauth.create_jwt(kid="test-1")
        resp = await self.oauth.get_token_response(
            grant_type="token_exchange",
            _jwt=client_assertion_jwt,
            id_token_jwt=id_token_jwt,
        )

        token = resp["body"]["access_token"]
        resp = await self.oauth.hit_oauth_endpoint(
            method="GET",
            endpoint="userinfo",
            headers={"Authorization": f"Bearer {token}"},
        )

        # Then
        assert expected_status_code == resp["status_code"]

    @pytest.mark.simulated_auth
    async def test_userinfo_nhs_login_exchanged_token(self, get_exchange_code_nhs_login_token):
        # Given
        expected_status_code = 400
        expected_error = 'invalid_request'
        expected_error_description = 'The Userinfo endpoint is only supported for Combined Auth integrations. ' \
                                     'Currently this is only for NHS CIS2 authentications - for more guidance see ' \
                                     'https://digital.nhs.uk/developer/guides-and-documentation/security-and' \
                                     '-authorisation/user-restricted-restful-apis-nhs-cis2-combined-authentication' \
                                     '-and-authorisation'

        # When
        resp = await get_exchange_code_nhs_login_token(self.oauth)
        token = resp["body"]["access_token"]
        resp = await self.oauth.hit_oauth_endpoint(
            method="GET",
            endpoint="userinfo",
            headers={"Authorization": f"Bearer {token}"},
        )

        # Then
        assert expected_status_code == resp['status_code']
        assert expected_error == resp['body']['error']
        assert expected_error_description == resp['body']['error_description']

    # ############# OAUTH TOKENS ###############

    @pytest.mark.simulated_auth
    @pytest.mark.parametrize("auth_method", ["P0", "P5", "P9"])
    @pytest.mark.authorize_endpoint
    async def test_nhs_login_auth_code_flow_happy_path(self, helper, auth_code_nhs_login):
        response = await auth_code_nhs_login.get_token(self.oauth)
        access_token = response["access_token"]

        assert helper.check_endpoint(
            verb="GET",
            endpoint=CANARY_API_URL,
            expected_status_code=200,
            expected_response="Hello user!",
            headers={
                "Authorization": f"Bearer {access_token}",
                "NHSD-Session-URID": "ROLD-ID",
            },
        )

    @pytest.mark.simulated_auth
    @pytest.mark.parametrize('scope', ['P9', 'P5', 'P0'])
    async def test_nhs_login_token_exchange_access_and_refresh_tokens_generated(self, scope):
        """
        Ensure access token and refresh token generated by nhs login token exchange
        Use to fetch and a new access token, refresh token pair.
        """
        id_token_claims = {
            "aud": "tf_-APIM-1",
            "id_status": "verified",
            "token_use": "id",
            "auth_time": 1616600683,
            "iss": "https://internal-dev.api.service.nhs.uk",
            "vot": "P9.Cp.Cd",
            "exp": int(time()) + 600,
            "iat": int(time()) - 10,
            "vtm": "https://auth.sandpit.signin.nhs.uk/trustmark/auth.sandpit.signin.nhs.uk",
            "jti": str(uuid4()),
            "identity_proofing_level": scope,
            "nhs_number": "900000000001"
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
            "jti": str(uuid4()),
        }

        with open(ID_TOKEN_NHS_LOGIN_PRIVATE_KEY_ABSOLUTE_PATH, "r") as f:
            contents = f.read()

        client_assertion_jwt = self.oauth.create_jwt(kid="test-1")
        id_token_jwt = self.oauth.create_id_token_jwt(
            algorithm="RS512",
            claims=id_token_claims,
            headers=id_token_headers,
            signing_key=contents,
        )
        resp = await self.oauth.get_token_response(
            grant_type="token_exchange",
            _jwt=client_assertion_jwt,
            id_token_jwt=id_token_jwt,
        )
        access_token = resp['body']['access_token']
        refresh_token = resp['body']['refresh_token']

        assert access_token
        assert refresh_token
        assert resp['body']['expires_in'] == '599'
        assert resp['body']['refresh_token_expires_in'] == '3599'

        # Get new access token using refresh token to ensure valid
        resp2 = await self.oauth.get_token_response(grant_type="refresh_token", refresh_token=refresh_token)
        access_token2 = resp2['body']['access_token']
        refresh_token2 = resp2['body']['refresh_token']

        assert access_token2
        assert refresh_token2

    @pytest.mark.simulated_auth
    async def test_cis2_token_exchange_access_tokens_valid(self):
        """
        Using a refresh token that was generated via token exchange, fetch and use
        a new access token, refresh token pair.
        """
        # Generate access token using token-exchange
        id_token_jwt = self.oauth.create_id_token_jwt()
        client_assertion_jwt = self.oauth.create_jwt(kid='test-1')
        resp = await self.oauth.get_token_response(grant_type='token_exchange', _jwt=client_assertion_jwt,
                                                   id_token_jwt=id_token_jwt)

        access_token = resp['body']['access_token']
        refresh_token = resp['body']['refresh_token']

        assert access_token
        assert refresh_token
        assert resp['body']['expires_in'] == '599'
        assert resp['body']['refresh_token_expires_in'] == '43199'

        # Make request using access token to ensure valid
        req = requests.get(f"{CANARY_API_URL}", headers={"Authorization": f"Bearer {access_token}"})
        assert req.status_code == 200

        # Get new access token using refresh token to ensure valid
        resp2 = await self.oauth.get_token_response(grant_type="refresh_token", refresh_token=refresh_token)
        access_token2 = resp2['body']['access_token']
        refresh_token2 = resp2['body']['refresh_token']
        assert access_token2
        assert refresh_token2

        # Make request using new access token to ensure valid
        req2 = requests.get(f"{CANARY_API_URL}", headers={"Authorization": f"Bearer {access_token2}"})
        assert req2.status_code == 200

    @pytest.mark.simulated_auth
    async def test_cis2_token_exchange_refresh_token_become_invalid(self):
        """
        Fetch a new access token, refresh token pair.
        Ensure the original refresh token becomes invalid
        """
        # Generate access token using token-exchange
        id_token_jwt = self.oauth.create_id_token_jwt()
        client_assertion_jwt = self.oauth.create_jwt(kid='test-1')
        resp = await self.oauth.get_token_response(grant_type='token_exchange', _jwt=client_assertion_jwt,
                                                   id_token_jwt=id_token_jwt)

        access_token = resp['body']['access_token']
        refresh_token = resp['body']['refresh_token']

        assert access_token
        assert refresh_token

        # Get new access token using refresh token
        resp2 = await self.oauth.get_token_response(grant_type="refresh_token", refresh_token=refresh_token)
        access_token2 = resp2['body']['access_token']
        assert access_token2

        # try to use the original refresh token to get another access token
        resp3 = await self.oauth.get_token_response(grant_type="refresh_token", refresh_token=refresh_token)
        assert resp3['status_code'] == 401

    async def test_rejects_token_request_by_password(self):
        """
        Test that request for token using password grant type is rejected.
        """
        form_data = {
            "client_id": self.oauth.client_id,
            "client_secret": self.oauth.client_secret,
            "grant_type": "password",
            "username": "username",
            "password": "password"
        }
        resp = await self.oauth.get_token_response(grant_type='password', data=form_data)

        assert resp['status_code'] == 400

    @pytest.mark.parametrize("token_expiry_ms, expected_time",
                             [(100000, 100), (500000, 500), (700000, 600), (1000000, 600)])
    async def test_access_token_override_with_client_credentials(self, token_expiry_ms, expected_time):
        """
        Test client credential flow access token can be overridden with a time less than 10 min(600000ms or 600s)
        and NOT be overridden with a time greater than 10 min(600000ms or 600s)
        """
        form_data = {
            "client_assertion_type": "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
            "client_assertion": self.oauth.create_jwt('test-1'),
            "grant_type": 'client_credentials',
            "_access_token_expiry_ms": token_expiry_ms
        }

        resp = await self.oauth.get_token_response(grant_type='client_credentials', data=form_data)

        assert resp['status_code'] == 200
        assert int(resp['body']['expires_in']) <= expected_time

    @pytest.mark.simulated_auth
    @pytest.mark.parametrize("token_expiry_ms, expected_time",
                             [(100000, 100), (500000, 500), (700000, 600), (1000000, 600)])
    async def test_access_token_override_with_token_exchange(self, token_expiry_ms, expected_time):
        """
        Test token exchange flow access token can be overridden with a time less than 10 min(600000ms or 600s)
        and NOT be overridden with a time greater than 10 min(600000ms or 600s)
        """
        id_token_jwt = self.oauth.create_id_token_jwt()
        client_assertion_jwt = self.oauth.create_jwt(kid='test-1')
        form_data = {
            "grant_type": "urn:ietf:params:oauth:grant-type:token-exchange",
            "subject_token_type": "urn:ietf:params:oauth:token-type:id_token",
            "client_assertion_type": "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
            "subject_token": id_token_jwt,
            "client_assertion": client_assertion_jwt,
            "_access_token_expiry_ms": token_expiry_ms
        }

        resp = await self.oauth.hit_oauth_endpoint("post", "token", data=form_data)

        assert resp['status_code'] == 200
        assert int(resp['body']['expires_in']) <= expected_time

    @pytest.mark.skip(
        reason="It is not feasible to run this test each build due to the timeframe required, run manually if needed."
    )
    @pytest.mark.parametrize('scope', ['P9', 'P5', 'P0'])
    async def test_nhs_login_refresh_token_invalid_after_1_hour(self, scope):
        """
        Test that a refresh token received via a NHS Login is invalid after 1 hour (existing behaviour).
        Run pytest with the -s arg to display the stdout and show the wait time countdown.
        """
        id_token_claims = {
            "aud": "tf_-APIM-1",
            "id_status": "verified",
            "token_use": "id",
            "auth_time": 1616600683,
            "iss": "https://internal-dev.api.service.nhs.uk",
            "vot": "P9.Cp.Cd",
            "exp": int(time()) + 600,
            "iat": int(time()) - 10,
            "vtm": "https://auth.sandpit.signin.nhs.uk/trustmark/auth.sandpit.signin.nhs.uk",
            "jti": str(uuid4()),
            "identity_proofing_level": scope,
            "nhs_number": "900000000001"
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
            "jti": str(uuid4()),
        }

        with open(ID_TOKEN_NHS_LOGIN_PRIVATE_KEY_ABSOLUTE_PATH, "r") as f:
            contents = f.read()

        client_assertion_jwt = self.oauth.create_jwt(kid="test-1")
        id_token_jwt = self.oauth.create_id_token_jwt(
            algorithm="RS512",
            claims=id_token_claims,
            headers=id_token_headers,
            signing_key=contents,
        )
        resp = await self.oauth.get_token_response(
            grant_type="token_exchange",
            _jwt=client_assertion_jwt,
            id_token_jwt=id_token_jwt,
        )
        refresh_token = resp['body']['refresh_token']

        assert refresh_token
        assert resp['body']['expires_in'] == '599'
        assert resp['body']['refresh_token_expires_in'] == '3599'

        # Wait 1 hour (the previous refresh token expiry time) and check that the token is still valid
        for remaining in range(3600, 0, -1):
            mins, sec = divmod(remaining, 60)
            sys.stdout.write("\r")
            sys.stdout.write("{:2d} minutes {:2d} seconds remaining.".format(mins, sec))
            sleep(1)

        # Get new access token using refresh token
        resp2 = await self.oauth.get_token_response(grant_type="refresh_token", refresh_token=refresh_token)
        assert resp2['status_code'] == 401

    @pytest.mark.simulated_auth
    @pytest.mark.parametrize("token_expiry_ms, expected_time",
                             [(100000, 100), (500000, 500), (700000, 600), (1000000, 600)])
    async def test_access_token_override_with_authorization_code(self, token_expiry_ms, expected_time):
        """
        Test authorization code flow access token can be overridden with a time less than 10 min(600000ms or 600s)
        and NOT be overridden with a time greater than 10 min(600000ms or 600s)
        """

        resp = await self.oauth.get_token_response(grant_type='authorization_code', timeout=token_expiry_ms)

        assert resp['status_code'] == 200
        assert int(resp['body']['expires_in']) <= expected_time

    @pytest.mark.simulated_auth
    @pytest.mark.usefixtures("set_refresh_token")
    @pytest.mark.parametrize("token_expiry_ms, expected_time",
                             [(100000, 100), (500000, 500), (700000, 600), (1000000, 600)])
    async def test_access_token_override_with_refresh_token(self, token_expiry_ms, expected_time):
        """
        Test refresh token flow access token can be overridden with a time less than 10 min(600000ms or 600s)
        and  NOT be overridden with a time greater than 10 min(600000ms or 600s)
        """
        form_data = {
            "client_id": self.oauth.client_id,
            "client_secret": self.oauth.client_secret,
            "grant_type": "refresh_token",
            "refresh_token": self.oauth.refresh_token,
            "_refresh_tokens_validity_ms": 599,
            "_access_token_expiry_ms": token_expiry_ms
        }

        resp = await self.oauth.get_token_response(grant_type='refresh_token', data=form_data)

        assert resp['status_code'] == 200
        assert int(resp['body']['expires_in']) <= expected_time

    @pytest.mark.skip(
        reason="It is not feasible to run this test each build due to the timeframe required, run manually if needed."
    )
    async def test_cis2_refresh_token_expires_after_12_hours(self):
        """
        Test that a refresh token received via a CIS2 login is valid for up to 12 hours.
        Run pytest with the -s arg to display the stdout and show the wait time countdown.
        """
        # Generate access token using token-exchange
        id_token_jwt = self.oauth.create_id_token_jwt()
        client_assertion_jwt = self.oauth.create_jwt(kid='test-1')
        resp = await self.oauth.get_token_response(
            grant_type="token_exchange",
            _jwt=client_assertion_jwt,
            id_token_jwt=id_token_jwt
        )

        refresh_token = resp['body']['refresh_token']

        assert refresh_token
        assert resp['body']['expires_in'] == '599'
        assert resp['body']['refresh_token_expires_in'] == '43199'

        # Wait 12 hours and check that the token has expired
        for remaining in range(43200, 0, -1):
            mins, sec = divmod(remaining, 60)
            hours, mins = divmod(mins, 60)
            sys.stdout.write("\r")
            sys.stdout.write("{:2d} hours {:2d} minutes {:2d} seconds remaining.".format(hours, mins, sec))
            sys.stdout.flush()
            sleep(1)

        # Try to use the now expired refresh token to get another access token
        resp2 = await self.oauth.get_token_response(grant_type="refresh_token", refresh_token=refresh_token)
        print(resp2)
        assert resp2['status_code'] == 401

    @pytest.mark.simulated_auth
    @pytest.mark.parametrize('scope', ['P9', 'P5', 'P0'])
    async def test_nhs_login_refresh_tokens_generated_with_expected_expiry_separated_auth(self, scope):
        """
        Test that refresh tokens generated via NHS Login have an expiry time of 1 hour for separated authentication.
        """
        id_token_claims = {
            "aud": "tf_-APIM-1",
            "id_status": "verified",
            "token_use": "id",
            "auth_time": 1616600683,
            "iss": "https://internal-dev.api.service.nhs.uk",
            "vot": "P9.Cp.Cd",
            "exp": int(time()) + 600,
            "iat": int(time()) - 10,
            "vtm": "https://auth.sandpit.signin.nhs.uk/trustmark/auth.sandpit.signin.nhs.uk",
            "jti": str(uuid4()),
            "identity_proofing_level": scope,
            "nhs_number": "900000000001"
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
            "jti": str(uuid4()),
        }

        with open(ID_TOKEN_NHS_LOGIN_PRIVATE_KEY_ABSOLUTE_PATH, "r") as f:
            contents = f.read()

        client_assertion_jwt = self.oauth.create_jwt(kid="test-1")
        id_token_jwt = self.oauth.create_id_token_jwt(
            algorithm="RS512",
            claims=id_token_claims,
            headers=id_token_headers,
            signing_key=contents,
        )
        resp = await self.oauth.get_token_response(
            grant_type="token_exchange",
            _jwt=client_assertion_jwt,
            id_token_jwt=id_token_jwt,
        )
        access_token = resp['body']['access_token']
        refresh_token = resp['body']['refresh_token']

        assert access_token
        assert refresh_token
        assert resp['body']['expires_in'] == '599'
        assert resp['body']['refresh_token_expires_in'] == '3599'

    @pytest.mark.simulated_auth
    async def test_cis2_refresh_tokens_generated_with_expected_expiry_separated_auth(self):
        """
        Test that refresh tokens generated via CIS2 have an expiry time of 12 hours for separated authentication.
        """
        # Generate access token using token-exchange
        id_token_jwt = self.oauth.create_id_token_jwt()
        client_assertion_jwt = self.oauth.create_jwt(kid='test-1')
        resp = await self.oauth.get_token_response(
            grant_type="token_exchange",
            _jwt=client_assertion_jwt,
            id_token_jwt=id_token_jwt
        )

        access_token = resp['body']['access_token']
        refresh_token = resp['body']['refresh_token']

        assert access_token
        assert refresh_token
        assert resp['body']['expires_in'] == '599'
        assert resp['body']['refresh_token_expires_in'] == '43199'
