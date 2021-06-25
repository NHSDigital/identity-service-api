import pytest
import requests
from api_test_utils.apigee_api_trace import ApigeeApiTraceDebug
from time import time
from uuid import uuid4

from e2e.scripts.config import OAUTH_URL, HELLO_WORLD_API_URL, ENVIRONMENT, ID_TOKEN_NHS_LOGIN_PRIVATE_KEY_ABSOLUTE_PATH


@pytest.mark.asyncio
class TestSplunkLogging:
    @pytest.mark.happy_path
    @pytest.mark.logging
    @pytest.mark.usefixtures('set_access_token')
    async def test_access_token_fields_for_logging_when_using_authorization_code(self, helper):
        # Given
        apigee_trace = ApigeeApiTraceDebug(proxy=f"hello-world-{ENVIRONMENT}")

        # When
        await apigee_trace.start_trace()
        requests.get(f"{HELLO_WORLD_API_URL}", headers={"Authorization": f"Bearer {self.oauth.access_token}"})

        # Then
        auth_type = await apigee_trace.get_apigee_variable_from_trace(name='accesstoken.auth_type')
        auth_grant_type = await apigee_trace.get_apigee_variable_from_trace(name='accesstoken.auth_grant_type')
        auth_level = await apigee_trace.get_apigee_variable_from_trace(name='accesstoken.auth_level')
        auth_provider = await apigee_trace.get_apigee_variable_from_trace(name='accesstoken.auth_provider')

        assert auth_type == 'user'
        assert auth_grant_type == 'authorization_code'
        assert auth_level == 'aal3'
        assert auth_provider == 'nhs-cis2'

    @pytest.mark.happy_path
    @pytest.mark.logging
    async def test_access_token_fields_for_logging_when_using_client_credentials(self):
        # Given
        apigee_trace = ApigeeApiTraceDebug(proxy=f"hello-world-{ENVIRONMENT}")
        jwt_claims = {
            'kid': 'test-1',
            'claims': {
                "sub": self.oauth.client_id,
                "iss": self.oauth.client_id,
                "jti": str(uuid4()),
                "aud": f"{OAUTH_URL}/token",
                "exp": int(time()),  # this includes the +30 seconds grace
            }
        }
        jwt = self.oauth.create_jwt(**jwt_claims)
        resp = await self.oauth.get_token_response(grant_type='client_credentials', _jwt=jwt)
        access_token = resp['body']['access_token']

        # When
        await apigee_trace.start_trace()
        requests.get(f"{HELLO_WORLD_API_URL}", headers={"Authorization": f"Bearer {access_token}"})

        # Then
        auth_type = await apigee_trace.get_apigee_variable_from_trace(name='accesstoken.auth_type')
        auth_grant_type = await apigee_trace.get_apigee_variable_from_trace(name='accesstoken.auth_grant_type')
        auth_level = await apigee_trace.get_apigee_variable_from_trace(name='accesstoken.auth_level')
        auth_provider = await apigee_trace.get_apigee_variable_from_trace(name='accesstoken.auth_provider')

        assert auth_type == 'app'
        assert auth_grant_type == 'client_credentials'
        assert auth_level == 'level3'
        assert auth_provider == 'apim'

    @pytest.mark.happy_path
    @pytest.mark.logging
    async def test_access_token_fields_for_logging_when_using_token_exchange_cis2(self):
        # Given
        apigee_trace = ApigeeApiTraceDebug(proxy=f"hello-world-{ENVIRONMENT}")

        id_token_jwt = self.oauth.create_id_token_jwt()
        client_assertion_jwt = self.oauth.create_jwt(kid='test-1')
        resp = await self.oauth.get_token_response(grant_type='token_exchange', _jwt=client_assertion_jwt,
                                                   id_token_jwt=id_token_jwt)
        access_token = resp['body']['access_token']

        # When
        await apigee_trace.start_trace()
        requests.get(f"{HELLO_WORLD_API_URL}", headers={"Authorization": f"Bearer {access_token}"})

        # Then
        auth_type = await apigee_trace.get_apigee_variable_from_trace(name='accesstoken.auth_type')
        auth_grant_type = await apigee_trace.get_apigee_variable_from_trace(name='accesstoken.auth_grant_type')
        auth_provider = await apigee_trace.get_apigee_variable_from_trace(name='accesstoken.auth_provider')
        auth_level = await apigee_trace.get_apigee_variable_from_trace(name='accesstoken.auth_level')

        assert auth_type == 'user'
        assert auth_grant_type == 'token_exchange'
        assert auth_provider == 'nhs-cis2'
        assert auth_level == 'aal3'

    @pytest.mark.happy_path
    @pytest.mark.logging
    @pytest.mark.debug
    # @pytest.mark.parametrize('scope', ['P9', 'P5', 'P0'])
    async def test_access_token_fields_for_logging_when_using_token_exchange_nhs_login(self):
        # Given
        apigee_trace = ApigeeApiTraceDebug(proxy=f"hello-world-{ENVIRONMENT}")

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
            "jti": "b68ddb28-e440-443d-8725-dfe0da330118",
            "identity_proofing_level": 'P5'
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
            "jti": "b68ddb28-e440-443d-8725-dfe0da330118",
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

        # When
        await apigee_trace.start_trace()
        requests.get(f"{HELLO_WORLD_API_URL}", headers={"Authorization": f"Bearer {access_token}"})

        # Then
        auth_type = await apigee_trace.get_apigee_variable_from_trace(name='accesstoken.auth_type')
        auth_grant_type = await apigee_trace.get_apigee_variable_from_trace(name='accesstoken.auth_grant_type')
        auth_provider = await apigee_trace.get_apigee_variable_from_trace(name='accesstoken.auth_provider')
        auth_level = await apigee_trace.get_apigee_variable_from_trace(name='accesstoken.auth_level')

        assert auth_type == 'user'
        assert auth_grant_type == 'token_exchange'
        assert auth_provider == 'nhs-login'
        assert auth_level == 'p9'
