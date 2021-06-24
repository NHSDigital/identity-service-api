import pytest
import requests
from api_test_utils.apigee_api_trace import ApigeeApiTraceDebug
from time import time
from uuid import uuid4

from e2e.scripts.config import OAUTH_URL, HELLO_WORLD_API_URL, ENVIRONMENT


@pytest.mark.asyncio
class TestSplunkLogging:
    @pytest.mark.happy_path
    @pytest.mark.logging
    @pytest.mark.usefixtures('set_access_token')
    async def test_access_token_fields_for_logging_when_using_authorization_code(self, helper):
        # Given
        apigee_trace = ApigeeApiTraceDebug(proxy=f"hello-world-{ENVIRONMENT}")
        assert helper.check_endpoint(
            verb='GET',
            endpoint=HELLO_WORLD_API_URL,
            expected_status_code=200,
            expected_response={"message": "hello user!"},
            headers={
                'Authorization': f'Bearer {self.oauth.access_token}',
                'NHSD-Session-URID': 'ROLD-ID',
            }
        )
        # When
        print(self.oauth.access_token)
        await apigee_trace.start_trace()
        requests.get(f"{HELLO_WORLD_API_URL}", headers={"Authorization": f"Bearer {self.oauth.access_token}"})

        # Then
        auth_type = await apigee_trace.get_apigee_variable_from_trace(name='accesstoken.auth_type')
        auth_grant_type = await apigee_trace.get_apigee_variable_from_trace(name='accesstoken.auth_grant_type')

        assert auth_type == 'app'
        assert auth_grant_type == 'client_credentials'

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

        assert auth_type == 'app'
        assert auth_grant_type == 'client_credentials'

    @pytest.mark.happy_path
    @pytest.mark.logging
    @pytest.mark.debug
    async def test_access_token_fields_for_logging_when_using_token_exchange(self):
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

        assert auth_type == 'user'
        assert auth_grant_type == 'token_exchange'
