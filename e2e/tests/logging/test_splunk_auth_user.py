import pytest
import requests
from api_test_utils.apigee_api_trace import ApigeeApiTraceDebug
from time import time
from uuid import uuid4

from e2e.scripts.config import OAUTH_URL, HELLO_WORLD_API_URL, ENVIRONMENT, ID_TOKEN_NHS_LOGIN_PRIVATE_KEY_ABSOLUTE_PATH, MOCK_IDP_BASE_URL


@pytest.mark.asyncio
class TestSplunkLogging:
    @pytest.mark.happy_path
    @pytest.mark.logging
    @pytest.mark.usefixtures('set_access_token')
    async def test_populate_access_token_hash(self, helper):
        # Given
        apigee_trace = ApigeeApiTraceDebug(proxy=f"hello-world-{ENVIRONMENT}")

        # When
        await apigee_trace.start_trace()
        requests.get(f"{HELLO_WORLD_API_URL}", headers={"Authorization": f"Bearer {self.oauth.access_token}"})

        # Then
        expected_access_token_hash = self.oauth.access_token
        access_token_hash = await apigee_trace.get_apigee_variable_from_trace(name='auth.access_token_hash')


