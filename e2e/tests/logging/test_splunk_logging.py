import pytest
import random
import json
from api_test_utils.apigee_api_trace import ApigeeApiTraceDebug

from e2e.scripts import config


@pytest.mark.asyncio
class TestSplunkLoggingFields:
    @staticmethod
    async def _get_payload_from_splunk(debug):
        splunk_content_json = await debug.get_apigee_variable_from_trace(name='splunkCalloutRequest.content')
        return json.loads(splunk_content_json)

    @pytest.mark.happy_path
    @pytest.mark.logging
    async def test_splunk_fields_for_authorize_endpoint_for_cis2(self):
        debug = ApigeeApiTraceDebug(proxy=config.SERVICE_NAME)

        await debug.start_trace()
        await self.oauth.hit_oauth_endpoint(
            method="GET",
            endpoint="authorize",
            params={
                "client_id": self.oauth.client_id,
                "redirect_uri": self.oauth.redirect_uri,
                "response_type": "code",
                "state": random.getrandbits(32),
            },
        )

        payload = await self._get_payload_from_splunk(debug)

        # Then
        auth = payload["auth"]

        auth_meta = auth["meta"]
        assert auth_meta["auth_type"] == "user"
        assert auth_meta["grant_type"] == "authorization_code"
        assert auth_meta["level"] == ""  # level is unknown when hitting /authorize
        assert auth_meta["provider"] == "nhs-cis2"

        auth_user = auth["user"]
        assert auth_user["user_id"] == ""  # user_id is unknown when hitting /authorize

    @pytest.mark.happy_path
    @pytest.mark.logging
    async def test_splunk_fields_for_callback_endpoint_for_cis2(self, helper):
        # Given
        response = await self.oauth.hit_oauth_endpoint(
            method="GET",
            endpoint="authorize",
            params={
                "client_id": self.oauth.client_id,
                "redirect_uri": self.oauth.redirect_uri,
                "response_type": "code",
                "state": "1234567890",
            },
            allow_redirects=False,
        )

        state = helper.get_param_from_url(
            url=response["headers"]["Location"], param="state"
        )

        # Make simulated auth request to authenticate
        response = await self.oauth.hit_oauth_endpoint(
            base_uri=config.MOCK_IDP_BASE_URL,
            method="POST",
            endpoint="simulated_auth",
            params={
                "response_type": "code",
                "client_id": self.oauth.client_id,
                "redirect_uri": self.oauth.redirect_uri,
                "scope": "openid",
                "state": state,
            },
            headers={"Content-Type": "application/x-www-form-urlencoded"},
            data={"state": state},
            allow_redirects=False,
        )

        # Make initial callback request
        auth_code = helper.get_param_from_url(
            url=response["headers"]["Location"], param="code"
        )

        # When
        debug = ApigeeApiTraceDebug(proxy=config.SERVICE_NAME)
        await debug.start_trace()
        await self.oauth.hit_oauth_endpoint(
            method="GET",
            endpoint="callback",
            params={"code": auth_code, "client_id": "some-client-id", "state": state},
            allow_redirects=False,
        )

        payload = await self._get_payload_from_splunk(debug)

        # Then
        auth = payload["auth"]

        auth_meta = auth["meta"]
        assert auth_meta["auth_type"] == "user"
        assert auth_meta["grant_type"] == "authorization_code"
        assert auth_meta["level"] == "aal3"
        assert auth_meta["provider"] == "nhs-cis2"

        auth_user = auth["user"]
        assert auth_user["user_id"] == "787807429511"

    @pytest.mark.happy_path
    @pytest.mark.logging
    async def test_splunk_fields_for_callback_endpoint_for_nhs_login(self, helper):
        # Given
        response = await self.oauth.hit_oauth_endpoint(
            method="GET",
            endpoint="authorize",
            params={
                "client_id": self.oauth.client_id,
                "redirect_uri": self.oauth.redirect_uri,
                "response_type": "code",
                "state": "1234567890",
                "scope": "nhs-login",
            },
            allow_redirects=False,
        )

        state = helper.get_param_from_url(
            url=response["headers"]["Location"], param="state"
        )

        # Make simulated auth request to authenticate
        response = await self.oauth.hit_oauth_endpoint(
            base_uri=config.MOCK_IDP_BASE_URL,
            method="POST",
            endpoint="simulated_auth",
            params={
                "response_type": "code",
                "client_id": self.oauth.client_id,
                "redirect_uri": self.oauth.redirect_uri,
                "scope": "openid",
                "state": state,
            },
            headers={"Content-Type": "application/x-www-form-urlencoded"},
            data={"state": state},
            allow_redirects=False,
        )

        # Make initial callback request
        auth_code = helper.get_param_from_url(
            url=response["headers"]["Location"], param="code"
        )

        # When
        debug = ApigeeApiTraceDebug(proxy=config.SERVICE_NAME)
        await debug.start_trace()
        await self.oauth.hit_oauth_endpoint(
            method="GET",
            endpoint="callback",
            params={"code": auth_code, "client_id": "some-client-id", "state": state},
            allow_redirects=False,
        )

        payload = await self._get_payload_from_splunk(debug)

        # Then
        auth = payload["auth"]

        auth_meta = auth["meta"]
        assert auth_meta["auth_type"] == "user"
        assert auth_meta["grant_type"] == "authorization_code"
        assert auth_meta["level"] == "p9"
        assert auth_meta["provider"] == "apim-mock-nhs-login"

        auth_user = auth["user"]
        assert auth_user["user_id"] == "9912003071"
