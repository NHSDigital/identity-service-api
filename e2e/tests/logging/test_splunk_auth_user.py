import base64
import hashlib
import hmac
import pytest
from time import time
from api_test_utils.apigee_api_trace import ApigeeApiTraceDebug
from api_test_utils.oauth_helper import OauthHelper
from e2e.scripts.config import (
    OAUTH_URL,
    SERVICE_NAME,
    ACCESS_TOKEN_SECRET,
    MOCK_IDP_BASE_URL,
    ID_TOKEN_NHS_LOGIN_PRIVATE_KEY_ABSOLUTE_PATH,
)


def calculate_hmac_sha512(content: str, key: str) -> str:
    binary_content = bytes(content, "utf-8")
    hmac_key = bytes(key, "utf-8")
    signature = hmac.new(hmac_key, binary_content, hashlib.sha512)

    return base64.b64encode(signature.digest())


@pytest.mark.asyncio
class TestSplunkUserAuthLogging:
    @pytest.mark.happy_path
    @pytest.mark.logging
    @pytest.mark.debug2
    async def test_populate_hashed_access_token_using_auth_code_cis2(
        self, test_app_and_product, helper
    ):
        # Given
        p1, p2, test_app = test_app_and_product
        await p1.update_scopes(
            ["urn:nhsd:apim:user-nhs-id:aal3:personal-demographics-service"]
        )
        await p2.update_scopes([])

        callback_url = await test_app.get_callback_url()
        oauth = OauthHelper(test_app.client_id, test_app.client_secret, callback_url)

        apigee_trace = ApigeeApiTraceDebug(proxy=SERVICE_NAME)

        # When
        await apigee_trace.start_trace()
        res = helper.send_request(
            verb="POST",
            endpoint=f"{OAUTH_URL}/token",
            data={
                "client_id": test_app.get_client_id(),
                "client_secret": test_app.get_client_secret(),
                "redirect_uri": callback_url,
                "grant_type": "authorization_code",
                "code": await oauth.get_authenticated_with_simulated_auth(),
            },
        )
        access_token = res.json()["access_token"]

        # Then
        expected_access_token_hashed = calculate_hmac_sha512(
            access_token, ACCESS_TOKEN_SECRET
        ).decode("utf-8")
        actual_access_token_hashed = await apigee_trace.get_apigee_variable_from_trace(
            name="auth.access_token_hash"
        )
        assert expected_access_token_hashed == actual_access_token_hashed

    @pytest.mark.happy_path
    @pytest.mark.logging
    @pytest.mark.debug2
    async def test_populate_hashed_access_token_using_auth_code_nhs_login(
        self, test_app_and_product, helper
    ):
        # Given
        # Make authorize request to retrieve state2
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
            base_uri=MOCK_IDP_BASE_URL,
            method="POST",
            endpoint="nhs_login_simulated_auth",
            params={
                "response_type": "code",
                "client_id": self.oauth.client_id,
                "redirect_uri": self.oauth.redirect_uri,
                "scope": "openid",
                "state": state,
            },
            headers={"Content-Type": "application/x-www-form-urlencoded"},
            data={"state": state, "auth_method": "P9"},
            allow_redirects=False,
        )

        # Make initial callback request
        auth_code = helper.get_param_from_url(
            url=response["headers"]["Location"], param="code"
        )

        response = await self.oauth.hit_oauth_endpoint(
            method="GET",
            endpoint="callback",
            params={"code": auth_code, "client_id": "some-client-id", "state": state},
            allow_redirects=False,
        )

        auth_code = helper.get_param_from_url(
            url=response["headers"]["Location"], param="code"
        )

        apigee_trace = ApigeeApiTraceDebug(proxy=SERVICE_NAME)

        # When
        await apigee_trace.start_trace()
        response = await self.oauth.hit_oauth_endpoint(
            method="POST",
            endpoint="token",
            data={
                "grant_type": "authorization_code",
                "state": state,
                "code": auth_code,
                "redirect_uri": self.oauth.redirect_uri,
                "client_id": self.oauth.client_id,
                "client_secret": self.oauth.client_secret,
            },
            allow_redirects=False,
        )

        access_token = response["body"]["access_token"]

        # Then
        expected_access_token_hashed = calculate_hmac_sha512(
            access_token, ACCESS_TOKEN_SECRET
        ).decode("utf-8")
        actual_access_token_hashed = await apigee_trace.get_apigee_variable_from_trace(
            name="auth.access_token_hash"
        )
        assert expected_access_token_hashed == actual_access_token_hashed

    @pytest.mark.happy_path
    @pytest.mark.logging
    @pytest.mark.debug2
    async def test_populate_hashed_access_token_using_client_credentials(self):
        jwt = self.oauth.create_jwt(kid="test-1")
        apigee_trace = ApigeeApiTraceDebug(proxy=SERVICE_NAME)
        await apigee_trace.start_trace()
        response = await self.oauth.get_token_response("client_credentials", _jwt=jwt)
        access_token = response["body"]["access_token"]
        expected_access_token_hashed = calculate_hmac_sha512(
            access_token, ACCESS_TOKEN_SECRET
        ).decode("utf-8")
        actual_access_token_hashed = await apigee_trace.get_apigee_variable_from_trace(
            name="auth.access_token_hash"
        )
        assert expected_access_token_hashed == actual_access_token_hashed

    @pytest.mark.happy_path
    @pytest.mark.logging
    @pytest.mark.debug2
    async def test_populate_hashed_access_token_using_token_exchange_cis2(self):

        id_token_jwt = self.oauth.create_id_token_jwt()
        client_assertion_jwt = self.oauth.create_jwt(kid="test-1")
        apigee_trace = ApigeeApiTraceDebug(proxy=SERVICE_NAME)
        await apigee_trace.start_trace()
        response = await self.oauth.get_token_response(
            grant_type="token_exchange",
            _jwt=client_assertion_jwt,
            id_token_jwt=id_token_jwt,
        )
        access_token = response["body"]["access_token"]
        expected_access_token_hashed = calculate_hmac_sha512(
            access_token, ACCESS_TOKEN_SECRET
        ).decode("utf-8")
        actual_access_token_hashed = await apigee_trace.get_apigee_variable_from_trace(
            name="auth.access_token_hash"
        )
        assert expected_access_token_hashed == actual_access_token_hashed

    @pytest.mark.happy_path
    @pytest.mark.logging
    @pytest.mark.debug2
    async def test_populate_hashed_access_token_using_token_exchange_nhs_login(self):

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
            "identity_proofing_level": "P9",
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

        # When
        apigee_trace = ApigeeApiTraceDebug(proxy=SERVICE_NAME)
        await apigee_trace.start_trace()
        response = await self.oauth.get_token_response(
            grant_type="token_exchange",
            data={
                "grant_type": "urn:ietf:params:oauth:grant-type:token-exchange",
                "subject_token_type": "urn:ietf:params:oauth:token-type:id_token",
                "client_assertion_type": "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
                "subject_token": id_token_jwt,
                "client_assertion": client_assertion_jwt,
            },
        )

        access_token = response["body"]["access_token"]
        expected_access_token_hashed = calculate_hmac_sha512(
            access_token, ACCESS_TOKEN_SECRET
        ).decode("utf-8")
        actual_access_token_hashed = await apigee_trace.get_apigee_variable_from_trace(
            name="auth.access_token_hash"
        )
        assert expected_access_token_hashed == actual_access_token_hashed
