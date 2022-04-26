from e2e.scripts.config import (
    OAUTH_URL,
    STATUS_ENDPOINT_API_KEY,
)
from e2e.scripts.response_bank import BANK
import pytest
import random

@pytest.mark.asyncio
class TestOauthEndpoints:
    """ A test suit to verify all the oauth endpoints """

    def _update_secrets(self, request):
        key = ("params", "data")[request.get("params", None) is None]
        if request[key].get("client_id", None) == "/replace_me":
            request[key]["client_id"] = self.oauth.client_id

        if request[key].get("client_secret", None) == "/replace_me":
            request[key]["client_secret"] = self.oauth.client_secret

        if request[key].get("redirect_uri", None) == "/replace_me":
            request[key]["redirect_uri"] = self.oauth.redirect_uri

    @pytest.mark.apm_801
    @pytest.mark.happy_path
    @pytest.mark.authorize_endpoint
    async def test_authorize_endpoint(self):
        resp = await self.oauth.hit_oauth_endpoint(
            method="GET",
            endpoint="authorize",
            params={
                "client_id": self.oauth.client_id,
                "redirect_uri": self.oauth.redirect_uri,
                "response_type": "code",
                "state": random.getrandbits(32),
            },
        )

        assert resp["status_code"] == 200
        # assert resp['body'] == BANK.get(self.name)["response"]

    @pytest.mark.apm_801
    @pytest.mark.happy_path
    @pytest.mark.token_endpoint
    async def test_token_endpoint(self):
        resp = await self.oauth.get_token_response(grant_type="authorization_code")

        assert resp["status_code"] == 200
        assert set(resp["body"].keys()) == {
            "access_token",
            "expires_in",
            "refresh_count",
            "refresh_token",
            "refresh_token_expires_in",
            "sid",
            "token_type",
        }

    @pytest.mark.apm_1618
    @pytest.mark.apm_1475
    @pytest.mark.errors
    @pytest.mark.token_endpoint
    @pytest.mark.authorize_endpoint
    @pytest.mark.parametrize(
        "method, endpoint",
        [
            ("GET", "token"),
            ("POST", "authorize"),
        ],
    )
    async def test_token_endpoint_http_allowed_methods(self, method, endpoint):
        resp = await self.oauth.hit_oauth_endpoint(method=method, endpoint=endpoint)

        allow = ("POST", "GET")[method == "POST"]

        assert resp["status_code"] == 405
        assert resp["body"] == ""
        assert resp["headers"].get("Allow", "The Allow Header is Missing") == allow

    @pytest.mark.apm_993
    @pytest.mark.errors
    @pytest.mark.authorize_endpoint
    @pytest.mark.parametrize("auth_method", [(None)])
    async def test_cache_invalidation(self, helper, auth_code_nhs_cis2):
        """
        Test identity cache invalidation after use:
            * Given i am authorizing
            * When the first request has succeeded
            * When using the same state as the first request
            * Then it should return xxx
        """

        # Make authorize request to retrieve state2
        state = await auth_code_nhs_cis2.get_state(self.oauth)        
        
        # Make simulated auth request to authenticate and make initial callback request
        auth_code = await auth_code_nhs_cis2.make_auth_request(self.oauth, state)
        auth_code = await auth_code_nhs_cis2.make_callback_request(self.oauth, state, auth_code)

        # Make second callback request with same state value
        assert helper.check_endpoint(
            verb="GET",
            endpoint=f"{OAUTH_URL}/callback",
            expected_status_code=400,
            expected_response={
                "error": "invalid_request",
                "error_description": "invalid state parameter.",
            },
            params={"code": auth_code, "client_id": "some-client-id", "state": state},
        )

    @pytest.mark.apm_801
    @pytest.mark.apm_990
    @pytest.mark.apm_1475
    @pytest.mark.errors
    @pytest.mark.authorize_endpoint
    @pytest.mark.parametrize(
        "request_data",
        [
            # condition 1: invalid redirect uri
            {
                "expected_status_code": 400,
                "expected_response": {
                    "error": "invalid_request",
                    "error_description": "redirect_uri is invalid",
                },
                "params": {
                    "client_id": "/replace_me",
                    "redirect_uri": f"/invalid",  # invalid redirect uri
                    "response_type": "code",
                    "state": random.getrandbits(32),
                },
            },
            # condition 2: missing redirect uri
            {
                "expected_status_code": 400,
                "expected_response": {
                    "error": "invalid_request",
                    "error_description": "redirect_uri is missing",
                },
                "params": {
                    "client_id": "/replace_me",
                    "response_type": "code",
                    "state": random.getrandbits(32),
                },
            },
            # condition 3: invalid client id
            {
                "expected_status_code": 401,
                "expected_response": {
                    "error": "invalid_request",
                    "error_description": "client_id is invalid",
                },
                "params": {
                    "client_id": "invalid",  # invalid client id
                    "redirect_uri": "/replace_me",
                    "response_type": "code",
                    "state": random.getrandbits(32),
                },
            },
            # condition 4: missing client id
            {
                "expected_status_code": 401,
                "expected_response": {
                    "error": "invalid_request",
                    "error_description": "client_id is missing",
                },
                "params": {  # not providing client_id
                    "redirect_uri": "/replace_me",
                    "response_type": "code",
                    "state": random.getrandbits(32),
                },
            },
        ],
    )
    async def test_authorization_error_conditions(self, request_data: dict, helper):
        self._update_secrets(request_data)

        assert await helper.send_request_and_check_output(
            expected_status_code=request_data["expected_status_code"],
            expected_response=request_data["expected_response"],
            function=self.oauth.hit_oauth_endpoint,
            method="GET",
            endpoint="authorize",
            params=request_data["params"],
        )

    @pytest.mark.errors
    @pytest.mark.authorize_endpoint
    async def test_authorize_revoked_app(self, app, helper):
        await app.create_new_app(status="revoked")

        assert await helper.send_request_and_check_output(
            expected_status_code=401,
            expected_response={
                "error": "access_denied",
                "error_description": "The developer app associated with the API key is not approved or revoked",
            },
            function=self.oauth.hit_oauth_endpoint,
            method="GET",
            endpoint="authorize",
            params={
                "client_id": app.client_id,
                "redirect_uri": app.callback_url,
                "response_type": "code",
                "state": random.getrandbits(32),
            },
        )

    async def test_authorize_unsubscribed_error_condition(
        self, test_product, test_app, helper
    ):
        await test_product.update_proxies(["hello-world-internal-dev"])
        await test_app.add_api_product([test_product.name])

        assert await helper.send_request_and_check_output(
            expected_status_code=401,
            expected_response={
                "error": "access_denied",
                "error_description": "API Key supplied does not have access to this resource. "
                "Please check the API Key you are using belongs to an app "
                "which has sufficient access to access this resource.",
            },
            function=self.oauth.hit_oauth_endpoint,
            method="GET",
            endpoint="authorize",
            params={
                "client_id": test_app.client_id,
                "redirect_uri": test_app.callback_url,
                "response_type": "code",
                "state": random.getrandbits(32),
            },
        )

    @pytest.mark.apm_1631
    @pytest.mark.errors
    @pytest.mark.token_endpoint
    async def test_token_unsubscribed_error_condition(
        self, test_product, test_app, helper
    ):
        await test_product.update_proxies(["hello-world-internal-dev"])
        await test_app.add_api_product([test_product.name])

        assert await helper.send_request_and_check_output(
            expected_status_code=401,
            expected_response={
                "error": "access_denied",
                "error_description": "API Key supplied does not have access to this resource."
                " Please check the API Key you are using belongs to an app"
                " which has sufficient access to access this resource.",
            },
            function=self.oauth.get_token_response,
            grant_type="authorization_code",
            data={
                "client_id": test_app.client_id,
                "client_secret": test_app.client_secret,
                "redirect_uri": test_app.callback_url,
                "grant_type": "authorization_code",
                "code": await self.oauth.get_authenticated_with_simulated_auth(),
            },
        )

    @pytest.mark.apm_1475
    @pytest.mark.errors
    @pytest.mark.authorize_endpoint
    @pytest.mark.parametrize(
        "test_case",
        [
            # condition 1: missing state
            {
                "expected_status_code": 302,
                "expected_response": "",
                "expected_params": {
                    "error": "invalid_request",
                    "error_description": "state is missing",
                },
                "params": {
                    "client_id": "/replace_me",
                    "redirect_uri": "/replace_me",
                    "response_type": "code",
                },
            },
            # condition 2: missing response type
            {
                "expected_status_code": 302,
                "expected_response": "",
                "expected_params": {
                    "error": "invalid_request",
                    "error_description": "response_type is missing",
                },
                "params": {
                    "client_id": "/replace_me",
                    "redirect_uri": "/replace_me",
                    "state": random.getrandbits(32),
                },
            },
            # condition 5: invalid response type
            {
                "expected_status_code": 302,
                "expected_response": "",
                "expected_params": {
                    "error": "unsupported_response_type",
                    "error_description": "response_type is invalid",
                },
                "params": {
                    "client_id": "/replace_me",
                    "redirect_uri": "/replace_me",
                    "response_type": "invalid",  # invalid response type
                    "state": random.getrandbits(32),
                },
            },
        ],
    )
    async def test_authorization_error_redirects(self, test_case: dict, helper):
        self._update_secrets(test_case)

        resp = await self.oauth.hit_oauth_endpoint(
            method="GET",
            endpoint="authorize",
            params=test_case["params"],
            allow_redirects=False,
        )

        assert resp["status_code"] == test_case["expected_status_code"]
        assert resp["body"] == test_case["expected_response"]

        helper.check_redirect(
            response=resp,
            expected_params=test_case["expected_params"],
            client_redirect=self.oauth.redirect_uri,
            state=test_case["params"].get("state"),
        )

    @pytest.mark.apm_1618
    @pytest.mark.errors
    @pytest.mark.token_endpoint
    @pytest.mark.parametrize(
        "request_data, expected_response",
        [
            # condition 2: invalid grant type
            (
                {
                    "headers": {"Content-Type": "application/x-www-form-urlencoded"},
                    "data": {
                        "client_id": "/replace_me",
                        "client_secret": "/replace_me",
                        "redirect_uri": "/replace_me",
                        "grant_type": "invalid",
                    },
                },
                {
                    "status_code": 400,
                    "body": {
                        "error": "unsupported_grant_type",
                        "error_description": "grant_type is invalid",
                    },
                },
            ),
            # condition 3: missing grant_type
            (
                {
                    "headers": {"Content-Type": "application/x-www-form-urlencoded"},
                    "data": {
                        "client_id": "/replace_me",
                        "client_secret": "/replace_me",
                        "redirect_uri": "/replace_me",
                    },
                },
                {
                    "status_code": 400,
                    "body": {
                        "error": "invalid_request",
                        "error_description": "grant_type is missing",
                    },
                },
            ),
            # condition 4: missing client_id
            (
                {
                    "headers": {"Content-Type": "application/x-www-form-urlencoded"},
                    "data": {
                        "client_secret": "/replace_me",
                        "redirect_uri": "/replace_me",
                        "grant_type": "authorization_code",
                    },
                },
                {
                    "status_code": 401,
                    "body": {
                        "error": "invalid_request",
                        "error_description": "client_id is missing",
                    },
                },
            ),
            # condition 5: invalid client_id
            (
                {
                    "headers": {"Content-Type": "application/x-www-form-urlencoded"},
                    "data": {
                        "client_id": "THISisANinvalidCLIENTid12345678",
                        "client_secret": "/replace_me",
                        "redirect_uri": "/replace_me",
                        "grant_type": "authorization_code",
                    },
                },
                {
                    "status_code": 401,
                    "body": {
                        "error": "invalid_client",
                        "error_description": "client_id or client_secret is invalid",
                    },
                },
            ),
            # condition 6: invalid client secret
            (
                {
                    "headers": {"Content-Type": "application/x-www-form-urlencoded"},
                    "data": {
                        "client_id": "/replace_me",
                        "client_secret": "ThisSecretIsInvalid",
                        "redirect_uri": "/replace_me",
                        "grant_type": "authorization_code",
                    },
                },
                {
                    "status_code": 401,
                    "body": {
                        "error": "invalid_client",
                        "error_description": "client_id or client_secret is invalid",
                    },
                },
            ),
            # condition 7: missing client secret
            (
                {
                    "headers": {"Content-Type": "application/x-www-form-urlencoded"},
                    "data": {
                        "client_id": "/replace_me",
                        "redirect_uri": "/replace_me",
                        "grant_type": "authorization_code",
                    },
                },
                {
                    "status_code": 401,
                    "body": {
                        "error": "invalid_request",
                        "error_description": "client_secret is missing",
                    },
                },
            ),
            # condition 8: redirect_uri is missing
            (
                {
                    "headers": {"Content-Type": "application/x-www-form-urlencoded"},
                    "data": {
                        "client_id": "/replace_me",
                        "client_secret": "/replace_me",
                        "grant_type": "authorization_code",
                    },
                },
                {
                    "status_code": 400,
                    "body": {
                        "error": "invalid_request",
                        "error_description": "redirect_uri is missing",
                    },
                },
            ),
            # condition 9: redirect_uri is invalid
            (
                {
                    "headers": {"Content-Type": "application/x-www-form-urlencoded"},
                    "data": {
                        "client_id": "/replace_me",
                        "client_secret": "/replace_me",
                        "redirect_uri": "invalid",
                        "grant_type": "authorization_code",
                    },
                },
                {
                    "status_code": 400,
                    "body": {
                        "error": "invalid_request",
                        "error_description": "redirect_uri is invalid",
                    },
                },
            ),
            # condition 10: authorization code is missing
            (
                {
                    "headers": {"Content-Type": "application/x-www-form-urlencoded"},
                    "data": {
                        "client_id": "/replace_me",
                        "client_secret": "/replace_me",
                        "redirect_uri": "/replace_me",
                        "grant_type": "authorization_code",
                    },
                },
                {
                    "status_code": 400,
                    "body": {
                        "error": "invalid_request",
                        "error_description": "authorization_code is missing",
                    },
                },
            ),
            # condition 11: authorization code is invalid
            (
                {
                    "headers": {"Content-Type": "application/x-www-form-urlencoded"},
                    "data": {
                        "client_id": "/replace_me",
                        "client_secret": "/replace_me",
                        "redirect_uri": "/replace_me",
                        "grant_type": "authorization_code",
                        "code": "invalid",
                    },
                },
                {
                    "status_code": 400,
                    "body": {
                        "error": "invalid_grant",
                        "error_description": "authorization_code is invalid",
                    },
                },
            ),
        ],
    )
    async def test_token_error_conditions(
        self, request_data: dict, expected_response: dict, helper
    ):
        self._update_secrets(request_data)

        assert await helper.send_request_and_check_output(
            expected_status_code=expected_response["status_code"],
            expected_response=expected_response["body"],
            function=self.oauth.get_token_response,
            grant_type="authorization_code",
            **request_data,
        )

    @pytest.mark.apm_1064
    @pytest.mark.errors
    @pytest.mark.xfail(reason="APM-2521: Endpoint has been deprecated")
    @pytest.mark.callback_endpoint
    @pytest.mark.parametrize("auth_method", [(None)])
    async def test_callback_error_conditions(self, helper, auth_code_nhs_cis2):
        
        state = await auth_code_nhs_cis2.get_state(self.oauth)
        assert await helper.send_request_and_check_output(

            expected_status_code=401,
            expected_response="",
            function=self.oauth.hit_oauth_endpoint,
            method="GET",
            endpoint="callback",
            params={
                "code": "some-code",
                "client_id": "invalid-client-id",
                "state": state
            },
        )

    @pytest.mark.apm_1475
    @pytest.mark.errors
    @pytest.mark.token_endpoint
    @pytest.mark.parametrize(
        "test_case",
        [
            # condition 1: missing client id
            {
                "expected_status_code": 401,
                "expected_response": {
                    "error": "invalid_request",
                    "error_description": "client_id is missing",
                },
                "data": {
                    "client_secret": "/replace_me",
                    "grant_type": "refresh_token",
                },
            },
            # condition 2: invalid client_id
            {
                "expected_status_code": 401,
                "expected_response": {
                    "error": "invalid_client",
                    "error_description": "client_id or client_secret is invalid",
                },
                "data": {
                    "client_id": "invalid-client-id",
                    "client_secret": "/replace_me",
                    "grant_type": "refresh_token",
                },
            },
            # condition 2: missing client_secret
            {
                "expected_status_code": 401,
                "expected_response": {
                    "error": "invalid_request",
                    "error_description": "client_secret is missing",
                },
                "data": {
                    "client_id": "/replace_me",
                    "grant_type": "refresh_token",
                },
            },
            # condition 4: invalid client_secret
            {
                "expected_status_code": 401,
                "expected_response": {
                    "error": "invalid_client",
                    "error_description": "client_id or client_secret is invalid",
                },
                "data": {
                    "client_id": "/replace_me",
                    "client_secret": "invalid",
                    "grant_type": "refresh_token",
                },
            },
            # condition 5: missing refresh_token
            {
                "expected_status_code": 400,
                "expected_response": {
                    "error": "invalid_request",
                    "error_description": "refresh_token is missing",
                },
                "data": {
                    "client_id": "/replace_me",
                    "client_secret": "/replace_me",
                    "grant_type": "refresh_token",
                },
            },
            # condition 6: invalid refresh_token
            {
                "expected_status_code": 401,
                "expected_response": {
                    "error": "invalid_grant",
                    "error_description": "refresh_token is invalid",
                },
                "data": {
                    "client_id": "/replace_me",
                    "client_secret": "/replace_me",
                    "grant_type": "refresh_token",
                    "refresh_token": "invalid",
                },
            },
        ],
    )
    async def test_refresh_token_error_conditions(self, test_case: dict, helper):
        self._update_secrets(test_case)
        assert await helper.send_request_and_check_output(
            expected_status_code=test_case["expected_status_code"],
            expected_response=test_case["expected_response"],
            function=self.oauth.get_token_response,
            grant_type="refresh_token",
            data=test_case["data"],
        )

    async def test_ping(self, helper):
        assert await helper.send_request_and_check_output(
            expected_status_code=200,
            function=self.oauth.hit_oauth_endpoint,
            expected_response=["version", "revision", "releaseId", "commitId"],
            method="GET",
            endpoint="_ping",
        )

    @pytest.mark.parametrize("test_case", [
        {
            # Condition 1 Happy path
            "expected_status_code": 200,
            "expected_response": ["status", "version", "revision", "releaseId", "commitId", "checks"],
            "headers":{"apikey": f"{STATUS_ENDPOINT_API_KEY}"}
        },
        {
            # Condition 2 invalid api key
            "expected_status_code": 401,
            "expected_response": {
                "error": "Access Denied",
                "error_description": "Invalid api key for _status monitoring endpoint"
            },
            "headers": {"apikey": "invalid"}
        },
        {
            # Condition 3 invalid api key header
            "expected_status_code": 401,
            "expected_response": {
                "error": "Access Denied",
                "error_description": "Invalid api key for _status monitoring endpoint"
            },
            "headers": {"invalid": "invalid"}
        }
    ])
    async def test_status(self, helper, test_case):
        assert await helper.send_request_and_check_output(
            expected_status_code=test_case["expected_status_code"],
            function=self.oauth.hit_oauth_endpoint,
            expected_response=test_case["expected_response"],
            method="GET",
            endpoint="_status",
            headers=test_case["headers"]
        )


    @pytest.mark.aea_756
    @pytest.mark.happy_path
    @pytest.mark.usefixtures("set_access_token")
    async def test_userinfo(self, helper):
        assert await helper.send_request_and_check_output(
            expected_status_code=200,
            expected_response=BANK.get(self.name)["response"],
            function=self.oauth.hit_oauth_endpoint,
            method="GET",
            endpoint="userinfo",
            headers={"Authorization": f"Bearer {self.oauth.access_token}"},
        )

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

    async def test_userinfo_nhs_login_exchanged_token(self, get_exchange_code_nhs_login_token):
        # Given
        expected_status_code = 400
        expected_error = 'invalid_request'
        expected_error_description = 'The Userinfo endpoint is only supported for Combined Auth integrations. Currently this is only for NHS CIS2 authentications - for more guidance see https://digital.nhs.uk/developer/guides-and-documentation/security-and-authorisation/user-restricted-restful-apis-nhs-cis2-combined-authentication-and-authorisation'

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

    async def test_userinfo_client_credentials_token(self):
        # Given
        expected_status_code = 400
        expected_error = 'invalid_request'
        expected_error_description = 'The Userinfo endpoint is only supported for Combined Auth integrations. Currently this is only for NHS CIS2 authentications - for more guidance see https://digital.nhs.uk/developer/guides-and-documentation/security-and-authorisation/user-restricted-restful-apis-nhs-cis2-combined-authentication-and-authorisation'

        # When
        jwt = self.oauth.create_jwt(kid="test-1")
        resp = await self.oauth.get_token_response("client_credentials", _jwt=jwt)
        
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
