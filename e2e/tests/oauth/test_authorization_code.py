import sys
import random
from time import sleep
import pytest
import requests
from e2e.scripts.config import (
    OAUTH_URL,
    CANARY_API_URL
)
from e2e.scripts.response_bank import BANK


@pytest.mark.asyncio
class TestAuthorizationCode:
    """ A test suit to test the token exchange flow """

############# OAUTH ENDPOINTS ###########     

    @pytest.mark.happy_path
    @pytest.mark.authorize_endpoint
    async def test_authorize_endpoint(
            self,
            nhsd_apim_proxy_url,
            _test_app_credentials,
            _test_app_callback_url
    ):
        params = {
            "client_id": _test_app_credentials["consumerKey"],
            "redirect_uri": _test_app_callback_url,
            "response_type": "code",
            "state": random.getrandbits(32)
        }

        resp = requests.get(
            nhsd_apim_proxy_url + "/authorize",
            params
        )

        assert resp.status_code == 200

    @pytest.mark.skip(
        reason="TO REFACTOR"
    )
    @pytest.mark.simulated_auth
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

    @pytest.mark.skip(
        reason="TO REFACTOR"
    )
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

    @pytest.mark.skip(
        reason="TO REFACTOR"
    )
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

    @pytest.mark.skip(
        reason="TO REFACTOR"
    )
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

    @pytest.mark.skip(
        reason="TO REFACTOR"
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

    @pytest.mark.skip(
        reason="TO REFACTOR"
    )
    async def test_authorize_unsubscribed_error_condition(
        self, test_product, test_application, helper
    ):
        await test_product.update_proxies(["canary-api-internal-dev"])
        await test_application.add_api_product([test_product.name])

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
                "client_id": test_application.client_id,
                "redirect_uri": test_application.callback_url,
                "response_type": "code",
                "state": random.getrandbits(32),
            },
        )

    @pytest.mark.skip(
        reason="TO REFACTOR"
    )
    @pytest.mark.simulated_auth
    @pytest.mark.errors
    @pytest.mark.token_endpoint
    async def test_token_unsubscribed_error_condition(
        self, test_product, test_application, helper
    ):
        await test_product.update_proxies(["canary-api-internal-dev"])
        await test_application.add_api_product([test_product.name])

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
                "client_id": test_application.client_id,
                "client_secret": test_application.client_secret,
                "redirect_uri": test_application.callback_url,
                "grant_type": "authorization_code",
                "code": await self.oauth.get_authenticated_with_simulated_auth(),
            },
        )

    @pytest.mark.skip(
        reason="TO REFACTOR"
    )
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

    @pytest.mark.skip(
        reason="TO REFACTOR"
    )
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

    @pytest.mark.skip(
        reason="TO REFACTOR"
    )
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

    @pytest.mark.skip(
        reason="TO REFACTOR"
    )
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

    @pytest.mark.skip(
        reason="TO REFACTOR"
    )
    @pytest.mark.simulated_auth
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

############## OAUTH TOKENS ###############

    @pytest.mark.skip(
        reason="TO REFACTOR"
    )
    @pytest.mark.simulated_auth
    @pytest.mark.happy_path
    @pytest.mark.usefixtures("set_access_token")
    def test_access_token(self, helper):
        assert helper.check_endpoint(
            verb="GET",
            endpoint=CANARY_API_URL,
            expected_status_code=200,
            expected_response="Hello user!",
            headers={
                "Authorization": f"Bearer {self.oauth.access_token}",
                "NHSD-Session-URID": "ROLD-ID",
            },
        )

    @pytest.mark.skip(
        reason="TO REFACTOR"
    )
    @pytest.mark.simulated_auth
    @pytest.mark.happy_path
    @pytest.mark.usefixtures("set_refresh_token")
    async def test_refresh_token(self):
        resp = await self.oauth.get_token_response(
            grant_type="refresh_token", refresh_token=self.oauth.refresh_token
        )

        assert resp["status_code"] == 200
        assert sorted(list(resp["body"].keys())) == [
            "access_token",
            "expires_in",
            "refresh_count",
            "refresh_token",
            "refresh_token_expires_in",
            "token_type",
        ]

    @pytest.mark.skip(
        reason="TO REFACTOR"
    )
    @pytest.mark.errors
    @pytest.mark.parametrize(
        ("token", "expected_response"),
        [
            # Condition 1: Using an invalid token
            ("ThisTokenIsInvalid", {
                "fault": {
                    "faultstring": "Invalid Access Token",
                    "detail": {
                        "errorcode": "keymanagement.service.invalid_access_token"
                    }
                }
            }),
            # Condition 2: Using an expired token
            ("QjMGgujVxVbCV98omVaOlY1zR8aB", {
                "fault": {
                    "faultstring": "Invalid Access Token",
                    "detail": {
                        "errorcode": "keymanagement.service.invalid_access_token"
                    }
                }
            }),
            # Condition 3: Empty token
            ("", {
                "fault": {
                    "faultstring": "Invalid access token",
                    "detail": {
                        "errorcode": "oauth.v2.InvalidAccessToken"
                    }
                }
            }),
        ],
    )
    @pytest.mark.errors
    async def test_invalid_access_token(self, token: str, helper, expected_response: dict):
        assert helper.check_endpoint(
            verb="POST",
            endpoint=CANARY_API_URL,
            expected_status_code=401,
            expected_response=expected_response,
            headers={"Authorization": f"Bearer {token}", "NHSD-Session-URID": ""},
        )

    @pytest.mark.skip(
        reason="TO REFACTOR"
    )
    def test_missing_access_token(self, helper):
        assert helper.check_endpoint(
            verb="POST",
            endpoint=CANARY_API_URL,
            expected_status_code=401,
            expected_response={"fault":
                {
                    "faultstring": "Invalid access token",
                    "detail": {
                        "errorcode": "oauth.v2.InvalidAccessToken"
                    }
                }
            },
            headers={"NHSD-Session-URID": ""},
        )

    @pytest.mark.skip(
        reason="TO REFACTOR"
    )
    @pytest.mark.simulated_auth
    @pytest.mark.errors
    @pytest.mark.usefixtures("set_access_token")
    def test_access_token_does_expire(self, helper):
        # Set token fixture is executed
        # wait until token has expired
        sleep(5)

        # Check token still works after access token has expired
        assert helper.check_endpoint(
            verb="GET",
            endpoint=CANARY_API_URL,
            expected_status_code=401,
            expected_response={
                "fault": {
                    "faultstring": "Access Token expired",
                    "detail": {
                        "errorcode": "keymanagement.service.access_token_expired"
                    },
                }
            },
            headers={
                "Authorization": f"Bearer {self.oauth.access_token}",
                "NHSD-Session-URID": "",
            },
        )

    @pytest.mark.skip(
        reason="TO REFACTOR"
    )
    @pytest.mark.simulated_auth
    @pytest.mark.errors
    async def test_access_token_with_params(self):
        resp = await self.oauth.hit_oauth_endpoint(
            method="POST",
            endpoint="token",
            params={
                "client_id": self.oauth.client_id,
                "client_secret": self.oauth.client_secret,
                "grant_type": "authorization_code",
                "redirect_uri": self.oauth.redirect_uri,
                "code": await self.oauth.get_authenticated_with_simulated_auth(),
                "_access_token_expiry_ms": 5000,
            },
        )

        assert resp["status_code"] == 415
        assert resp["body"] == {
            "error": "invalid_request",
            "error_description": "Content-Type header must be application/x-www-urlencoded",
        }

    @pytest.mark.skip(
        reason="TO REFACTOR"
    )
    @pytest.mark.simulated_auth
    @pytest.mark.errors
    @pytest.mark.usefixtures("set_refresh_token")
    async def test_refresh_token_does_expire(self):
        sleep(5)
        resp = await self.oauth.get_token_response(
            grant_type="refresh_token", refresh_token=self.oauth.refresh_token
        )

        assert resp["status_code"] == 401
        assert resp["body"] == {
            "error": "invalid_grant",
            "error_description": "refresh token refresh period has expired",
        }

    @pytest.mark.skip(
        reason="TO REFACTOR"
    )
    @pytest.mark.simulated_auth
    @pytest.mark.errors
    @pytest.mark.usefixtures("set_refresh_token")
    async def test_refresh_tokens_validity_expires(self):
        # Set refresh token validity to 0
        resp = await self.oauth.get_token_response(
            grant_type="refresh_token",
            refresh_token=self.oauth.refresh_token,
            data={
                "client_id": self.oauth.client_id,
                "client_secret": self.oauth.client_secret,
                "grant_type": "refresh_token",
                "refresh_token": self.oauth.refresh_token,
                "_refresh_tokens_validity_ms": 0,
            },
        )

        assert resp["status_code"] == 401
        assert resp["body"] == {
            "error": "invalid_grant",
            "error_description": "refresh token refresh period has expired",
        }

    @pytest.mark.skip(
        reason="TO REFACTOR"
    )
    @pytest.mark.simulated_auth
    @pytest.mark.errors
    @pytest.mark.usefixtures("set_refresh_token")
    async def test_re_use_of_refresh_token(self):
        resp = await self.oauth.get_token_response(
            grant_type="refresh_token", refresh_token=self.oauth.refresh_token
        )

        assert resp["status_code"] == 200
        assert sorted(list(resp["body"].keys())) == [
            "access_token",
            "expires_in",
            "refresh_count",
            "refresh_token",
            "refresh_token_expires_in",
            "token_type",
        ]

        # Sending another request with the same refresh token
        resp = await self.oauth.get_token_response(
            grant_type="refresh_token", refresh_token=self.oauth.refresh_token
        )

        assert resp["status_code"] == 401
        assert resp["body"] == {
            "error": "invalid_grant",
            "error_description": "refresh_token is invalid",
        }

    @pytest.mark.skip(
        reason="TO REFACTOR"
    )
    @pytest.mark.simulated_auth
    @pytest.mark.parametrize('scope', ['P9', 'P5', 'P0'])
    async def test_nhs_login_refresh_tokens_generated_with_expected_expiry_combined_auth(self, scope):
        """
        Test that refresh tokens generated via NHS Login have an expiry time of 1 hour for combined authentication.
        """

        form_data = {
            "client_id": self.oauth.client_id,
            "client_secret": self.oauth.client_secret,
            "grant_type": "authorization_code",
            "redirect_uri": self.oauth.redirect_uri,
            "_access_token_expiry_ms": 600000,
            "code": await self.oauth.get_authenticated_with_simulated_auth(auth_scope="nhs-login"),
        }
        params = {"scope": "nhs-login"}
        resp = await self.oauth.hit_oauth_endpoint("post", "token", data=form_data, params=params)

        access_token = resp['body']['access_token']
        refresh_token = resp['body']['refresh_token']

        assert access_token
        assert refresh_token
        assert resp['body']['expires_in'] == '599'
        assert resp['body']['refresh_token_expires_in'] == '3599'

    @pytest.mark.skip(
        reason="TO REFACTOR"
    )
    @pytest.mark.simulated_auth
    async def test_cis2_refresh_tokens_generated_with_expected_expiry_combined_auth(self):
        """
        Test that refresh tokens generated via CIS2 have an expiry time of 12 hours for combined authentication.
        """
        resp = await self.oauth.get_token_response(
            grant_type="authorization_code",
            timeout=600000,
        )

        access_token = resp['body']['access_token']
        refresh_token = resp['body']['refresh_token']

        assert access_token
        assert refresh_token
        assert resp['body']['expires_in'] == '599'
        assert resp['body']['refresh_token_expires_in'] == '43199'

    # TO DO
    @pytest.mark.skip(
        reason="It is not feasible to run this test each build due to the timeframe required, run manually if needed."
    )
    async def test_cis2_refresh_token_valid_after_1_hour(self):
        """
        Test that a refresh token received via a CIS2 login is valid after 1 hour (the previous expiry time).
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

        # Wait 1 hour (the previous refresh token expiry time) and check that the token is still valid
        for remaining in range(3600, 0, -1):
            mins, sec = divmod(remaining, 60)
            sys.stdout.write("\r")
            sys.stdout.write("{:2d} minutes {:2d} seconds remaining.".format(mins, sec))
            sleep(1)

        # Get new access token using refresh token
        resp2 = await self.oauth.get_token_response(grant_type="refresh_token", refresh_token=refresh_token)
        access_token2 = resp2['body']['access_token']
        assert access_token2