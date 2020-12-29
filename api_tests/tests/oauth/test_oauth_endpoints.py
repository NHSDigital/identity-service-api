from api_tests.config_files import config
from api_tests.scripts.response_bank import BANK
from api_tests.config_files.environments import ENV
import pytest
import random


@pytest.mark.usefixtures("setup")
class TestOauthEndpointSuite:
    """ A test suit to verify all the happy path oauth endpoints """

    @staticmethod
    def switch_to_valid_asid_application():
        config.CLIENT_ID = ENV["oauth"]["valid_asic_client_id"]
        config.CLIENT_SECRET = ENV["oauth"]["valid_asid_client_secret"]
        config.REDIRECT_URI = "https://example.com/callback"

    @staticmethod
    def switch_to_application():
        config.CLIENT_ID = ENV["oauth"]["client_id"]
        config.CLIENT_SECRET = ENV["oauth"]["client_secret"]
        config.REDIRECT_URI = ENV["oauth"]["redirect_uri"]

    @pytest.mark.apm_801
    @pytest.mark.happy_path
    @pytest.mark.authorize_endpoint
    def test_authorize_endpoint(self):
        # Test authorize endpoint is redirected and returns a 200
        self.oauth.check_endpoint(
            verb="GET",
            endpoint="authorize",
            expected_status_code=200,
            expected_response=BANK.get(self.name)["response"],
            params={
                "client_id": config.CLIENT_ID,
                "redirect_uri": config.REDIRECT_URI,
                "response_type": "code",
            },
        )

    @pytest.mark.apm_801
    @pytest.mark.happy_path
    @pytest.mark.token_endpoint
    def test_token_endpoint(self):
        assert self.oauth.check_endpoint(
            verb="POST",
            endpoint="token",
            expected_status_code=200,
            expected_response=[
                "access_token",
                "expires_in",
                "refresh_count",
                "refresh_token",
                "refresh_token_expires_in",
                "token_type",
            ],
            data={
                "client_id": config.CLIENT_ID,
                "client_secret": config.CLIENT_SECRET,
                "redirect_uri": config.REDIRECT_URI,
                "grant_type": "authorization_code",
                "code": self.oauth.get_authenticated(),
            },
        )

    @pytest.mark.apm_1618
    @pytest.mark.errors
    @pytest.mark.token_endpoint
    def test_token_endpoint_http_allowed_methods(self):
        response = self.oauth.check_and_return_endpoint(
            verb="GET", endpoint="token", expected_status_code=405, expected_response=""
        )
        assert response.headers["Allow"] == "POST"

    @pytest.mark.apm_993
    @pytest.mark.errors
    @pytest.mark.authorize_endpoint
    def test_cache_invalidation(self):
        """
        Test identity cache invalidation after use:
            * Given i am authorizing
            * When the first request has succeeded
            * When using the same state as the first request
            * Then it should return xxx
        """

        # Make authorize request to retrieve state2
        response = self.oauth.check_and_return_endpoint(
            verb="GET",
            endpoint="authorize",
            expected_status_code=302,
            expected_response="",
            params={
                "client_id": config.CLIENT_ID,
                "redirect_uri": config.REDIRECT_URI,
                "response_type": "code",
                "state": "1234567890",
            },
            allow_redirects=False,
        )
        state2 = self.oauth.get_param_from_url(
            url=response.headers["Location"], param="state"
        )

        # Make simulated auth request to authenticate
        response = self.oauth.check_and_return_endpoint(
            verb="POST",
            endpoint="sim_auth",
            expected_status_code=302,
            expected_response="",
            params={
                "response_type": "code",
                "client_id": config.CLIENT_ID,
                "redirect_uri": config.REDIRECT_URI,
                "scope": "openid",
                "state": state2,
            },
            headers={"Content-Type": "application/x-www-form-urlencoded"},
            data={"state": state2},
            allow_redirects=False,
        )

        # Make initial callback request
        auth_code = self.oauth.get_param_from_url(
            url=response.headers["Location"], param="code"
        )
        response = self.oauth.check_and_return_endpoint(
            verb="GET",
            endpoint="callback",
            expected_status_code=302,
            expected_response="",
            params={"code": auth_code, "client_id": "some-client-id", "state": state2},
            allow_redirects=False,
        )

        # Verify auth code and state are returned
        response_params = self.oauth.get_params_from_url(response.headers["Location"])
        assert response_params["code"]
        assert response_params["state"]

        # Make second callback request with same state value
        assert self.oauth.check_endpoint(
            verb="GET",
            endpoint="callback",
            expected_status_code=400,
            expected_response={
                "error": "invalid_request",
                "error_description": "invalid state parameter.",
            },
            params={"code": auth_code, "client_id": "some-client-id", "state": state2},
        )

    @pytest.mark.apm_801
    @pytest.mark.apm_990
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
                    "error_description": f"invalid redirection uri {config.REDIRECT_URI}/invalid",
                },
                "params": {
                    "client_id": config.CLIENT_ID,
                    "redirect_uri": f"{config.REDIRECT_URI}/invalid",  # invalid redirect uri
                    "response_type": "code",
                    "state": random.getrandbits(32),
                },
            },
            # condition 2: missing redirect uri
            # condition 3: invalid client id
            # condition 4: missing client id
            # condition 5: invalid response type
            {
                "expected_status_code": 400,
                "expected_response": {
                    "error": "unsupported_response_type",
                    "error_description": "invalid response type: invalid",
                },
                "params": {
                    "client_id": config.CLIENT_ID,
                    "redirect_uri": config.REDIRECT_URI,
                    "response_type": "invalid",  # invalid response type
                    "state": random.getrandbits(32),
                },
            },
            # condition 6: missing response type
        ],
    )
    def test_authorization_error_conditions(self, request_data: dict):
        assert self.oauth.check_endpoint("GET", "authorize", **request_data)

    @pytest.mark.apm_1631
    @pytest.mark.errors
    @pytest.mark.token_endpoint
    @pytest.mark.parametrize(
        "request_data",
        [
            {
                "expected_status_code": 401,
                "expected_response": {
                    "error": "invalid_request",
                    "error_description": "API Key supplied does not have access to this resource. Please check the API Key you are using belongs to an app which has sufficient access to access this resource.",
                },
                "params": {
                    "client_id": config.VALID_UNSUBSCRIBED_CLIENT_ID,
                    "client_secret": config.VALID_UNSUBSCRIBED_CLIENT_SECRET,
                    "redirect_uri": config.VALID_UNSUBSCRIBED_REDIRECT_URI,
                    "grant_type": "authorization_code",
                },
            },
        ],
    )
    def test_token_unsubscribed_error_conditions(self, request_data: dict):
        request_data["params"]["code"] = self.oauth.get_authenticated()
        response = self.oauth.get_custom_token_response(request_data["params"])

        assert response.status_code == request_data["expected_status_code"]

        response_data = response.json()
        assert response_data["error"] == request_data["expected_response"]["error"]
        assert response_data["error_description"] == request_data["expected_response"]["error_description"]

    @pytest.mark.apm_801
    @pytest.mark.errors
    @pytest.mark.token_endpoint
    @pytest.mark.parametrize(
        "request_data",
        [
            # condition 1: invalid grant type
            {
                "expected_status_code": 400,
                "expected_response": {
                    "error": "invalid_request",
                    "error_description": "invalid grant_type",
                },
                "params": {
                    "client_id": config.CLIENT_ID,
                    "client_secret": config.CLIENT_SECRET,
                    "redirect_uri": config.REDIRECT_URI,
                    "grant_type": "invalid",
                },
            },
            # condition 2: missing grant_type
            {
                "expected_status_code": 400,
                "expected_response": {
                    "error": "invalid_request",
                    "error_description": "The request is missing a required parameter: grant_type",
                },
                "params": {
                    "client_id": config.CLIENT_ID,
                    "client_secret": config.CLIENT_SECRET,
                    "redirect_uri": config.REDIRECT_URI,
                },
            },
            # condition 3: invalid client id
            {
                "expected_status_code": 400,
                "expected_response": {
                    "error": "invalid_request",
                    "error_description": "invalid client_id",
                },
                "params": {
                    "client_id": "THISisANinvalidCLIENTid12345678",
                    "client_secret": config.CLIENT_SECRET,
                    "redirect_uri": config.REDIRECT_URI,
                    "grant_type": "authorization_code",
                },
            },
            # condition 4: missing client_id
            {
                "expected_status_code": 400,
                "expected_response": {
                    "error": "invalid_request",
                    "error_description": "The request is missing a required parameter : client_id",
                },
                "params": {
                    "client_secret": config.CLIENT_SECRET,
                    "redirect_uri": config.REDIRECT_URI,
                    "grant_type": "authorization_code",
                },
            },
            # condition 5: invalid redirect uri
            {
                "expected_status_code": 400,
                "expected_response": {
                    "error": "invalid_request",
                    "error_description": "invalid redirect_uri",
                },
                "params": {
                    "client_id": config.CLIENT_ID,
                    "client_secret": config.CLIENT_SECRET,
                    "redirect_uri": f"{config.REDIRECT_URI}/invalid",
                    "grant_type": "authorization_code",
                },
            },
            # condition 6: missing redirect_uri
            {
                "expected_status_code": 400,
                "expected_response": {
                    "error": "invalid_request",
                    "error_description": "The request is missing a required parameter : redirect_uri",
                },
                "params": {
                    "client_id": config.CLIENT_ID,
                    "client_secret": config.CLIENT_SECRET,
                    "grant_type": "authorization_code",
                },
            },
            # condition 7: invalid client secret
            {
                "expected_status_code": 400,
                "expected_response": {
                    "error": "invalid_request",
                    "error_description": "invalid secret_id",
                },
                "params": {
                    "client_id": config.CLIENT_ID,
                    "client_secret": "ThisSecretIsInvalid",
                    "redirect_uri": config.REDIRECT_URI,
                    "grant_type": "authorization_code",
                },
            },
            # condition 8: missing client secret
            {
                "expected_status_code": 400,
                "expected_response": {
                    "error": "invalid_request",
                    "error_description": "The request is missing a required parameter : secret_id",
                },
                "params": {
                    "client_id": config.CLIENT_ID,
                    "redirect_uri": config.REDIRECT_URI,
                    "grant_type": "authorization_code",
                },
            },
        ],
    )
    @pytest.mark.skip(reason="Not implemented")
    def test_token_error_conditions(self, request_data: dict):
        request_data["params"]["code"] = self.oauth.get_authenticated()
        assert self.oauth.check_endpoint("POST", "token", **request_data)

    @pytest.mark.apm_1618
    @pytest.mark.errors
    @pytest.mark.token_endpoint
    @pytest.mark.parametrize(
        "request_data",
        [
            # condition 1: no params provided
            {
                "expected_status_code": 400,
                "expected_response": {
                    "error": "invalid_request",
                    "error_description": "the request is missing a required parameter: 'grant_type'",
                },
                "params": {},
            },
            # condition 2: invalid grant type
            {
                "expected_status_code": 400,
                "expected_response": {
                    "error": "invalid_request",
                    "error_description": "unsupported grant_type: 'invalid'",
                },
                "headers": {"Content-Type": "application/x-www-form-urlencoded"},
                "params": {},
                "data": {
                    "client_id": config.CLIENT_ID,
                    "client_secret": config.CLIENT_SECRET,
                    "redirect_uri": config.REDIRECT_URI,
                    "grant_type": "invalid",
                },
            },
            # condition 3: missing grant_type
            {
                "expected_status_code": 400,
                "expected_response": {
                    "error": "invalid_request",
                    "error_description": "the request is missing a required parameter: 'grant_type'",
                },
                "headers": {"Content-Type": "application/x-www-form-urlencoded"},
                "params": {},
                "data": {
                    "client_id": config.CLIENT_ID,
                    "client_secret": config.CLIENT_SECRET,
                    "redirect_uri": config.REDIRECT_URI,
                },
            },
        ],
    )
    # Temporary enable error scenarios that have been implemented
    def test_token_error_conditions_implemented(self, request_data: dict):
        request_data["params"]["code"] = self.oauth.get_authenticated()
        assert self.oauth.check_endpoint("POST", "token", **request_data)

    @pytest.mark.errors
    @pytest.mark.parametrize(
        "request_data",
        [
            # condition 1: invalid code
            {
                "expected_status_code": 400,
                "expected_response": {
                    "error": "invalid_request",
                    "error_description": "invalid code",
                },
                "params": {
                    "client_id": config.CLIENT_ID,
                    "client_secret": config.CLIENT_SECRET,
                    "redirect_uri": config.REDIRECT_URI,
                    "grant_type": "authorization_code",
                    "code": "ThisIsAnInvalidCode",
                },
            },
            # condition 2: missing code
            {
                "expected_status_code": 400,
                "expected_response": {
                    "error": "invalid_request",
                    "error_description": "The request is missing a required parameter : code",
                },
                "params": {
                    "client_id": config.CLIENT_ID,
                    "client_secret": config.CLIENT_SECRET,
                    "redirect_uri": config.REDIRECT_URI,
                    "grant_type": "authorization_code",
                },
            },
        ],
    )
    @pytest.mark.skip(reason="Not implemented")
    def test_token_endpoint_with_invalid_authorization_code(self, request_data: dict):
        assert self.oauth.check_endpoint("POST", "token", **request_data)

    @pytest.mark.apm_1064
    @pytest.mark.errors
    @pytest.mark.callback_endpoint
    @pytest.mark.parametrize(
        "request_data",
        [
            # condition 1: invalid client id
            {
                "expected_status_code": 401,
                "expected_response": "",
                "params": {
                    "code": "some-code",
                    "client_id": "invalid-client-id",
                    "state": random.getrandbits(32),
                },
            },
        ],
    )
    def test_callback_error_conditions(self, request_data: dict):
        assert self.oauth.check_endpoint("GET", "callback", **request_data)

    def test_ping(self):
        assert self.oauth.check_endpoint('GET', 'ping', 200, ["version", "revision", "releaseId", "commitId"])

    @pytest.mark.aea_756
    @pytest.mark.happy_path
    @pytest.mark.usefixtures('get_token')
    def test_userinfo(self):
        assert self.oauth.check_endpoint(
            verb='GET',
            endpoint='userinfo',
            expected_status_code=200,
            expected_response=BANK.get(self.name)["response"],
            headers={
                'Authorization': f'Bearer {self.token}'
            }
        )
