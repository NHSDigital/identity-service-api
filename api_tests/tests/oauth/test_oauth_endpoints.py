from api_tests.config_files import config
from api_tests.scripts.response_bank import BANK
from api_tests.config_files.environments import ENV
import pytest
import random
from api_test_utils.apigee_api_apps import ApigeeApiDeveloperApps
from api_test_utils.apigee_api_products import ApigeeApiProducts


@pytest.mark.usefixtures("setup")
class TestOauthEndpointSuite:
    """ A test suit to verify all the happy path oauth endpoints """

    @pytest.fixture()
    async def test_app_and_product(self):
        apigee_product = ApigeeApiProducts()
        apigee_product2 = ApigeeApiProducts()
        await apigee_product.create_new_product()
        await apigee_product2.create_new_product()

        apigee_app = ApigeeApiDeveloperApps()
        await apigee_app.create_new_app(
            callback_url=config.REDIRECT_URI
        )

        yield apigee_product, apigee_product2, apigee_app

        await apigee_app.destroy_app()
        await apigee_product.destroy_product()
        await apigee_product2.destroy_product()

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
                "state": random.getrandbits(32)
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

    @pytest.mark.apm_1475
    @pytest.mark.errors
    @pytest.mark.authorize_endpoint
    def test_authorize_endpoint_http_allowed_methods(self):
        response = self.oauth.check_and_return_endpoint(
            verb="POST", endpoint="authorize", expected_status_code=405, expected_response=""
        )
        assert response.headers["Allow"] == "GET"

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
                    "client_id": config.CLIENT_ID,
                    "redirect_uri": f"{config.REDIRECT_URI}/invalid",  # invalid redirect uri
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
                "params": {  # not providing redirect uri
                    "client_id": config.CLIENT_ID,
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
                    "redirect_uri": f"{config.REDIRECT_URI}/invalid",
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
                    "redirect_uri": config.REDIRECT_URI,
                    "response_type": "code",
                    "state": random.getrandbits(32),
                },
            },
            # condition 5: app not subscribed
            {
                "expected_status_code": 401,
                "expected_response": {
                    "error": "access_denied",
                    "error_description": "api key supplied does not have access to this resource."
                                         " please check the api key you are using belongs to an app"
                                         " which has sufficient access to access this resource.",
                },
                "params": {
                    "client_id": config.VALID_UNSUBSCRIBED_CLIENT_ID,
                    "redirect_uri": config.VALID_UNSUBSCRIBED_REDIRECT_URI,
                    "response_type": "code",
                    "state": random.getrandbits(32),
                },
            },
            # condition 6: app revoked
            {
                "expected_status_code": 401,
                "expected_response": {
                    "error": "access_denied",
                    "error_description": "the developer app associated with the api key is not approved or revoked",
                },
                "params": {
                    "client_id": config.VALID_UNAPPROVED_CLIENT_ID,
                    "redirect_uri": config.VALID_UNAPPROVED_CLIENT_REDIRECT_URI,
                    "response_type": "code",
                    "state": random.getrandbits(32),
                },
            },
        ],
    )
    def test_authorization_error_conditions(self, request_data: dict):
        assert self.oauth.check_endpoint("GET", "authorize", **request_data)

    @pytest.mark.apm_1475
    @pytest.mark.errors
    @pytest.mark.authorize_endpoint
    @pytest.mark.parametrize(
        "request_data",
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
                    "client_id": config.CLIENT_ID,
                    "redirect_uri": config.REDIRECT_URI,
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
                    "client_id": config.CLIENT_ID,
                    "redirect_uri": config.REDIRECT_URI,
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
                    "client_id": config.CLIENT_ID,
                    "redirect_uri": config.REDIRECT_URI,
                    "response_type": "invalid",  # invalid response type
                    "state": random.getrandbits(32),
                },
            },
        ],
    )
    def test_authorization_error_redirects(self, request_data: dict):
        response = self.oauth.check_and_return_endpoint(
            verb="GET",
            endpoint="authorize",
            expected_status_code=request_data["expected_status_code"],
            expected_response=request_data["expected_response"],
            params=request_data["params"],
            allow_redirects=False
        )
        self.oauth.check_redirect(
            response=response,
            expected_params=request_data["expected_params"],
            client_redirect=config.REDIRECT_URI,
            state=request_data["params"].get("state")
        )

    @pytest.mark.apm_1631
    @pytest.mark.errors
    @pytest.mark.token_endpoint
    @pytest.mark.parametrize(
        "request_data",
        [
            {
                "expected_status_code": 401,
                "expected_response": {
                    "error": "access_denied",
                    "error_description": "API Key supplied does not have access to this resource."
                                         " Please check the API Key you are using belongs to an app"
                                         " which has sufficient access to access this resource.",
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
                    "error_description": "grant_type is missing",
                },
                "params": {},
            },
            # condition 2: invalid grant type
            {
                "expected_status_code": 400,
                "expected_response": {
                    "error": "unsupported_grant_type",
                    "error_description": "grant_type is invalid",
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
                    "error_description": "grant_type is missing",
                },
                "headers": {"Content-Type": "application/x-www-form-urlencoded"},
                "params": {},
                "data": {
                    "client_id": config.CLIENT_ID,
                    "client_secret": config.CLIENT_SECRET,
                    "redirect_uri": config.REDIRECT_URI,
                },
            },
            # condition 4: missing client_id
            {
                "expected_status_code": 401,
                "expected_response": {
                    "error": "invalid_request",
                    "error_description": "client_id is missing",
                },
                "headers": {"Content-Type": "application/x-www-form-urlencoded"},
                "params": {},
                "data": {
                    "client_secret": config.CLIENT_SECRET,
                    "redirect_uri": config.REDIRECT_URI,
                    "grant_type": "authorization_code",
                },
            },
            # condition 5: invalid client_id
            {
                "expected_status_code": 401,
                "expected_response": {
                    "error": "invalid_client",
                    "error_description": "client_id or client_secret is invalid",
                },
                "headers": {"Content-Type": "application/x-www-form-urlencoded"},
                "params": {},
                "data": {
                    "client_id": "THISisANinvalidCLIENTid12345678",
                    "client_secret": config.CLIENT_SECRET,
                    "redirect_uri": config.REDIRECT_URI,
                    "grant_type": "authorization_code",
                },
            },
            # condition 7: invalid client secret
            {
                "expected_status_code": 401,
                "expected_response": {
                    "error": "invalid_client",
                    "error_description": "client_id or client_secret is invalid",
                },
                "headers": {"Content-Type": "application/x-www-form-urlencoded"},
                "params": {},
                "data": {
                    "client_id": config.CLIENT_ID,
                    "client_secret": "ThisSecretIsInvalid",
                    "redirect_uri": config.REDIRECT_URI,
                    "grant_type": "authorization_code",
                },
            },
            # condition 8: missing client secret
            {
                "expected_status_code": 401,
                "expected_response": {
                    "error": "invalid_request",
                    "error_description": "client_secret is missing",
                },
                "headers": {"Content-Type": "application/x-www-form-urlencoded"},
                "params": {},
                "data": {
                    "client_id": config.CLIENT_ID,
                    "redirect_uri": config.REDIRECT_URI,
                    "grant_type": "authorization_code",
                },
            },
            # condition 9: redirect_uri is missing
            {
                "expected_status_code": 400,
                "expected_response": {
                    "error": "invalid_request",
                    "error_description": "redirect_uri is missing",
                },
                "headers": {"Content-Type": "application/x-www-form-urlencoded"},
                "params": {},
                "data": {
                    "client_id": config.CLIENT_ID,
                    "client_secret": config.CLIENT_SECRET,
                    "grant_type": "authorization_code",
                },
            },
            # condition 9: redirect_uri is invalid
            {
                "expected_status_code": 400,
                "expected_response": {
                    "error": "invalid_request",
                    "error_description": "redirect_uri is invalid",
                },
                "headers": {"Content-Type": "application/x-www-form-urlencoded"},
                "params": {},
                "data": {
                    "client_id": config.CLIENT_ID,
                    "client_secret": config.CLIENT_SECRET,
                    "redirect_uri": 'invalid',
                    "grant_type": "authorization_code",
                },
            },
            # condition 10: authorization code is missing
            {
                "expected_status_code": 400,
                "expected_response": {
                    "error": "invalid_request",
                    "error_description": "authorization_code is missing",
                },
                "headers": {"Content-Type": "application/x-www-form-urlencoded"},
                "params": {},
                "data": {
                    "client_id": config.CLIENT_ID,
                    "client_secret": config.CLIENT_SECRET,
                    "redirect_uri": config.REDIRECT_URI,
                    "grant_type": "authorization_code",
                },
            },
            # condition 11: authorization code is invalid
            {
                "expected_status_code": 400,
                "expected_response": {
                    "error": "invalid_grant",
                    "error_description": "authorization_code is invalid",
                },
                "headers": {"Content-Type": "application/x-www-form-urlencoded"},
                "params": {},
                "data": {
                    "client_id": config.CLIENT_ID,
                    "client_secret": config.CLIENT_SECRET,
                    "redirect_uri": config.REDIRECT_URI,
                    "grant_type": "authorization_code",
                    "code": "invalid",
                },
            },
        ],
    )
    def test_token_error_conditions(self, request_data: dict):
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

    @pytest.mark.apm_1475
    @pytest.mark.errors
    @pytest.mark.token_endpoint
    @pytest.mark.parametrize(
        "request_data",
        [
            # condition 1: missing client id
            {
                "expected_status_code": 401,
                "expected_response": {
                    "error": "invalid_request",
                    "error_description": "client_id is missing",
                },
                "data": {
                    'client_secret': config.CLIENT_SECRET,
                    'grant_type': 'refresh_token',
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
                    'client_secret': config.CLIENT_SECRET,
                    'grant_type': 'refresh_token',
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
                    "client_id": config.CLIENT_ID,
                    'grant_type': 'refresh_token',
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
                    "client_id": config.CLIENT_ID,
                    'client_secret': 'invalid',
                    'grant_type': 'refresh_token',
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
                    "client_id": config.CLIENT_ID,
                    'client_secret': config.CLIENT_SECRET,
                    'grant_type': 'refresh_token',
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
                    "client_id": config.CLIENT_ID,
                    'client_secret': config.CLIENT_SECRET,
                    'grant_type': 'refresh_token',
                    'refresh_token': 'invalid'
                },
            },
        ],
    )
    def test_refresh_token_error_conditions(self, request_data: dict):
        assert self.oauth.check_endpoint("POST", "token", **request_data)

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

    @pytest.mark.apm_1701
    @pytest.mark.happy_path
    @pytest.mark.token_endpoint
    @pytest.mark.asyncio
    async def test_user_restricted_scopes_single_product(self, test_app_and_product):

        test_product, test_product2, test_app = test_app_and_product

        await test_product.update_scopes(
            ['urn:nhsd:apim:user:aal3:personal-demographics-service']
        )
        await test_product.update_proxies([config.SERVICE_NAME])

        callback_url = await test_app.get_callback_url()

        await test_app.add_api_product(
            api_products=[
                test_product.name, test_product2.name
            ]
        )

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
                "client_id": test_app.get_client_id(),
                "client_secret": test_app.get_client_secret(),
                "redirect_uri": callback_url,
                "grant_type": "authorization_code",
                "code": self.oauth.get_authenticated(
                    client_id=test_app.get_client_id(),
                    redirect_uri=callback_url
                ),
            },
        )

    @pytest.mark.apm_1701
    @pytest.mark.errors
    @pytest.mark.token_endpoint
    @pytest.mark.asyncio
    async def test_user_restricted_wrong_scope_single_product(self, test_app_and_product):

        test_product, test_product2, test_app = test_app_and_product

        await test_product.update_scopes(
            ['urn:nhsd:apim:user:aal2:personal-demographics-service']
        )
        await test_product.update_proxies([config.SERVICE_NAME])

        callback_url = await test_app.get_callback_url()

        await test_app.add_api_product(
            api_products=[
                test_product.name, test_product2.name
            ]
        )

        assert self.oauth.check_endpoint(
            verb="GET",
            endpoint="authorize",
            expected_status_code=401,
            expected_response={
                "error": "unauthorized_client",
                "error_description": "the authenticated client is not authorized to use this authorization grant type"
            },
            params={
                "client_id": test_app.get_client_id(),
                "redirect_uri": callback_url,
                "response_type": "code",
                "state": random.getrandbits(32)
            },
        )

    @pytest.mark.apm_1701
    @pytest.mark.happy_path
    @pytest.mark.token_endpoint
    @pytest.mark.asyncio
    async def test_user_restricted_scopes_multiple_types_products(self, test_app_and_product):

        test_product, test_product2, test_app = test_app_and_product

        await test_product.update_scopes(
            ['urn:nhsd:apim:user:aal3:personal-demographics-service']
        )
        await test_product.update_proxies([config.SERVICE_NAME])

        await test_product2.update_scopes(
            ['urn:nhsd:apim:app:jwks:ambulance-analytics']
        )
        await test_product2.update_proxies([config.SERVICE_NAME])

        callback_url = await test_app.get_callback_url()

        await test_app.add_api_product(
            api_products=[
                test_product.name, test_product2.name
            ]
        )

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
                "client_id": test_app.get_client_id(),
                "client_secret": test_app.get_client_secret(),
                "redirect_uri": callback_url,
                "grant_type": "authorization_code",
                "code": self.oauth.get_authenticated(
                    client_id=test_app.get_client_id(),
                    redirect_uri=callback_url
                ),
            },
        )

    @pytest.mark.apm_1701
    @pytest.mark.errors
    @pytest.mark.token_endpoint
    @pytest.mark.asyncio
    async def test_user_restricted_scopes_multiple_wrong_products(self, test_app_and_product):

        test_product, test_product2, test_app = test_app_and_product

        await test_product.update_scopes(
            ['urn:nhsd:apim:app:jwks:personal-demographics-service']
        )
        await test_product.update_proxies([config.SERVICE_NAME])

        await test_product2.update_scopes(
            ['urn:nhsd:apim:app:jwks:ambulance-analytics']
        )
        await test_product2.update_proxies([config.SERVICE_NAME])

        callback_url = await test_app.get_callback_url()

        await test_app.add_api_product(
            api_products=[
                test_product.name, test_product2.name
            ]
        )

        assert self.oauth.check_endpoint(
            verb="GET",
            endpoint="authorize",
            expected_status_code=401,
            expected_response={
                "error": "unauthorized_client",
                "error_description": "the authenticated client is not authorized to use this authorization grant type"
            },
            params={
                "client_id": test_app.get_client_id(),
                "redirect_uri": callback_url,
                "response_type": "code",
                "state": random.getrandbits(32)
            },
        )

    @pytest.mark.apm_1701
    @pytest.mark.happy_path
    @pytest.mark.token_endpoint
    @pytest.mark.asyncio
    async def test_user_restricted_scopes_multiple_right_products(self, test_app_and_product):

        test_product, test_product2, test_app = test_app_and_product

        await test_product.update_scopes(
            ['urn:nhsd:apim:user:aal3:personal-demographics-service']
        )
        await test_product.update_proxies([config.SERVICE_NAME])

        await test_product2.update_scopes(
            ['urn:nhsd:apim:user:aal3:ambulance-analytics']
        )
        await test_product2.update_proxies([config.SERVICE_NAME])

        callback_url = await test_app.get_callback_url()

        await test_app.add_api_product(
            api_products=[
                test_product.name, test_product2.name
            ]
        )

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
                "client_id": test_app.get_client_id(),
                "client_secret": test_app.get_client_secret(),
                "redirect_uri": callback_url,
                "grant_type": "authorization_code",
                "code": self.oauth.get_authenticated(
                    client_id=test_app.get_client_id(),
                    redirect_uri=callback_url
                ),
            },
        )

    @pytest.mark.apm_1701
    @pytest.mark.errors
    @pytest.mark.token_endpoint
    @pytest.mark.asyncio
    async def test_user_restricted_no_scope_in_product(self, test_app_and_product):

        test_product, test_product2, test_app = test_app_and_product

        await test_product.update_proxies([config.SERVICE_NAME])

        callback_url = await test_app.get_callback_url()

        await test_app.add_api_product(
            api_products=[
                test_product.name, test_product2.name
            ]
        )

        assert self.oauth.check_endpoint(
            verb="GET",
            endpoint="authorize",
            expected_status_code=401,
            expected_response={
                "error": "unauthorized_client",
                "error_description": "the authenticated client is not authorized to use this authorization grant type"
            },
            params={
                "client_id": test_app.get_client_id(),
                "redirect_uri": callback_url,
                "response_type": "code",
                "state": random.getrandbits(32)
            },
        )
