from cgi import test
import sys
import random
from time import sleep
import pytest
import requests
from lxml import html
from urllib import parse
from urllib.parse import urlparse, parse_qs
from e2e.scripts.config import (
    OAUTH_URL,
    CANARY_API_URL,
    CANARY_PRODUCT_NAME
)
from e2e.scripts.response_bank import BANK


def get_params_from_url(url: str) -> dict:
    """Returns all the params and param values from a given url as a dictionary"""
    return dict(parse.parse_qsl(parse.urlsplit(url).query))


def remove_keys(data: dict, keys_to_remove: dict) -> dict:
    """Returns all the params with specified keys removed"""
    for key in keys_to_remove:
        data.pop(key)
    return data


def replace_keys(data: dict, keys_to_replace: dict) -> dict:
    return {**data, **keys_to_replace}


def get_auth_code(url, authorize_params, username):
    # Log in to Keycloak and get code
    session = requests.Session()
    resp = session.get(
        url=url,
        params=authorize_params,
        verify=False
    )

    assert resp.status_code == 200

    tree = html.fromstring(resp.content.decode())

    form = tree.get_element_by_id("kc-form-login")
    url = form.action
    resp2 = session.post(url, data={"username": username})

    qs = urlparse(resp2.history[-1].headers["Location"]).query
    auth_code = parse_qs(qs)["code"]
    if isinstance(auth_code, list):
        auth_code = auth_code[0]

    return auth_code


def subscribe_app_to_product(
    _apigee_edge_session, _apigee_app_base_url, credential, app_name, product_name
):
    key = credential["consumerKey"]
    attributes = credential["attributes"]
    api_products = [product_name]
    url = f"{_apigee_app_base_url}/{app_name}/keys/{key}"

    for product in credential["apiProducts"]:
        api_products.append(product["apiproduct"])

    product_data = {
        "apiProducts": api_products,
        "attributes": attributes
    }

    return _apigee_edge_session.post(url, json=product_data)


def unsubscribe_product(
    _apigee_edge_session, _apigee_app_base_url, credential, app_name, product_name
):
    key = credential["consumerKey"]
    url = f"{_apigee_app_base_url}/{app_name}/keys/{key}/apiproducts/{product_name}"

    return _apigee_edge_session.delete(url)


@pytest.fixture()
def authorize_params(_test_app_credentials, _test_app_callback_url):
    return {
        "client_id": _test_app_credentials["consumerKey"],
        "redirect_uri": _test_app_callback_url,
        "response_type": "code",
        "state": random.getrandbits(32)
    }


@pytest.fixture()
def token_data(_test_app_credentials, _test_app_callback_url):
    return {
        "client_id": _test_app_credentials["consumerKey"],
        "client_secret": _test_app_credentials["consumerSecret"],
        "redirect_uri": _test_app_callback_url,
        "grant_type": "authorization_code",
        "code": None  # Should be updated in the test
    }


@pytest.fixture()
def refresh_token_data(_test_app_credentials, _nhsd_apim_auth_token_data):
    return {
        "client_id": _test_app_credentials["consumerKey"],
        "client_secret": _test_app_credentials["consumerSecret"],
        "grant_type": "refresh_token",
        "refresh_token": None  # Should be updated in the test
    }


@pytest.mark.asyncio
class TestAuthorizationCode:
    """ A test suit to test the token exchange flow """

############# OAUTH ENDPOINTS ###########

    @pytest.mark.happy_path
    @pytest.mark.token_endpoint
    @pytest.mark.nhsd_apim_authorization(
        access="healthcare_worker",
        level="aal3",
        login_form={"username": "656005750104"},
        force_new_token=True
    )
    def test_token_endpoint(self, _nhsd_apim_auth_token_data):
        assert _nhsd_apim_auth_token_data["expires_in"] == "599"
        assert _nhsd_apim_auth_token_data["token_type"] == "Bearer"
        assert _nhsd_apim_auth_token_data["refresh_count"] == "0"
        assert set(_nhsd_apim_auth_token_data.keys()) == {
            "access_token",
            "expires_in",
            "refresh_count",
            "refresh_token",
            "refresh_token_expires_in",
            "sid",
            "token_type",
            "issued_at"  # Added by pytest_nhsd_apim
        }

    @pytest.mark.mock_auth
    @pytest.mark.errors
    @pytest.mark.token_endpoint
    @pytest.mark.parametrize(
        "expected_response,expected_status_code,missing_or_invalid,update_data",
        [
            (  # Test invalid grant_type
                {
                    "error": "unsupported_grant_type",
                    "error_description": "grant_type is invalid"
                },
                400,
                "invalid",
                {"grant_type": "invalid"},
            ),
            (  # Test missing grant_type
                {
                    "error": "invalid_request",
                    "error_description": "grant_type is missing"
                },
                400,
                "missing",
                {"grant_type"},
            ),
            (  # Test missing client_id
                {
                    "error": "invalid_request",
                    "error_description": "client_id is missing"
                },
                401,
                "missing",
                {"client_id"},
            ),
            (  # Test invalid client_id
                {
                    "error": "invalid_client",
                    "error_description": "client_id or client_secret is invalid"
                },
                401,
                "invalid",
                {"client_id": "invalid"},
            ),
            (  # Test invalid client_secret
                {
                    "error": "invalid_client",
                    "error_description": "client_id or client_secret is invalid"
                },
                401,
                "invalid",
                {"client_secret": "invalid"},
            ),
            (  # Test missing client_secret
                {
                    "error": "invalid_request",
                    "error_description": "client_secret is missing"
                },
                401,
                "missing",
                {"client_secret"},
            ),
            (  # Test invalid redirect_uri
                {
                    "error": "invalid_request",
                    "error_description": "redirect_uri is invalid"
                },
                400,
                "invalid",
                {"redirect_uri": "invalid"},
            ),
            (  # Test missing redirect_uri
                {
                    "error": "invalid_request",
                    "error_description": "redirect_uri is missing"
                },
                400,
                "missing",
                {"redirect_uri"},
            ),
            (  # Test invalid authorization_code
                {
                    "error": "invalid_grant",
                    "error_description": "authorization_code is invalid"
                },
                400,
                "invalid",
                {"code": "invalid"},
            ),
            (  # Test missing authorization_code
                {
                    "error": "invalid_request",
                    "error_description": "authorization_code is missing"
                },
                400,
                "missing",
                {"code"},
            )
        ]
    )
    def test_token_error_conditions(
        self,
        nhsd_apim_proxy_url,
        authorize_params,
        token_data,
        expected_response,
        expected_status_code,
        missing_or_invalid,
        update_data
    ):
        token_data["code"] = get_auth_code(
            url=nhsd_apim_proxy_url + "/authorize",
            authorize_params=authorize_params,
            username="656005750104"
        )

        if missing_or_invalid == "missing":
            token_data = remove_keys(token_data, update_data)
        if missing_or_invalid == "invalid":
            token_data = replace_keys(token_data, update_data)

        # Post to token endpoint
        resp = requests.post(
            nhsd_apim_proxy_url + "/token",
            headers={"Content-Type": "application/x-www-form-urlencoded"},
            data=token_data
        )

        body = resp.json()
        assert resp.status_code == expected_status_code
        assert (
            "message_id" in body.keys()
        )  # We assert the key but not he value for message_id
        del body["message_id"]
        assert body == expected_response

    @pytest.mark.happy_path
    @pytest.mark.authorize_endpoint
    def test_authorize_endpoint(
            self,
            nhsd_apim_proxy_url,
            authorize_params
    ):
        resp = requests.get(
            nhsd_apim_proxy_url + "/authorize",
            authorize_params
        )

        assert resp.status_code == 200

    @pytest.mark.errors
    @pytest.mark.token_endpoint
    @pytest.mark.authorize_endpoint
    @pytest.mark.parametrize(
        "method, allowed_method, endpoint",
        [
            ("GET", "POST", "/token"),
            ("POST", "GET", "/authorize"),
        ],
    )
    def test_token_endpoint_http_allowed_methods(
        self,
        method,
        allowed_method,
        endpoint,
        nhsd_apim_proxy_url
    ):
        resp = requests.request(
            method,
            url=nhsd_apim_proxy_url + endpoint,
        )

        assert resp.status_code == 405
        assert resp.headers["Allow"] == allowed_method

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

    @pytest.mark.errors
    @pytest.mark.authorize_endpoint
    @pytest.mark.parametrize(
        "expected_response,expected_status_code,missing_or_invalid,update_params",
        [
            (  # Test invalid redirect_uri
                {
                    "error": "invalid_request",
                    "error_description": "redirect_uri is invalid",
                },
                400,
                "invalid",
                {"redirect_uri": "/invalid"},
            ),
            (  # Test invalid client_id
                {
                    "error": "invalid_request",
                    "error_description": "client_id is invalid",
                },
                401,
                "invalid",
                {"client_id": "invalid"},
            ),
            (  # Test missing redirect_uri
                {
                    "error": "invalid_request",
                    "error_description": "redirect_uri is missing",
                },
                400,
                "missing",
                {"redirect_uri"},
            ),
            (  # Test missing client_id
                {
                    "error": "invalid_request",
                    "error_description": "client_id is missing",
                },
                401,
                "missing",
                {"client_id"},
            ),
        ]
    )
    def test_authorization_param_errors(
        self,
        expected_response,
        expected_status_code,
        missing_or_invalid,
        update_params,
        nhsd_apim_proxy_url,
        authorize_params,
    ):
        if missing_or_invalid == "missing":
            params = remove_keys(authorize_params, update_params)
        if missing_or_invalid == "invalid":
            params = replace_keys(authorize_params, update_params)

        resp = requests.get(
            nhsd_apim_proxy_url + "/authorize",
            params
        )

        body = resp.json()
        assert resp.status_code == expected_status_code
        assert (
            "message_id" in body.keys()
        )  # We assert the key but not he value for message_id
        del body["message_id"]
        assert body == expected_response

    @pytest.mark.errors
    @pytest.mark.authorize_endpoint
    @pytest.mark.parametrize(
        "expected_params,expected_status_code,missing_or_invalid,update_params",
        [
            (  # Test missing state
                {
                    "error": "invalid_request",
                    "error_description": "state is missing",
                },
                302,
                "missing",
                {"state"},
            ),
            (  # Test missing response_type
                {
                    "error": "invalid_request",
                    "error_description": "response_type is missing",
                },
                302,
                "missing",
                {"response_type"},
            ),
            (  # Test invalid response_type
                {
                    "error": "unsupported_response_type",
                    "error_description": "response_type is invalid",
                },
                302,
                "invalid",
                {"response_type": "invalid"},
            ),
        ]
    )
    def test_authorization_params_redirects_errors(
        self,
        expected_params,
        expected_status_code,
        missing_or_invalid,
        update_params,
        nhsd_apim_proxy_url,
        _test_app_callback_url,
        authorize_params
    ):
        if missing_or_invalid == "missing":
            params = remove_keys(authorize_params, update_params)
        if missing_or_invalid == "invalid":
            params = replace_keys(authorize_params, update_params)
        
        resp = requests.get(
            nhsd_apim_proxy_url + "/authorize",
            params,
            allow_redirects=False
        )

        assert resp.status_code == expected_status_code

        redirected_url = resp.headers["Location"]
        assert redirected_url.startswith(_test_app_callback_url)

        redirect_params = get_params_from_url(redirected_url)
        if "state" in params:
            expected_params["state"] = str(params["state"])
        
        assert redirect_params == expected_params

    @pytest.mark.skip(
        reason="TO REFACTOR"
    )
    @pytest.mark.errors
    @pytest.mark.authorize_endpoint
    def test_authorize_revoked_app(
        self,
        nhsd_apim_proxy_url,
        authorize_params
    ):
        resp = requests.get(
            nhsd_apim_proxy_url + "/authorize",
            authorize_params,
            allow_redirects=False
        )

        body = resp.json()
        assert resp.status_code == 401
        assert (
            "message_id" in body.keys()
        )  # We assert the key but not he value for message_id
        del body["message_id"]
        assert body == {
            "error": "access_denied",
            "error_description": "The developer app associated with the API key is not approved or revoked",
        }

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

    @pytest.mark.happy_path
    @pytest.mark.nhsd_apim_authorization(
        access="healthcare_worker",
        level="aal3",
        login_form={"username": "656005750104"},
        force_new_token=True
    )
    def test_refresh_token(
        self,
        nhsd_apim_proxy_url,
        refresh_token_data,
        _nhsd_apim_auth_token_data
    ):
        refresh_token_data["refresh_token"] = _nhsd_apim_auth_token_data["refresh_token"]
        resp = requests.post(
            nhsd_apim_proxy_url + "/token",
            headers={"Content-Type": "application/x-www-form-urlencoded"},
            data=refresh_token_data
        )
        body = resp.json()

        assert resp.status_code == 200
        assert body["expires_in"] == "599"
        assert body["token_type"] == "Bearer"
        assert body["refresh_count"] == "1"
        assert sorted(list(body.keys())) == [
            "access_token",
            "expires_in",
            "refresh_count",
            "refresh_token",
            "refresh_token_expires_in",
            "token_type"
        ]

    @pytest.mark.errors
    @pytest.mark.authorize_endpoint
    @pytest.mark.parametrize(
        "expected_response,expected_status_code,missing_or_invalid,update_data",
        [
            (  # Test missing client_id
                {
                    "error": "invalid_request",
                    "error_description": "client_id is missing",
                },
                401,
                "missing",
                {"client_id"},
            ),
            (  # Test invalid client_id
                {
                    "error": "invalid_client",
                    "error_description": "client_id or client_secret is invalid",
                },
                401,
                "invalid",
                {"client_id": "invalid"},
            ),
            (  # Test missing client_secret
                {
                    "error": "invalid_request",
                    "error_description": "client_secret is missing",
                },
                401,
                "missing",
                {"client_secret"},
            ),
            (  # Test invalid client_secret
                {
                    "error": "invalid_client",
                    "error_description": "client_id or client_secret is invalid",
                },
                401,
                "invalid",
                {"client_secret": "invalid"},
            ),
            (  # Test missing refresh_token
                {
                    "error": "invalid_request",
                    "error_description": "refresh_token is missing",
                },
                400,
                "missing",
                {"refresh_token"},
            ),
            (  # Test invalid refresh_token
                {
                    "error": "invalid_grant",
                    "error_description": "refresh_token is invalid",
                },
                401,
                "invalid",
                {"refresh_token": "invalid"},
            ),
            (  # Test missing grant_type
                {
                    "error": "invalid_request",
                    "error_description": "grant_type is missing",
                },
                400,
                "missing",
                {"grant_type"},
            ),
            (  # Test invalid grant_type
                {
                    "error": "unsupported_grant_type",
                    "error_description": "grant_type is invalid",
                },
                400,
                "invalid",
                {"grant_type": "invalid"},
            ),
        ]
    )
    @pytest.mark.nhsd_apim_authorization(
        access="healthcare_worker",
        level="aal3",
        login_form={"username": "656005750104"},
        force_new_token=True
    )
    def test_refresh_token_error_conditions(
        self,
        expected_response,
        expected_status_code,
        missing_or_invalid,
        update_data,
        nhsd_apim_proxy_url,
        refresh_token_data,
        _nhsd_apim_auth_token_data
    ):
        refresh_token_data["refresh_token"] = _nhsd_apim_auth_token_data["refresh_token"]
        if missing_or_invalid == "missing":
            data = remove_keys(refresh_token_data, update_data)
        if missing_or_invalid == "invalid":
            data = replace_keys(refresh_token_data, update_data)

        resp = requests.post(
            nhsd_apim_proxy_url + "/token",
            headers={"Content-Type": "application/x-www-form-urlencoded"},
            data=data
        )

        body = resp.json()
        assert resp.status_code == expected_status_code
        assert (
            "message_id" in body.keys()
        )  # We assert the key but not he value for message_id
        del body["message_id"]
        assert body == expected_response

    @pytest.mark.mock_auth
    @pytest.mark.happy_path
    @pytest.mark.nhsd_apim_authorization(
        access="healthcare_worker",
        level="aal3",
        login_form={"username": "656005750104"},
        force_new_token=True
    )
    def test_userinfo(self, nhsd_apim_proxy_url, nhsd_apim_auth_headers):
        resp = requests.get(
            nhsd_apim_proxy_url + "/userinfo",
            headers=nhsd_apim_auth_headers
        )
        body = resp.json()

        assert resp.status_code == 200
        assert body == BANK.get(self.name)["response"]

############## OAUTH TOKENS ###############

    @pytest.mark.nhsd_apim_authorization
    @pytest.mark.happy_path
    def test_access_token(
        self,
        nhsd_apim_proxy_url,
        test_app,
        _test_app_credentials,
        _apigee_edge_session,
        _apigee_app_base_url,
        token_data,
        authorize_params
    ):
        app = test_app()
        product_resp = subscribe_app_to_product(
            _apigee_edge_session,
            _apigee_app_base_url,
            _test_app_credentials,
            app["name"],
            CANARY_PRODUCT_NAME
        )
        assert product_resp.status_code == 200

        token_data["code"] = get_auth_code(
            url=nhsd_apim_proxy_url + "/authorize",
            authorize_params=authorize_params,
            username="656005750104"
        )

        # Post to token endpoint
        resp = requests.post(
            nhsd_apim_proxy_url + "/token",
            data=token_data,
            headers={"Content-Type": "application/x-www-form-urlencoded"}
        )
        body = resp.json()
        assert resp.status_code == 200
        token = body["access_token"]

        # Call Canary
        canary_resp = requests.get(
            CANARY_API_URL,
            headers={"Authorization": f"Bearer {token}"}
        )

        assert canary_resp.status_code == 200
        assert canary_resp.text == "Hello user!"

        # Tear down
        remove_product_resp = unsubscribe_product(
            _apigee_edge_session,
            _apigee_app_base_url,
            _test_app_credentials,
            app["name"],
            CANARY_PRODUCT_NAME
        )

        assert remove_product_resp.status_code == 200

    @pytest.mark.errors
    @pytest.mark.parametrize(
        ("token", "expected_response"),
        [
            # Using an invalid token
            ("ThisTokenIsInvalid", {
                "fault": {
                    "faultstring": "Invalid Access Token",
                    "detail": {
                        "errorcode": "keymanagement.service.invalid_access_token"
                    }
                }
            }),
            # Empty token
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
    def test_invalid_access_token(self, token, expected_response):
        resp = requests.get(
            CANARY_API_URL,
            headers={"Authorization": f"Bearer {token}"}
        )
        body = resp.json()

        assert resp.status_code == 401
        assert body == expected_response

    @pytest.mark.errors
    def test_expired_access_token(
        self,
        nhsd_apim_proxy_url,
        authorize_params,
        token_data
    ):
        token_data["code"] = get_auth_code(
            url=nhsd_apim_proxy_url + "/authorize",
            authorize_params=authorize_params,
            username="656005750104"
        )
        token_data["_access_token_expiry_ms"] = 5

        # Post to token endpoint
        resp = requests.post(
            nhsd_apim_proxy_url + "/token",
            headers={"Content-Type": "application/x-www-form-urlencoded"},
            data=token_data
        )

        token_resp = resp.json()
        token = token_resp["access_token"]

        sleep(5)

        resp_canary = requests.get(
            CANARY_API_URL,
            headers={"Authorization": f"Bearer {token}"}
        )
        body = resp_canary.json()

        assert resp_canary.status_code == 401
        assert body == {
            "fault": {
                "faultstring": "Access Token expired",
                "detail": {
                    "errorcode": "keymanagement.service.access_token_expired"
                }
            }
        }

    def test_missing_access_token(self):
        resp = requests.get(
            CANARY_API_URL,
        )
        body = resp.json()

        assert resp.status_code == 401
        assert body == {
            "fault": {
                "faultstring": "Invalid access token",
                "detail": {
                    "errorcode": "oauth.v2.InvalidAccessToken"
                }
            }
        }

    @pytest.mark.errors
    def test_access_token_with_params(
        self,
        nhsd_apim_proxy_url,
        authorize_params,
        token_data
    ):
        token_data["code"] = get_auth_code(
            url=nhsd_apim_proxy_url + "/authorize",
            authorize_params=authorize_params,
            username="656005750104"
        )

        # Post to token endpoint
        resp = requests.post(
            nhsd_apim_proxy_url + "/token",
            params=token_data
        )

        body = resp.json()
        assert resp.status_code == 415
        assert (
            "message_id" in body.keys()
        )  # We assert the key but not he value for message_id
        del body["message_id"]
        assert body == {
            "error": "invalid_request",
            "error_description": "Content-Type header must be application/x-www-urlencoded",
        }

    @pytest.mark.errors
    @pytest.mark.nhsd_apim_authorization(
        access="healthcare_worker",
        level="aal3",
        login_form={"username": "656005750104"},
        force_new_token=True
    )
    def test_refresh_token_does_expire(
        self,
        nhsd_apim_proxy_url,
        refresh_token_data,
        _nhsd_apim_auth_token_data
    ):
        refresh_token_data["refresh_token"] = _nhsd_apim_auth_token_data["refresh_token"]
        refresh_token_data["_refresh_token_expiry_ms"] = 4

        resp = requests.post(
            nhsd_apim_proxy_url + "/token",
            headers={"Content-Type": "application/x-www-form-urlencoded"},
            data=refresh_token_data
        )
        refresh_token_resp = resp.json()
        refresh_token_data["refresh_token"] = refresh_token_resp["refresh_token"]

        sleep(5)

        resp = requests.post(
            nhsd_apim_proxy_url + "/token",
            headers={"Content-Type": "application/x-www-form-urlencoded"},
            data=refresh_token_data
        )
        body = resp.json()

        assert resp.status_code == 401
        assert (
            "message_id" in body.keys()
        )  # We assert the key but not he value for message_id
        del body["message_id"]
        assert body == {
            "error": "invalid_grant",
            "error_description": "refresh token refresh period has expired",
        }

    @pytest.mark.errors
    @pytest.mark.nhsd_apim_authorization(
        access="healthcare_worker",
        level="aal3",
        login_form={"username": "656005750104"},
        force_new_token=True
    )
    def test_refresh_tokens_validity_expires(
        self,
        nhsd_apim_proxy_url,
        refresh_token_data,
        _nhsd_apim_auth_token_data
    ):
        refresh_token_data["refresh_token"] = _nhsd_apim_auth_token_data["refresh_token"]
        refresh_token_data["_refresh_tokens_validity_ms"] = 0

        resp = requests.post(
            nhsd_apim_proxy_url + "/token",
            headers={"Content-Type": "application/x-www-form-urlencoded"},
            data=refresh_token_data
        )
        body = resp.json()

        assert resp.status_code == 401
        assert (
            "message_id" in body.keys()
        )  # We assert the key but not he value for message_id
        del body["message_id"]
        assert body == {
            "error": "invalid_grant",
            "error_description": "refresh token refresh period has expired",
        }

    @pytest.mark.errors
    @pytest.mark.nhsd_apim_authorization(
        access="healthcare_worker",
        level="aal3",
        login_form={"username": "656005750104"},
        force_new_token=True
    )
    def test_re_use_of_refresh_token(
        self,
        nhsd_apim_proxy_url,
        refresh_token_data,
        _nhsd_apim_auth_token_data
    ):
        refresh_token_data["refresh_token"] = _nhsd_apim_auth_token_data["refresh_token"]

        resp = requests.post(
            nhsd_apim_proxy_url + "/token",
            headers={"Content-Type": "application/x-www-form-urlencoded"},
            data=refresh_token_data
        )

        assert resp.status_code == 200
        assert sorted(list(resp.json().keys())) == [
            "access_token",
            "expires_in",
            "refresh_count",
            "refresh_token",
            "refresh_token_expires_in",
            "token_type",
        ]

        resp_two = requests.post(
            nhsd_apim_proxy_url + "/token",
            headers={"Content-Type": "application/x-www-form-urlencoded"},
            data=refresh_token_data
        )
        body = resp_two.json()

        assert resp_two.status_code == 401
        assert (
            "message_id" in body.keys()
        )  # We assert the key but not he value for message_id
        del body["message_id"]
        assert body == {
            "error": "invalid_grant",
            "error_description": "refresh_token is invalid",
        }

    @pytest.mark.nhsd_apim_authorization(
        access="healthcare_worker",
        level="aal3",
        login_form={"username": "656005750104"},
        force_new_token=True
    )
    def test_cis2_refresh_tokens_generated_with_expected_expiry_combined_auth(
        self,
        _nhsd_apim_auth_token_data
    ):
        """
        Test that refresh tokens generated via CIS2 have an expiry time of 12 hours for combined authentication.
        """
        assert _nhsd_apim_auth_token_data["expires_in"] == "599"
        assert _nhsd_apim_auth_token_data["refresh_token_expires_in"] == "43199"

    @pytest.mark.skip(
        reason="TO REFACTOR to use Second Gen mock auth once completed. First gen does not work on prs"
    )
    @pytest.mark.parametrize(
        '_',
        [
            pytest.param(
                None,
                marks=pytest.mark.nhsd_apim_authorization(
                    access="patient",
                    level="P0",
                    login_form={"auth_method": "P0"},
                    force_new_token=True
                ),
            ),
            pytest.param(
                None,
                marks=pytest.mark.nhsd_apim_authorization(
                    access="patient",
                    level="P5",
                    login_form={"auth_method": "P5"},
                    force_new_token=True
                ),
            ),
            pytest.param(
                None,
                marks=pytest.mark.nhsd_apim_authorization(
                    access="patient",
                    level="P9",
                    login_form={"auth_method": "P9"},
                    force_new_token=True
                ),
            )
        ]
    )
    def test_nhs_login_refresh_tokens_generated_with_expected_expiry_combined_auth(
        self,
        _nhsd_apim_auth_token_data,
        _
    ):
        """
        Test that refresh tokens generated via NHS Login have an expiry time of 1 hour for combined authentication.
        """
        assert _nhsd_apim_auth_token_data["expires_in"] == "599"
        assert _nhsd_apim_auth_token_data["refresh_token_expires_in"] == "3599"
