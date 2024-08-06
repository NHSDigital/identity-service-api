import pytest
import requests
import random

from time import sleep
from urllib import parse

from e2e.tests.utils.response_bank import BANK
from e2e.tests.utils.config import CANARY_API_URL, CANARY_PRODUCT_NAME
from e2e.tests.utils.helpers import (
    remove_keys,
    replace_keys,
    subscribe_app_to_products,
    unsubscribe_product,
    get_auth_info,
    get_auth_item,
)


class TestAuthorizationCode:
    """A test suit to test the token exchange flow"""
    # We are on our second generation of mock identity provider for
    # healthcare_worker access (CIS2). This allows you to log-in using a
    # username.
    MOCK_CIS2_USERNAMES = {
     "aal1": ["656005750110"],
     "aal2": ["656005750109", "656005750111", "656005750112"],
     "aal3": ["656005750104", "656005750105", "656005750106"],
    }

    # Create a list of pytest.param for each combination of username and level for combined auth
    combined_auth_params = [
        pytest.param(
            username, level,
            marks=pytest.mark.nhsd_apim_authorization(
                access="healthcare_worker",
                level=level,
                login_form={"username": username},
                force_new_token=True,
            ),
        )
        for level, usernames in MOCK_CIS2_USERNAMES.items()
        for username in usernames
    ]
    

    def get_params_from_url(self, url: str) -> dict:
        """Returns all the params and param values from a given url as a dictionary"""
        return dict(parse.parse_qsl(parse.urlsplit(url).query))

    def change_app_status(
        self,
        apigee_edge_session,
        apigee_app_base_url,
        app,
        status,
    ):
        assert status in ["approve", "revoke"]
        app_name = app["name"]
        url = f"{apigee_app_base_url}/{app_name}?action={status}"

        app["status"] = status

        resp = apigee_edge_session.post(url)

        return resp

    @pytest.mark.happy_path
    @pytest.mark.token_endpoint
    # @pytest.mark.nhsd_apim_authorization(
    #     access="healthcare_worker",
    #     level="aal3",
    #     login_form={"username": "656005750104"},
    #     force_new_token=True,
    # )
    @pytest.mark.parametrize("username, level", combined_auth_params)
    def test_token_endpoint(self, _nhsd_apim_auth_token_data, username, level):
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
            "issued_at",  # Added by pytest_nhsd_apim
        }

    @pytest.mark.errors
    @pytest.mark.token_endpoint
    # @pytest.mark.nhsd_apim_authorization(
    #     access="healthcare_worker",
    #     level="aal3",
    #     login_form={"username": "656005750104"},
    #     force_new_token=True,
    # )
    @pytest.mark.parametrize("username, level", combined_auth_params)
    @pytest.mark.parametrize(
        "expected_response,expected_status_code,missing_or_invalid,update_data",
        [
            (  # Test invalid grant_type
                {
                    "error": "unsupported_grant_type",
                    "error_description": "grant_type is invalid",
                },
                400,
                "invalid",
                {"grant_type": "invalid"},
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
            (  # Test invalid client_secret
                {
                    "error": "invalid_client",
                    "error_description": "client_id or client_secret is invalid",
                },
                401,
                "invalid",
                {"client_secret": "invalid"},
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
            (  # Test invalid redirect_uri
                {
                    "error": "invalid_request",
                    "error_description": "redirect_uri is invalid",
                },
                400,
                "invalid",
                {"redirect_uri": "invalid"},
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
            (  # Test invalid authorization_code
                {
                    "error": "invalid_grant",
                    "error_description": "authorization_code is invalid",
                },
                400,
                "invalid",
                {"code": "invalid"},
            ),
            (  # Test missing authorization_code
                {
                    "error": "invalid_request",
                    "error_description": "authorization_code is missing",
                },
                400,
                "missing",
                {"code"},
            ),
        ],
    )
    def test_token_error_conditions(
        self,
        nhsd_apim_proxy_url,
        authorize_params,
        token_data_authorization_code,
        expected_response,
        expected_status_code,
        missing_or_invalid,
        update_data,
        username,
        level
    ):
        auth_info = get_auth_info(
            url=nhsd_apim_proxy_url + "/authorize",
            authorize_params=authorize_params,
            username="656005750104",
        )
        token_data_authorization_code["code"] = get_auth_item(auth_info, "code")

        if missing_or_invalid == "missing":
            token_data_authorization_code = remove_keys(
                token_data_authorization_code, update_data
            )
        if missing_or_invalid == "invalid":
            token_data_authorization_code = replace_keys(
                token_data_authorization_code, update_data
            )

        # Post to token endpoint
        resp = requests.post(
            nhsd_apim_proxy_url + "/token",
            headers={"Content-Type": "application/x-www-form-urlencoded"},
            data=token_data_authorization_code,
        )

        body = resp.json()
        assert resp.status_code == expected_status_code
        assert (
            "message_id" in body.keys()
        )  # We assert the key but not he value for message_id
        del body["message_id"]
        assert body == expected_response

    @pytest.mark.happy_path
    # @pytest.mark.nhsd_apim_authorization(
    #     access="healthcare_worker",
    #     level="aal3",
    #     login_form={"username": "656005750104"},
    #     force_new_token=True,
    # )
    @pytest.mark.parametrize("username, level", combined_auth_params)
    def test_refresh_token(
        self, nhsd_apim_proxy_url, refresh_token_data, _nhsd_apim_auth_token_data, username, level
    ):
        refresh_token_data["refresh_token"] = _nhsd_apim_auth_token_data[
            "refresh_token"
        ]
        resp = requests.post(
            nhsd_apim_proxy_url + "/token",
            headers={"Content-Type": "application/x-www-form-urlencoded"},
            data=refresh_token_data,
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
            "token_type",
        ]

    @pytest.mark.happy_path
    # @pytest.mark.nhsd_apim_authorization(
    #     access="healthcare_worker",
    #     level="aal3",
    #     login_form={"username": "656005750104"},
    #     force_new_token=True
    # )
    @pytest.mark.parametrize("username, level", combined_auth_params)
    def test_refresh_token_expiry_calculated_correctly(
        self,
        nhsd_apim_proxy_url,
        refresh_token_data,
        _nhsd_apim_auth_token_data,
        username,
        level
    ):
        '''
        refresh_token_expires_in should reduce on subsequent calls
        '''
        wait_time_between_refresh_token_calls = 3
        refresh_token_data["refresh_token"] = _nhsd_apim_auth_token_data["refresh_token"]
        resp = requests.post(
            nhsd_apim_proxy_url + "/token",
            headers={"Content-Type": "application/x-www-form-urlencoded"},
            data=refresh_token_data
        )
        body = resp.json()
        first_expiry = int(body["refresh_token_expires_in"])
        assert body["refresh_count"] == "1"

        sleep(wait_time_between_refresh_token_calls)

        refresh_token_data["refresh_token"] = body["refresh_token"]
        resp = requests.post(
            nhsd_apim_proxy_url + "/token",
            headers={"Content-Type": "application/x-www-form-urlencoded"},
            data=refresh_token_data
        )
        body = resp.json()
        assert body["refresh_count"] == "2"
        second_expiry = int(body["refresh_token_expires_in"])
        assert second_expiry < first_expiry
        assert first_expiry - second_expiry == wait_time_between_refresh_token_calls

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
        ],
    )
    # @pytest.mark.nhsd_apim_authorization(
    #     access="healthcare_worker",
    #     level="aal3",
    #     login_form={"username": "656005750104"},
    #     force_new_token=True,
    # )
    @pytest.mark.parametrize("username, level", combined_auth_params)
    def test_refresh_token_error_conditions(
        self,
        expected_response,
        expected_status_code,
        missing_or_invalid,
        update_data,
        nhsd_apim_proxy_url,
        refresh_token_data,
        _nhsd_apim_auth_token_data,
        username,
        level
    ):
        refresh_token_data["refresh_token"] = _nhsd_apim_auth_token_data[
            "refresh_token"
        ]
        if missing_or_invalid == "missing":
            data = remove_keys(refresh_token_data, update_data)
        if missing_or_invalid == "invalid":
            data = replace_keys(refresh_token_data, update_data)

        resp = requests.post(
            nhsd_apim_proxy_url + "/token",
            headers={"Content-Type": "application/x-www-form-urlencoded"},
            data=data,
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
    def test_authorize_endpoint(self, nhsd_apim_proxy_url, authorize_params):
        resp = requests.get(nhsd_apim_proxy_url + "/authorize", authorize_params)

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
        self, method, allowed_method, endpoint, nhsd_apim_proxy_url
    ):
        resp = requests.request(
            method,
            url=nhsd_apim_proxy_url + endpoint,
        )

        assert resp.status_code == 405
        assert resp.headers["Allow"] == allowed_method

    @pytest.mark.errors
    @pytest.mark.authorize_endpoint
    # @pytest.mark.nhsd_apim_authorization(
    #     access="healthcare_worker",
    #     level="aal3",
    #     login_form={"username": "656005750104"},
    #     force_new_token=True,
    # )
    @pytest.mark.parametrize("username, level", combined_auth_params)
    def test_cache_invalidation(self, nhsd_apim_proxy_url, authorize_params, username, level):
        # Make authorize request, which includes callback call to retrieve used state
        auth_info = get_auth_info(
            url=nhsd_apim_proxy_url + "/authorize",
            authorize_params=authorize_params,
            username="656005750104",
        )
        authorize_params["code"] = get_auth_item(auth_info, "code")
        authorize_params["state"] = get_auth_item(auth_info, "state")

        resp = requests.get(
            nhsd_apim_proxy_url + "/callback", authorize_params, allow_redirects=False
        )

        body = resp.json()
        assert resp.status_code == 400
        assert (
            "message_id" in body.keys()
        )  # We assert the key but not he value for message_id
        del body["message_id"]
        assert body == {
            "error": "invalid_request",
            "error_description": "Invalid state parameter.",
        }

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
        ],
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

        resp = requests.get(nhsd_apim_proxy_url + "/authorize", params)

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
        ],
    )
    def test_authorization_params_redirects_errors(
        self,
        expected_params,
        expected_status_code,
        missing_or_invalid,
        update_params,
        nhsd_apim_proxy_url,
        _test_app_callback_url,
        authorize_params,
    ):
        if missing_or_invalid == "missing":
            params = remove_keys(authorize_params, update_params)
        if missing_or_invalid == "invalid":
            params = replace_keys(authorize_params, update_params)

        resp = requests.get(
            nhsd_apim_proxy_url + "/authorize", params, allow_redirects=False
        )

        assert resp.status_code == expected_status_code

        redirected_url = resp.headers["Location"]
        assert redirected_url.startswith(_test_app_callback_url)

        redirect_params = self.get_params_from_url(redirected_url)
        if "state" in params:
            expected_params["state"] = str(params["state"])

        assert redirect_params == expected_params

    @pytest.mark.errors
    @pytest.mark.authorize_endpoint
    def test_authorize_revoked_app(
        self,
        nhsd_apim_proxy_url,
        authorize_params,
        _apigee_edge_session,
        _apigee_app_base_url,
        _create_function_scoped_test_app,
    ):
        authorize_params["client_id"] = _create_function_scoped_test_app["credentials"][
            0
        ]["consumerKey"]
        authorize_params["redirect_uri"] = _create_function_scoped_test_app[
            "callbackUrl"
        ]

        # Revoke app
        revoke_app_resp = self.change_app_status(
            _apigee_edge_session,
            _apigee_app_base_url,
            _create_function_scoped_test_app,
            "revoke",
        )

        assert revoke_app_resp.status_code == 204

        # Attempt to authorize
        resp = requests.get(
            nhsd_apim_proxy_url + "/authorize", authorize_params, allow_redirects=False
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

    @pytest.mark.errors
    @pytest.mark.authorize_endpoint
    def test_authorize_unsubscribed_error_condition(
        self,
        nhsd_apim_proxy_url,
        _create_function_scoped_test_app,
        _apigee_edge_session,
        _apigee_app_base_url,
    ):
        # Create app subscribed to no products
        app = _create_function_scoped_test_app
        credential = app["credentials"][0]

        # Must be subscribed to product so add product from wrong environment
        product_resp = subscribe_app_to_products(
            _apigee_edge_session,
            _apigee_app_base_url,
            credential,
            app["name"],
            ["canary-api-ref"],
        )
        assert product_resp.status_code == 200

        params = {
            "client_id": credential["consumerKey"],
            "redirect_uri": app["callbackUrl"],
            "response_type": "code",
            "state": random.getrandbits(32),
        }

        resp = requests.get(
            nhsd_apim_proxy_url + "/authorize", params, allow_redirects=False
        )

        body = resp.json()
        assert resp.status_code == 401
        assert (
            "message_id" in body.keys()
        )  # We assert the key but not he value for message_id
        del body["message_id"]
        assert body == {
            "error": "access_denied",
            "error_description": "API Key supplied does not have access to this resource. "
            "Please check the API Key you are using belongs to an app "
            "which has sufficient access to access this resource.",
        }

    @pytest.mark.errors
    @pytest.mark.token_endpoint
    # @pytest.mark.nhsd_apim_authorization(
    #     access="healthcare_worker",
    #     level="aal3",
    #     login_form={"username": "656005750104"},
    #     force_new_token=True,
    # )
    @pytest.mark.parametrize("username, level", combined_auth_params)
    def test_token_unsubscribed_error_condition(
        self,
        nhsd_apim_proxy_url,
        _create_function_scoped_test_app,
        _apigee_edge_session,
        _apigee_app_base_url,
        _proxy_product_with_scope,
        username,
        level
    ):
        # Subscribe app to wrong environment Canary
        # so that product with wrong identity service associated
        # Also subscribe app to correct identity service
        app = _create_function_scoped_test_app
        credential = app["credentials"][0]

        product_resp = subscribe_app_to_products(
            _apigee_edge_session,
            _apigee_app_base_url,
            credential,
            app["name"],
            ["canary-api-ref", _proxy_product_with_scope["name"]],
        )
        assert product_resp.status_code == 200

        params = {
            "client_id": credential["consumerKey"],
            "redirect_uri": app["callbackUrl"],
            "response_type": "code",
            "state": random.getrandbits(32),
        }

        # Authorize
        auth_info = get_auth_info(
            url=nhsd_apim_proxy_url + "/authorize",
            authorize_params=params,
            username="656005750104",
        )

        # Remove correct ideneity service from product
        remove_product_resp = unsubscribe_product(
            _apigee_edge_session,
            _apigee_app_base_url,
            credential["consumerKey"],
            app["name"],
            _proxy_product_with_scope["name"],
        )
        assert remove_product_resp.status_code == 200

        token_data = {
            "client_id": credential["consumerKey"],
            "client_secret": credential["consumerSecret"],
            "redirect_uri": app["callbackUrl"],
            "grant_type": "authorization_code",
            "code": get_auth_item(auth_info, "code"),
        }

        # Post to token endpoint
        resp = requests.post(
            nhsd_apim_proxy_url + "/token",
            data=token_data,
            headers={"Content-Type": "application/x-www-form-urlencoded"},
        )

        body = resp.json()
        assert resp.status_code == 401
        assert (
            "message_id" in body.keys()
        )  # We assert the key but not he value for message_id
        del body["message_id"]
        assert body == {
            "error": "access_denied",
            "error_description": "API Key supplied does not have access to this resource. "
            "Please check the API Key you are using belongs to an app "
            "which has sufficient access to access this resource.",
        }

    @pytest.mark.happy_path
    # @pytest.mark.nhsd_apim_authorization(
    #     access="healthcare_worker",
    #     level="aal3",
    #     login_form={"username": "656005750104"},
    #     force_new_token=True,
    # )
    @pytest.mark.parametrize("username, level", combined_auth_params)
    def test_userinfo(self, nhsd_apim_proxy_url, nhsd_apim_auth_headers, username, level):
        resp = requests.get(
            nhsd_apim_proxy_url + "/userinfo", headers=nhsd_apim_auth_headers
        )
        body = resp.json()

        assert resp.status_code == 200
        assert body == BANK.get("test_userinfo")["response"]

    # @pytest.mark.nhsd_apim_authorization(
    #     access="healthcare_worker",
    #     level="aal3",
    #     login_form={"username": "656005750104"},
    #     force_new_token=True,
    # )
    @pytest.mark.parametrize("username, level", combined_auth_params)
    @pytest.mark.happy_path
    def test_access_token(
        self,
        nhsd_apim_proxy_url,
        _create_function_scoped_test_app,
        _proxy_product_with_scope,
        _apigee_edge_session,
        _apigee_app_base_url,
        username,
        level
    ):
        # Subscribe app to canary and identity service
        app = _create_function_scoped_test_app
        credential = app["credentials"][0]

        product_resp = subscribe_app_to_products(
            _apigee_edge_session,
            _apigee_app_base_url,
            credential,
            app["name"],
            [CANARY_PRODUCT_NAME, _proxy_product_with_scope["name"]],
        )
        assert product_resp.status_code == 200

        # Authorize
        params = {
            "client_id": credential["consumerKey"],
            "redirect_uri": app["callbackUrl"],
            "response_type": "code",
            "state": random.getrandbits(32),
        }

        auth_info = get_auth_info(
            url=nhsd_apim_proxy_url + "/authorize",
            authorize_params=params,
            username="656005750104",
        )

        token_data = {
            "client_id": credential["consumerKey"],
            "client_secret": credential["consumerSecret"],
            "redirect_uri": app["callbackUrl"],
            "grant_type": "authorization_code",
            "code": get_auth_item(auth_info, "code"),
        }

        # Post to token endpoint
        resp = requests.post(
            nhsd_apim_proxy_url + "/token",
            data=token_data,
            headers={"Content-Type": "application/x-www-form-urlencoded"},
        )
        body = resp.json()
        assert resp.status_code == 200
        token = body["access_token"]

        # Call Canary
        canary_resp = requests.get(
            CANARY_API_URL, headers={"Authorization": f"Bearer {token}"}
        )

        assert canary_resp.status_code == 200
        assert canary_resp.text == "Hello user!"

    @pytest.mark.errors
    @pytest.mark.parametrize(
        ("token", "expected_response"),
        [
            # Using an invalid token
            (
                "ThisTokenIsInvalid",
                {
                    "fault": {
                        "faultstring": "Invalid Access Token",
                        "detail": {
                            "errorcode": "keymanagement.service.invalid_access_token"
                        },
                    }
                },
            ),
            # Empty token
            (
                "",
                {
                    "fault": {
                        "faultstring": "Invalid access token",
                        "detail": {"errorcode": "oauth.v2.InvalidAccessToken"},
                    }
                },
            ),
        ],
    )
    @pytest.mark.errors
    def test_invalid_access_token(self, token, expected_response):
        resp = requests.get(
            CANARY_API_URL, headers={"Authorization": f"Bearer {token}"}
        )
        body = resp.json()

        assert resp.status_code == 401
        assert body == expected_response

    @pytest.mark.errors
    # @pytest.mark.nhsd_apim_authorization(
    #     access="healthcare_worker",
    #     level="aal3",
    #     login_form={"username": "656005750104"},
    #     force_new_token=True,
    # )
    @pytest.mark.parametrize("username, level", combined_auth_params)
    def test_expired_access_token(
        self, nhsd_apim_proxy_url, authorize_params, token_data_authorization_code, username, level
    ):
        # Set short expiry
        auth_info = get_auth_info(
            url=nhsd_apim_proxy_url + "/authorize",
            authorize_params=authorize_params,
            username="656005750104",
        )
        token_data_authorization_code["code"] = get_auth_item(auth_info, "code")
        token_data_authorization_code["_access_token_expiry_ms"] = 4

        # Post to token endpoint
        resp = requests.post(
            nhsd_apim_proxy_url + "/token",
            headers={"Content-Type": "application/x-www-form-urlencoded"},
            data=token_data_authorization_code,
        )

        token_resp = resp.json()
        token = token_resp["access_token"]

        # Wait for expiry
        sleep(5)

        # Hit canary with expired token
        resp_canary = requests.get(
            CANARY_API_URL, headers={"Authorization": f"Bearer {token}"}
        )
        body = resp_canary.json()

        assert resp_canary.status_code == 401
        assert body == {
            "fault": {
                "faultstring": "Access Token expired",
                "detail": {"errorcode": "keymanagement.service.access_token_expired"},
            }
        }

    @pytest.mark.errors
    # @pytest.mark.nhsd_apim_authorization(
    #     access="healthcare_worker",
    #     level="aal3",
    #     login_form={"username": "656005750104"},
    #     force_new_token=True,
    # )
    @pytest.mark.parametrize("username, level", combined_auth_params)
    @pytest.mark.parametrize(
        "token_expiry_ms, expected_time",
        [(100000, 100), (500000, 500), (700000, 600), (1000000, 600)],
    )
    def test_access_token_override_with_authorization_code(
        self,
        token_expiry_ms,
        expected_time,
        nhsd_apim_proxy_url,
        authorize_params,
        token_data_authorization_code,
        username,
        level
    ):
        # Set short expiry
        auth_info = get_auth_info(
            url=nhsd_apim_proxy_url + "/authorize",
            authorize_params=authorize_params,
            username="656005750104",
        )
        token_data_authorization_code["code"] = get_auth_item(auth_info, "code")
        token_data_authorization_code["_access_token_expiry_ms"] = token_expiry_ms

        # Post to token endpoint
        resp = requests.post(
            nhsd_apim_proxy_url + "/token", data=token_data_authorization_code
        )
        body = resp.json()

        assert resp.status_code == 200
        assert int(body["expires_in"]) <= expected_time

    @pytest.mark.errors
    # @pytest.mark.nhsd_apim_authorization(
    #     access="healthcare_worker",
    #     level="aal3",
    #     login_form={"username": "656005750104"},
    #     force_new_token=True,
    # )
    @pytest.mark.parametrize("username, level", combined_auth_params)
    @pytest.mark.parametrize(
        "token_expiry_ms, expected_time",
        [(100000, 100), (500000, 500), (700000, 600), (1000000, 600)],
    )
    def test_access_token_override_with_refresh_token(
        self,
        token_expiry_ms,
        expected_time,
        nhsd_apim_proxy_url,
        authorize_params,
        token_data_authorization_code,
        _test_app_credentials,
        username,
        level
    ):
        # Set short expiry
        auth_info = get_auth_info(
            url=nhsd_apim_proxy_url + "/authorize",
            authorize_params=authorize_params,
            username="656005750104",
        )
        token_data_authorization_code["code"] = get_auth_item(auth_info, "code")

        # Post to token endpoint
        resp = requests.post(
            nhsd_apim_proxy_url + "/token", data=token_data_authorization_code
        )
        body = resp.json()

        assert resp.status_code == 200
        assert body["refresh_token"]

        refresh_token = body["refresh_token"]

        refresh_token_data = {
            "client_id": _test_app_credentials["consumerKey"],
            "client_secret": _test_app_credentials["consumerSecret"],
            "grant_type": "refresh_token",
            "refresh_token": refresh_token,
            "_refresh_tokens_validity_ms": 599,
            "_access_token_expiry_ms": token_expiry_ms,
        }

        resp2 = requests.post(nhsd_apim_proxy_url + "/token", data=refresh_token_data)
        body2 = resp2.json()

        assert resp2.status_code == 200
        assert int(body2["expires_in"]) <= expected_time

    @pytest.mark.errors
    def test_missing_access_token(self):
        resp = requests.get(
            CANARY_API_URL,
        )
        body = resp.json()

        assert resp.status_code == 401
        assert body == {
            "fault": {
                "faultstring": "Invalid access token",
                "detail": {"errorcode": "oauth.v2.InvalidAccessToken"},
            }
        }

    @pytest.mark.errors
    # @pytest.mark.nhsd_apim_authorization(
    #     access="healthcare_worker",
    #     level="aal3",
    #     login_form={"username": "656005750104"},
    #     force_new_token=True,
    # )
    @pytest.mark.parametrize("username, level", combined_auth_params)
    def test_access_token_with_params(
        self, nhsd_apim_proxy_url, authorize_params, token_data_authorization_code, username, level
    ):
        # Authorize
        auth_info = get_auth_info(
            url=nhsd_apim_proxy_url + "/authorize",
            authorize_params=authorize_params,
            username="656005750104",
        )
        token_data_authorization_code["code"] = get_auth_item(auth_info, "code")

        # Post to token endpoint with params not data
        resp = requests.post(
            nhsd_apim_proxy_url + "/token", params=token_data_authorization_code
        )

        body = resp.json()
        assert resp.status_code == 415
        assert (
            "message_id" in body.keys()
        )  # We assert the key but not he value for message_id
        del body["message_id"]
        assert body == {
            "error": "invalid_request",
            "error_description": "Content-Type header must be application/x-www-form-urlencoded",
        }

    @pytest.mark.errors
    # @pytest.mark.nhsd_apim_authorization(
    #     access="healthcare_worker",
    #     level="aal3",
    #     login_form={"username": "656005750104"},
    #     force_new_token=True,
    # )
    @pytest.mark.parametrize("username, level", combined_auth_params)
    def test_refresh_token_does_expire(
        self, nhsd_apim_proxy_url, refresh_token_data, _nhsd_apim_auth_token_data, username, level
    ):
        # Set short expiry
        refresh_token_data["refresh_token"] = _nhsd_apim_auth_token_data[
            "refresh_token"
        ]
        refresh_token_data["_refresh_token_expiry_ms"] = 4

        # Refresh token
        resp = requests.post(
            nhsd_apim_proxy_url + "/token",
            headers={"Content-Type": "application/x-www-form-urlencoded"},
            data=refresh_token_data,
        )
        refresh_token_resp = resp.json()
        refresh_token_data["refresh_token"] = refresh_token_resp["refresh_token"]

        # Wait for expiry
        sleep(5)

        # Attempt to get new token
        resp = requests.post(
            nhsd_apim_proxy_url + "/token",
            headers={"Content-Type": "application/x-www-form-urlencoded"},
            data=refresh_token_data,
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
    # @pytest.mark.nhsd_apim_authorization(
    #     access="healthcare_worker",
    #     level="aal3",
    #     login_form={"username": "656005750104"},
    #     force_new_token=True,
    # )
    @pytest.mark.parametrize("username, level", combined_auth_params)
    def test_refresh_tokens_validity_expires(
        self, nhsd_apim_proxy_url, refresh_token_data, _nhsd_apim_auth_token_data, username, level
    ):
        refresh_token_data["refresh_token"] = _nhsd_apim_auth_token_data[
            "refresh_token"
        ]
        refresh_token_data["_refresh_tokens_validity_ms"] = 0

        resp = requests.post(
            nhsd_apim_proxy_url + "/token",
            headers={"Content-Type": "application/x-www-form-urlencoded"},
            data=refresh_token_data,
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
    # @pytest.mark.nhsd_apim_authorization(
    #     access="healthcare_worker",
    #     level="aal3",
    #     login_form={"username": "656005750104"},
    #     force_new_token=True,
    # )
    @pytest.mark.parametrize("username, level", combined_auth_params)
    def test_re_use_of_refresh_token(
        self, nhsd_apim_proxy_url, refresh_token_data, _nhsd_apim_auth_token_data, username, level
    ):
        refresh_token_data["refresh_token"] = _nhsd_apim_auth_token_data[
            "refresh_token"
        ]

        # Refresh token
        resp = requests.post(
            nhsd_apim_proxy_url + "/token",
            headers={"Content-Type": "application/x-www-form-urlencoded"},
            data=refresh_token_data,
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

        # Refresh original token
        resp_two = requests.post(
            nhsd_apim_proxy_url + "/token",
            headers={"Content-Type": "application/x-www-form-urlencoded"},
            data=refresh_token_data,
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

    @pytest.mark.happy_path
    # @pytest.mark.nhsd_apim_authorization(
    #     access="healthcare_worker",
    #     level="aal3",
    #     login_form={"username": "656005750104"},
    #     force_new_token=True,
    # )
    @pytest.mark.parametrize("username, level", combined_auth_params)
    def test_cis2_refresh_tokens_generated_with_expected_expiry_combined_auth(
        self, _nhsd_apim_auth_token_data, username, level
    ):
        """
        Test that refresh tokens generated via CIS2 have an expiry time of 12 hours for combined authentication.
        """
        assert _nhsd_apim_auth_token_data["expires_in"] == "599"
        assert _nhsd_apim_auth_token_data["refresh_token_expires_in"] == "43199"

    @pytest.mark.parametrize(
        "_",
        [
            pytest.param(
                None,
                marks=pytest.mark.nhsd_apim_authorization(
                    access="patient",
                    level="P0",
                    login_form={"username": "9912003073"},
                    force_new_token=True,
                ),
            ),
            pytest.param(
                None,
                marks=pytest.mark.nhsd_apim_authorization(
                    access="patient",
                    level="P5",
                    login_form={"username": "9912003072"},
                    force_new_token=True,
                ),
            ),
            pytest.param(
                None,
                marks=pytest.mark.nhsd_apim_authorization(
                    access="patient",
                    level="P9",
                    login_form={"username": "9912003071"},
                    force_new_token=True,
                ),
            ),
        ],
    )
    def test_nhs_login_refresh_tokens_generated_with_expected_expiry_combined_auth(
        self, _nhsd_apim_auth_token_data, _
    ):
        """
        Test that refresh tokens generated via NHS Login have an expiry time of 1 hour for combined authentication.
        """
        assert _nhsd_apim_auth_token_data["expires_in"] == "599"
        assert _nhsd_apim_auth_token_data["refresh_token_expires_in"] == "3599"