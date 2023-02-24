import pytest
import requests
import random

from time import time
from uuid import uuid4

from e2e.tests.oauth.utils.helpers import (
    create_client_assertion,
    get_auth_info,
    get_auth_item,
    get_variable_from_trace,
    create_subject_token
)
from e2e.scripts.config import (ENVIRONMENT)


# Fixtures
@pytest.fixture(scope="function")
def test_app_and_products(
    nhsd_apim_test_app,
    products_api,
    _apigee_edge_session,
    _apigee_app_base_url,
    nhsd_apim_proxy_name,
    nhsd_apim_unsubscribe_test_app_from_all_products
):
    nhsd_apim_unsubscribe_test_app_from_all_products()

    app = nhsd_apim_test_app()
    app_name = app["name"]

    product_names = [f"apim-auto-{uuid4()}", f"apim-auto-{uuid4()}"]
    products = [
        {
            "apiResources": ["/"],
            "approvalType": "auto",
            "attributes": [{"name": "access", "value": "public"}],
            "description": product_name,
            "displayName": product_name,
            "environments": [ENVIRONMENT],
            "name": product_name,
            "proxies": [nhsd_apim_proxy_name],
            "scopes": [],
        }
        for product_name in product_names
    ]

    for product in products:
        products_api.post_products(body=product)
    
    app["apiProducts"] = product_names
    add_products_to_app_resp = _apigee_edge_session.post(f"{_apigee_app_base_url}/{app_name}", json=app)
    assert add_products_to_app_resp.status_code == 200

    app = add_products_to_app_resp.json()

    yield app, products

    nhsd_apim_unsubscribe_test_app_from_all_products()
    
    for product in products:
        products_api.delete_product_by_name(product_name=product["name"])
        

class TestClientCredentials:
    @pytest.mark.happy_path
    @pytest.mark.parametrize(
        "product_1_scopes, product_2_scopes, expected_filtered_scopes",
        [
            # Scenario 1: one product with valid scope
            (
                ["urn:nhsd:apim:app:level3:personal-demographics"],
                [],
                ["urn:nhsd:apim:app:level3:personal-demographics"],
            ),
            # Scenario 2: one product with valid scope, one product with invalid scope
            (
                ["urn:nhsd:apim:app:level3:personal-demographics-service"],
                ["urn:nhsd:apim:user-nhs-id:aal3:personal-demographics-service"],
                ["urn:nhsd:apim:app:level3:personal-demographics-service"],
            ),
            # Scenario 3: multiple products with valid scopes
            (
                ["urn:nhsd:apim:app:level3:personal-demographics-service"],
                ["urn:nhsd:apim:app:level3:ambulance-analytics"],
                [
                    "urn:nhsd:apim:app:level3:personal-demographics-service",
                    "urn:nhsd:apim:app:level3:ambulance-analytics",
                ],
            ),
            # Scenario 4: one product with multiple valid scopes
            (
                [
                    "urn:nhsd:apim:app:level3:personal-demographics",
                    "urn:nhsd:apim:app:level3:ambulance-analytics",
                ],
                [],
                [
                    "urn:nhsd:apim:app:level3:personal-demographics",
                    "urn:nhsd:apim:app:level3:ambulance-analytics",
                ],
            ),
            # Scenario 5: multiple products with multiple valid scopes
            (
                [
                    "urn:nhsd:apim:app:level3:personal-demographics",
                    "urn:nhsd:apim:app:level3:ambulance-analytics",
                ],
                [
                    "urn:nhsd:apim:app:level3:example-1",
                    "urn:nhsd:apim:app:level3:example-2",
                ],
                [
                    "urn:nhsd:apim:app:level3:personal-demographics",
                    "urn:nhsd:apim:app:level3:ambulance-analytics",
                    "urn:nhsd:apim:app:level3:example-1",
                    "urn:nhsd:apim:app:level3:example-2",
                ],
            ),
            # Scenario 6: one product with multiple scopes (valid and invalid)
            (
                [
                    "urn:nhsd:apim:app:level3:ambulance-analytics",
                    "urn:nhsd:apim:user-nhs-id:aal3:personal-demographics-service",
                ],
                [],
                ["urn:nhsd:apim:app:level3:ambulance-analytics"],
            ),
            # Scenario 7: multiple products with multiple scopes (valid and invalid)
            (
                [
                    "urn:nhsd:apim:app:level3:ambulance-analytics",
                    "urn:nhsd:apim:user-nhs-id:aal3:personal-demographics-service",
                ],
                [
                    "urn:nhsd:apim:app:level3:example-1",
                    "urn:nhsd:apim:user-nhs-id:aal3:example-2",
                ],
                [
                    "urn:nhsd:apim:app:level3:ambulance-analytics",
                    "urn:nhsd:apim:app:level3:example-1",
                ],
            ),
        ],
    )
    def test_valid_application_restricted_scope_combinations(
        self,
        product_1_scopes,
        product_2_scopes,
        expected_filtered_scopes,
        test_app_and_products,
        nhsd_apim_proxy_url,
        products_api,
        access_token_api,
        token_data_client_credentials,
        _jwt_keys
    ):
        app, products = test_app_and_products

        # Update product scopes
        for product, product_scopes in zip(products, [product_1_scopes, product_2_scopes]):
            product["scopes"] = product_scopes
            products_api.put_product_by_name(product["name"], product)

        # Get app-restricted token
        claims = {
            "sub": app["credentials"][0]["consumerKey"],
            "iss": app["credentials"][0]["consumerKey"],
            "jti": str(uuid4()),
            "aud": nhsd_apim_proxy_url + "/token",
            "exp": int(time()) + 300,  # 5 minutes in the future
        }

        token_data_client_credentials["client_assertion"] = create_client_assertion(
            claims,
            _jwt_keys["private_key_pem"]
        )

        resp = requests.post(
            nhsd_apim_proxy_url + "/token",
            data=token_data_client_credentials
        )

        assert resp.status_code == 200
        body = resp.json()
        access_token = body["access_token"]

        # Compare scopes
        token_data = access_token_api.get_token_details(access_token)
        token_scopes = token_data["scope"].split(" ")
        
        assert sorted(token_scopes) == sorted(expected_filtered_scopes)

    @pytest.mark.errors
    @pytest.mark.parametrize(
        "product_1_scopes, product_2_scopes",
        [
            # Scenario 1: multiple products with no scopes
            ([], []),
            # Scenario 2: one product with test_user_restricted_scope_combinationinvalid scope, one product with no scope
            (["urn:nhsd:apim:user-nhs-id:aal2:personal-demographics-service"], []),
            # Scenario 3: multiple products with invalid scopes
            (
                ["urn:nhsd:apim:user-nhs-id:aal3:personal-demographics-service"],
                ["urn:nhsd:apim:user-nhs-id:aal3:ambulance-analytics"],
            ),
            # Scenario 4: one product with multiple invalid scopes
            (
                [
                    "urn:nhsd:apim:user-nhs-id:aal3:personal-demographics-service",
                    "urn:nhsd:apim:user-nhs-id:aal3:ambulance-analytics",
                ],
                [],
            ),
            # Scenario 5: multiple products with multiple invalid scopes
            (
                [
                    "urn:nhsd:apim:user-nhs-id:aal3:personal-demographics-service",
                    "urn:nhsd:apim:user-nhs-id:aal3:ambulance-analytics",
                ],
                [
                    "urn:nhsd:apim:user-nhs-id:aal3:example-1",
                    "urn:nhsd:apim:user-nhs-id:aal3:example-2",
                ],
            ),
            # Scenario 6: one product with invalid scope (wrong formation)
            (["ThisDoesNotExist"], []),
            # Scenario 7: one product with invalid scope (special caracters)
            (["#£$?!&%*.;@~_-"], []),
            # Scenario 8: one product with invalid scope (empty string)
            ([""], []),
            # Scenario 9: one product with invalid scope (None object)
            ([None], []),
            # Scenario 10: one product with invalid scope (missing colon)
            (["urn:nshd:apim:app:level3personal-demographics-service"], []),
        ],
    )
    def test_application_restricted_scope_combination_errors(
        self,
        product_1_scopes,
        product_2_scopes,
        test_app_and_products,
        products_api,
        nhsd_apim_proxy_url,
        token_data_client_credentials,
        _jwt_keys
    ):
        app, products = test_app_and_products

        # Update product scopes
        for product, product_scopes in zip(products, [product_1_scopes, product_2_scopes]):
            product["scopes"] = product_scopes
            products_api.put_product_by_name(product["name"], product)

        # Get app-restricted token
        claims = {
            "sub": app["credentials"][0]["consumerKey"],
            "iss": app["credentials"][0]["consumerKey"],
            "jti": str(uuid4()),
            "aud": nhsd_apim_proxy_url + "/token",
            "exp": int(time()) + 300,  # 5 minutes in the future
        }

        token_data_client_credentials["client_assertion"] = create_client_assertion(
            claims,
            _jwt_keys["private_key_pem"]
        )

        resp = requests.post(
            nhsd_apim_proxy_url + "/token",
            data=token_data_client_credentials
        )
        body = resp.json()

        assert resp.status_code == 401
        assert "message_id" in body.keys()  # We assert the key but not he value for message_id
        del body["message_id"]
        assert body == {
            "error": "unauthorized_client",
            "error_description": "you have tried to request authorization but your "
            "application is not configured to use this authorization grant type",
        }

    @pytest.mark.parametrize(
        "external_scope",
        [
            # passing in external scopes via form params
            "invavlid scope",
            "$£$12vdg@@fd",
            "   external  scope",
            [
                "urn:nhsd:apim:user:aal3personal-demographics-service",
                "urn:nhsd:apim:app:level3:example-2",
            ],
        ],
    )
    def test_client_credentials_flow_removes_external_scopes(
        self,
        external_scope,
        test_app_and_products,
        nhsd_apim_proxy_url,
        products_api,
        access_token_api,
        token_data_client_credentials,
        _jwt_keys
    ):
        app, products = test_app_and_products

        expected_scopes = ["urn:nhsd:apim:app:level3:personal-demographics"]

        # Update product scopes
        for product in products:
            product["scopes"] = expected_scopes
            products_api.put_product_by_name(product["name"], product)

        # Get app-restricted token
        claims = {
            "sub": app["credentials"][0]["consumerKey"],
            "iss": app["credentials"][0]["consumerKey"],
            "jti": str(uuid4()),
            "aud": nhsd_apim_proxy_url + "/token",
            "exp": int(time()) + 300,  # 5 minutes in the future
        }

        token_data_client_credentials["client_assertion"] = create_client_assertion(
            claims,
            _jwt_keys["private_key_pem"]
        )

        token_data_client_credentials["scope"] = external_scope

        resp = requests.post(
            nhsd_apim_proxy_url + "/token",
            data=token_data_client_credentials
        )

        assert resp.status_code == 200

        body = resp.json()
        access_token = body["access_token"]

        # Compare scopes
        token_data = access_token_api.get_token_details(access_token)
        token_scopes = token_data["scope"].split(" ")
        
        assert token_scopes == expected_scopes


class TestAuthorizationCode:
    @pytest.mark.happy_path
    @pytest.mark.parametrize(
        "product_1_scopes, product_2_scopes, expected_filtered_scopes",
        [
            # Scenario 1: one product with valid scope
            (
                ["urn:nhsd:apim:user-nhs-id:aal3:personal-demographics-service"],
                [],
                ["urn:nhsd:apim:user-nhs-id:aal3:personal-demographics-service"],
            ),
            # Scenario 2: one product with valid scope, one product with invalid scope
            (
                ["urn:nhsd:apim:user-nhs-id:aal3:personal-demographics-service"],
                ["urn:nhsd:apim:app:level3:ambulance-analytics"],
                ["urn:nhsd:apim:user-nhs-id:aal3:personal-demographics-service"],
            ),
            # Scenario 3: multiple products with valid scopes
            (
                ["urn:nhsd:apim:user-nhs-id:aal3:personal-demographics-service"],
                ["urn:nhsd:apim:user-nhs-id:aal3:ambulance-analytics"],
                [
                    "urn:nhsd:apim:user-nhs-id:aal3:personal-demographics-service",
                    "urn:nhsd:apim:user-nhs-id:aal3:ambulance-analytics",
                ],
            ),
            # Scenario 4: one product with multiple valid scopes
            (
                [
                    "urn:nhsd:apim:user-nhs-id:aal3:personal-demographics-service",
                    "urn:nhsd:apim:user-nhs-id:aal3:ambulance-analytics",
                ],
                [],
                [
                    "urn:nhsd:apim:user-nhs-id:aal3:personal-demographics-service",
                    "urn:nhsd:apim:user-nhs-id:aal3:ambulance-analytics",
                ],
            ),
            # Scenario 5: multiple products with multiple valid scopes
            (
                [
                    "urn:nhsd:apim:user-nhs-id:aal3:personal-demographics-service",
                    "urn:nhsd:apim:user-nhs-id:aal3:ambulance-analytics",
                ],
                [
                    "urn:nhsd:apim:user-nhs-id:aal3:example-1",
                    "urn:nhsd:apim:user-nhs-id:aal3:example-2",
                ],
                [
                    "urn:nhsd:apim:user-nhs-id:aal3:personal-demographics-service",
                    "urn:nhsd:apim:user-nhs-id:aal3:ambulance-analytics",
                    "urn:nhsd:apim:user-nhs-id:aal3:example-1",
                    "urn:nhsd:apim:user-nhs-id:aal3:example-2",
                ],
            ),
            # Scenario 6: one product with multiple scopes (valid and invalid)
            (
                [
                    "urn:nhsd:apim:user-nhs-id:aal3:personal-demographics-service",
                    "urn:nhsd:apim:app:level3:ambulance-analytics",
                ],
                [],
                ["urn:nhsd:apim:user-nhs-id:aal3:personal-demographics-service"],
            ),
            # Scenario 7: multiple products with multiple scopes (valid and invalid)
            (
                [
                    "urn:nhsd:apim:user-nhs-id:aal3:personal-demographics-service",
                    "urn:nhsd:apim:app:level3:ambulance-analytics",
                ],
                [
                    "urn:nhsd:apim:user-nhs-id:aal3:example-1",
                    "urn:nhsd:apim:app:level3:example-2",
                ],
                [
                    "urn:nhsd:apim:user-nhs-id:aal3:example-1",
                    "urn:nhsd:apim:user-nhs-id:aal3:personal-demographics-service",
                ],
            ),
        ],
    )
    def test_valid_cis2_combined_user_restricted_scope_combinations(
        self,
        product_1_scopes,
        product_2_scopes,
        expected_filtered_scopes,
        test_app_and_products,
        nhsd_apim_proxy_url,
        products_api,
        access_token_api
    ):
        app, products = test_app_and_products

        # Update product scopes
        for product, product_scopes in zip(products, [product_1_scopes, product_2_scopes]):
            product["scopes"] = product_scopes
            products_api.put_product_by_name(product["name"], product)

        # Get cis2 combined token
        authorize_params = {
            "client_id": app["credentials"][0]["consumerKey"],
            "redirect_uri": app["callbackUrl"],
            "response_type": "code",
            "state": random.getrandbits(32),
        }
        auth_info = get_auth_info(
            url=nhsd_apim_proxy_url + "/authorize",
            authorize_params=authorize_params,
            username="656005750104"
        )
        token_data = {
            "client_id": app["credentials"][0]["consumerKey"],
            "client_secret": app["credentials"][0]["consumerSecret"],
            "redirect_uri": app["callbackUrl"],
            "grant_type": "authorization_code",
            "code": get_auth_item(auth_info, "code")
        }

        # Post to token endpoint
        resp = requests.post(
            nhsd_apim_proxy_url + "/token",
            headers={"Content-Type": "application/x-www-form-urlencoded"},
            data=token_data
        )

        assert resp.status_code == 200
        body = resp.json()
        access_token = body["access_token"]

        # Compare scopes
        token_data = access_token_api.get_token_details(access_token)
        token_scopes = token_data["scope"].split(" ")
        
        assert sorted(token_scopes) == sorted(expected_filtered_scopes)

    @pytest.mark.errors
    @pytest.mark.parametrize(
        "product_1_scopes, product_2_scopes",
        [
            # Scenario 1: multiple products with no scopes
            ([], []),
            # Scenario 2: one product with invalid scope, one product with no scope
            (["urn:nhsd:apim:user-nhs-id:aal2:personal-demographics-service"], []),
            # Scenario 3: multiple products with invalid scopes
            (
                ["urn:nhsd:apim:app:level3:personal-demographics-service"],
                ["urn:nhsd:apim:app:level3:ambulance-analytics"],
            ),
            # Scenario 4: one product with multiple invalid scopes
            (
                [
                    "urn:nhsd:apim:app:level3:personal-demographics-service",
                    "urn:nhsd:apim:app:level3:ambulance-analytics",
                ],
                [],
            ),
            # Scenario 5: multiple products with multiple invalid scopes
            (
                [
                    "urn:nhsd:apim:app:level3:personal-demographics-service",
                    "urn:nhsd:apim:app:level3:ambulance-analytics",
                ],
                [
                    "urn:nhsd:apim:app:level3:example-1",
                    "urn:nhsd:apim:app:level3:example-2",
                ],
            ),
            # Scenario 6: one product with invalid scope (wrong formation)
            (["ThisDoesNotExist"], []),
            # Scenario 7: one product with invalid scope (special characters)
            (["#£$?!&%*.;@~_-"], []),
            # Scenario 8: one product with invalid scope (empty string)
            ([""], []),
            # Scenario 8: one product with invalid scope (None object)
            ([None], []),
            # Scenario 9: one product with invalid scope, one product with no scope
            (["urn:nhsd:apim:user:aal3personal-demographics-service"], []),
        ],
    )
    def test_cis2_combined_user_restricted_scope_combination_errors(
        self,
        product_1_scopes,
        product_2_scopes,
        test_app_and_products,
        nhsd_apim_proxy_url,
        products_api,
        trace
    ):
        app, products = test_app_and_products

        # Update product scopes
        for product, product_scopes in zip(products, [product_1_scopes, product_2_scopes]):
            product["scopes"] = product_scopes
            products_api.put_product_by_name(product["name"], product)

        # Set up trace
        session_name = str(uuid4())
        header_filters = {"trace_id": session_name}
        trace.post_debugsession(session=session_name, header_filters=header_filters)


        # Authorize and hit callback endpoint
        authorize_params = {
            "client_id": app["credentials"][0]["consumerKey"],
            "redirect_uri": app["callbackUrl"],
            "response_type": "code",
            "state": random.getrandbits(32),
        }
        get_auth_info(
            url=nhsd_apim_proxy_url + "/authorize",
            authorize_params=authorize_params,
            username="656005750104",
            callback_headers=header_filters,
        )

        # Get variables from trace
        status_code = get_variable_from_trace(trace, session_name, "error.status.code")
        error_content = get_variable_from_trace(trace, session_name, "error.content")

        trace.delete_debugsession_by_name(session_name)

        assert status_code == 401
        assert "message_id" in error_content.keys()  # We assert the key but not he value for message_id
        del error_content["message_id"]
        assert error_content == {
            "error": "unauthorized_client",
            "error_description": "you have tried to request authorization but your "
            "application is not configured to use this authorization grant type",
        }

    @pytest.mark.parametrize(
        "external_scope",
        [
            # passing in external scopes via form params
            "invavlid scope",
            "$£$12vdg@@fd",
            "   external  scope",
            [
                "urn:nhsd:apim:user:aal3personal-demographics-service",
                "urn:nhsd:apim:app:level3:example-2",
            ],
        ],
    )
    def test_cis2_combined_user_restricted_flow_removes_external_scopes(
        self,
        external_scope,
        test_app_and_products,
        nhsd_apim_proxy_url,
        products_api,
        access_token_api
    ):
        app, products = test_app_and_products

        expected_scopes = ["urn:nhsd:apim:user-nhs-id:aal3:personal-demographics-service"]

        # Update product scopes
        for product in products:
            product["scopes"] = expected_scopes
            products_api.put_product_by_name(product["name"], product)

        # Get cis2 combined token
        authorize_params = {
            "client_id": app["credentials"][0]["consumerKey"],
            "redirect_uri": app["callbackUrl"],
            "response_type": "code",
            "state": random.getrandbits(32),
        }
        auth_info = get_auth_info(
            url=nhsd_apim_proxy_url + "/authorize",
            authorize_params=authorize_params,
            username="656005750104"
        )
        token_data = {
            "client_id": app["credentials"][0]["consumerKey"],
            "client_secret": app["credentials"][0]["consumerSecret"],
            "redirect_uri": app["callbackUrl"],
            "grant_type": "authorization_code",
            "code": get_auth_item(auth_info, "code"),
            "scope": external_scope
        }

        # Post to token endpoint
        resp = requests.post(
            nhsd_apim_proxy_url + "/token",
            headers={"Content-Type": "application/x-www-form-urlencoded"},
            data=token_data
        )

        assert resp.status_code == 200
        body = resp.json()
        access_token = body["access_token"]

        # Compare scopes
        token_data = access_token_api.get_token_details(access_token)
        token_scopes = token_data["scope"].split(" ")
        
        assert token_scopes == expected_scopes


#     @pytest.mark.happy_path
#     @pytest.mark.parametrize(
#         "product_1_scopes, product_2_scopes, expected_filtered_scopes",
#         [
#             # Scenario 1: one product with valid scope
#             (
#                 ["urn:nhsd:apim:user-nhs-login:P9:personal-demographics-service"],
#                 [],
#                 ["urn:nhsd:apim:user-nhs-login:P9:personal-demographics-service"],
#             ),
#             # Scenario 2: one product with valid scope, one product with invalid scope
#             (
#                 ["urn:nhsd:apim:user-nhs-login:P9:personal-demographics-service"],
#                 ["urn:nhsd:apim:app:level3:ambulance-analytics"],
#                 ["urn:nhsd:apim:user-nhs-login:P9:personal-demographics-service"],
#             ),
#             # Scenario 3: multiple products with valid scopes
#             (
#                 ["urn:nhsd:apim:user-nhs-login:P9:personal-demographics-service"],
#                 ["urn:nhsd:apim:user-nhs-login:P9:ambulance-analytics"],
#                 [
#                     "urn:nhsd:apim:user-nhs-login:P9:personal-demographics-service,"
#                     "urn:nhsd:apim:user-nhs-login:P9:ambulance-analytics"
#                 ],
#             ),
#             # Scenario 4: one product with multiple valid scopes
#             (
#                 [
#                     "urn:nhsd:apim:user-nhs-login:P9:personal-demographics-service",
#                     "urn:nhsd:apim:user-nhs-login:P9:ambulance-analytics",
#                 ],
#                 [],
#                 [
#                     "urn:nhsd:apim:user-nhs-login:P9:personal-demographics-service",
#                     "urn:nhsd:apim:user-nhs-login:P9:ambulance-analytics",
#                 ],
#             ),
#             # Scenario 5: multiple products with multiple valid scopes
#             (
#                 [
#                     "urn:nhsd:apim:user-nhs-login:P9:personal-demographics-service",
#                     "urn:nhsd:apim:user-nhs-login:P9:ambulance-analytics",
#                 ],
#                 [
#                     "urn:nhsd:apim:user-nhs-login:P9:example-1",
#                     "urn:nhsd:apim:user-nhs-login:P9:example-2",
#                 ],
#                 [
#                     "urn:nhsd:apim:user-nhs-login:P9:personal-demographics-service",
#                     "urn:nhsd:apim:user-nhs-login:P9:ambulance-analytics",
#                     "urn:nhsd:apim:user-nhs-login:P9:example-1",
#                     "urn:nhsd:apim:user-nhs-login:P9:example-2",
#                 ],
#             ),
#             # Scenario 6: one product with multiple scopes (valid and invalid)
#             (
#                 [
#                     "urn:nhsd:apim:user-nhs-login:P9:personal-demographics-service",
#                     "urn:nhsd:apim:app:level3:ambulance-analytics",
#                 ],
#                 [],
#                 ["urn:nhsd:apim:user-nhs-login:P9:personal-demographics-service"],
#             ),
#             # Scenario 7: multiple products with multiple scopes (valid and invalid)
#             (
#                 [
#                     "urn:nhsd:apim:user-nhs-login:P9:personal-demographics-service",
#                     "urn:nhsd:apim:app:level3:ambulance-analytics",
#                 ],
#                 [
#                     "urn:nhsd:apim:user-nhs-login:P9:example-1",
#                     "urn:nhsd:apim:app:level3:example-2",
#                 ],
#                 [
#                     "urn:nhsd:apim:user-nhs-login:P9:personal-demographics-service",
#                     "urn:nhsd:apim:user-nhs-login:P9:example-1",
#                 ],
#             ),
#             # Scenario 8: one product with valid scope with trailing and leading spaces
#             (
#                 [" urn:nhsd:apim:user-nhs-login:P9:personal-demographics-service "],
#                 [],
#                 ["urn:nhsd:apim:user-nhs-login:P9:personal-demographics-service"],
#             ),
#         ],
#     )
#     @pytest.mark.parametrize("auth_method", [('P9')])
#     def test_valid_nhs_login_combined_user_restricted_scope_combinations(
#         self,
#         product_1_scopes,
#         product_2_scopes,
#         expected_filtered_scopes,
#         test_app_and_products,
#         helper,
#         auth_code_nhs_login,
#     ):
#         test_product, test_product2, test_application = test_app_and_products

#         await test_product.update_scopes(product_1_scopes)
#         await test_product2.update_scopes(product_2_scopes)
#         apigee_trace = ApigeeApiTraceDebug(proxy=config.SERVICE_NAME)

#         callback_url = await test_application.get_callback_url()

        
#         state = await auth_code_nhs_login.get_state(self.oauth, test_application)

#         auth_code = await auth_code_nhs_login.make_auth_request(self.oauth, state)

#         await apigee_trace.start_trace()
#         await auth_code_nhs_login.make_callback_request(self.oauth, state, auth_code)

#         user_restricted_scopes = await apigee_trace.get_apigee_variable_from_trace(
#             name="apigee.user_restricted_scopes"
#         )
#         assert (
#             user_restricted_scopes is not None
#         ), "variable apigee.user_restricted_scopes not found in the trace"
#         user_restricted_scopes = user_restricted_scopes.split(" ")
#         assert expected_filtered_scopes.sort() == user_restricted_scopes.sort()


#     @pytest.mark.errors
#     @pytest.mark.parametrize(
#         "product_1_scopes, product_2_scopes",
#         [
#             # Scenario 1: multiple products with no scopes
#             ([], []),
#             # Scenario 2: one product with invalid scope, one product with no scope
#             (["urn:nhsd:apim:user-nhs-login:P0:personal-demographics-service"], []),
#             # Scenario 3: multiple products with invalid scopes
#             (
#                 ["urn:nhsd:apim:app:level3:personal-demographics-service"],
#                 ["urn:nhsd:apim:app:level3:ambulance-analytics"],
#             ),
#             # Scenario 4: one product with multiple invalid scopes
#             (
#                 [
#                     "urn:nhsd:apim:app:level3:personal-demographics-service",
#                     "urn:nhsd:apim:app:level3:ambulance-analytics",
#                 ],
#                 [],
#             ),
#             # Scenario 5: multiple products with multiple invalid scopes
#             (
#                 [
#                     "urn:nhsd:apim:app:level3:personal-demographics-service",
#                     "urn:nhsd:apim:app:level3:ambulance-analytics",
#                 ],
#                 [
#                     "urn:nhsd:apim:app:level3:example-1",
#                     "urn:nhsd:apim:app:level3:example-2",
#                 ],
#             ),
#             # Scenario 6: one product with invalid scope (wrong formation)
#             (["ThisDoesNotExist"], []),
#             # Scenario 7: one product with invalid scope (special characters)
#             (["#£$?!&%*.;@~_-"], []),
#             # Scenario 8: one product with invalid scope (empty string)
#             ([""], []),
#             # Scenario 8: one product with invalid scope (None object)
#             ([None], []),
#             # Scenario 9: one product with invalid scope, one product with no scope
#             (["urn:nhsd:apim:user-nhs-login:P0personal-demographics-service"], []),
#         ],
#     )
#     @pytest.mark.parametrize("auth_method", [("P9")])
#     def test_nhs_login_combined_user_restricted_scope_combination_errors(
#         self, product_1_scopes, product_2_scopes, test_app_and_products, helper, auth_code_nhs_login
#     ):
#         test_product, test_product2, test_application = test_app_and_products

#         expected_status_code = 401
#         expected_error = "unauthorized_client"
#         expected_error_description = (
#             "you have tried to request authorization but your "
#             "application is not configured to use this authorization grant type"
#         )

#         await test_product.update_scopes(product_1_scopes)
#         await test_product2.update_scopes(product_2_scopes)

        
#         state = await auth_code_nhs_login.get_state(self.oauth, test_application)


#         # Make simulated auth request to authenticate and  Make initial callback request
#         auth_code = await auth_code_nhs_login.make_auth_request(self.oauth, state)
#         await auth_code_nhs_login.make_callback_request(self.oauth, state, auth_code)
#         response = auth_code_nhs_login.response


#         assert expected_status_code == response["status_code"]
#         assert expected_error == response["body"]["error"]
#         assert expected_error_description == response["body"]["error_description"]


class TestTokenExchange:
    @pytest.mark.token_exchange
    @pytest.mark.parametrize(
        "product_1_scopes, product_2_scopes, expected_filtered_scopes",
        [
            # Scenario 1: one product with valid scope
            (
                ["urn:nhsd:apim:user-nhs-id:aal3:personal-demographics-service"],
                [],
                ["urn:nhsd:apim:user-nhs-id:aal3:personal-demographics-service"],
            ),
            # Scenario 2: one product with valid scope, one product with invalid scope
            (
                ["urn:nhsd:apim:user-nhs-id:aal3:personal-demographics-service"],
                ["urn:nhsd:apim:app:level3:ambulance-analytics"],
                ["urn:nhsd:apim:user-nhs-id:aal3:personal-demographics-service"],
            ),
            # Scenario 3: multiple products with valid scopes
            (
                ["urn:nhsd:apim:user-nhs-id:aal3:personal-demographics-service"],
                ["urn:nhsd:apim:user-nhs-id:aal3:ambulance-analytics"],
                [
                    "urn:nhsd:apim:user-nhs-id:aal3:personal-demographics-service",
                    "urn:nhsd:apim:user-nhs-id:aal3:ambulance-analytics",
                ],
            ),
            # Scenario 4: one product with multiple valid scopes
            (
                [
                    "urn:nhsd:apim:user-nhs-id:aal3:personal-demographics-service",
                    "urn:nhsd:apim:user-nhs-id:aal3:ambulance-analytics",
                ],
                [],
                [
                    "urn:nhsd:apim:user-nhs-id:aal3:personal-demographics-service",
                    "urn:nhsd:apim:user-nhs-id:aal3:ambulance-analytics",
                ],
            ),
            # Scenario 5: multiple products with multiple valid scopes
            (
                [
                    "urn:nhsd:apim:user-nhs-id:aal3:personal-demographics-service",
                    "urn:nhsd:apim:user-nhs-id:aal3:ambulance-analytics",
                ],
                [
                    "urn:nhsd:apim:user-nhs-id:aal3:example-1",
                    "urn:nhsd:apim:user-nhs-id:aal3:example-2",
                ],
                [
                    "urn:nhsd:apim:user-nhs-id:aal3:personal-demographics-service",
                    "urn:nhsd:apim:user-nhs-id:aal3:ambulance-analytics",
                    "urn:nhsd:apim:user-nhs-id:aal3:example-1",
                    "urn:nhsd:apim:user-nhs-id:aal3:example-2",
                ],
            ),
            # Scenario 6: one product with multiple scopes (valid and invalid)
            (
                [
                    "urn:nhsd:apim:user-nhs-id:aal3:personal-demographics-service",
                    "urn:nhsd:apim:app:level3:ambulance-analytics",
                ],
                [],
                ["urn:nhsd:apim:user-nhs-id:aal3:personal-demographics-service"],
            ),
            # Scenario 7: multiple products with multiple scopes (valid and invalid)
            (
                [
                    "urn:nhsd:apim:user-nhs-id:aal3:personal-demographics-service",
                    "urn:nhsd:apim:app:level3:ambulance-analytics",
                ],
                [
                    "urn:nhsd:apim:user-nhs-id:aal3:example-1",
                    "urn:nhsd:apim:app:level3:example-2",
                ],
                [
                    "urn:nhsd:apim:user-nhs-id:aal3:personal-demographics-service",
                    "urn:nhsd:apim:user-nhs-id:aal3:example-1",
                ],
            ),
        ],
    )
    def test_valid_cis2_token_exchange_user_restricted_scope_combination(
        self,
        product_1_scopes,
        product_2_scopes,
        expected_filtered_scopes,
        test_app_and_products,
        nhsd_apim_proxy_url,
        products_api,
        access_token_api,
        token_data_token_exchange,
        _jwt_keys,
        cis2_subject_token_claims
    ):
        app, products = test_app_and_products

        # Update product scopes
        for product, product_scopes in zip(products, [product_1_scopes, product_2_scopes]):
            product["scopes"] = product_scopes
            products_api.put_product_by_name(product["name"], product)

        # Get app-restricted token
        claims = {
            "sub": app["credentials"][0]["consumerKey"],
            "iss": app["credentials"][0]["consumerKey"],
            "jti": str(uuid4()),
            "aud": nhsd_apim_proxy_url + "/token",
            "exp": int(time()) + 300,  # 5 minutes in the future
        }

        token_data_token_exchange["client_assertion"] = create_client_assertion(
            claims,
            _jwt_keys["private_key_pem"]
        )
        token_data_token_exchange["subject_token"] = create_subject_token(cis2_subject_token_claims)

        resp = requests.post(
            nhsd_apim_proxy_url + "/token",
            data=token_data_token_exchange
        )

        assert resp.status_code == 200
        body = resp.json()
        access_token = body["access_token"]

        # Compare scopes
        token_data = access_token_api.get_token_details(access_token)
        token_scopes = token_data["scope"].split(" ")
        
        assert sorted(token_scopes) == sorted(expected_filtered_scopes)

    @pytest.mark.token_exchange
    @pytest.mark.errors
    @pytest.mark.parametrize(
        "product_1_scopes, product_2_scopes",
        [
            # Scenario 1: multiple products with no scopes
            ([], []),
            # Scenario 2: one product with invalid scope, one product with no scope
            (["urn:nhsd:apim:user-nhs-id:aal2:personal-demographics-service"], []),
            # Scenario 3: multiple products with invalid scopes
            (
                ["urn:nhsd:apim:app:level3:personal-demographics-service"],
                ["urn:nhsd:apim:app:level3:ambulance-analytics"],
            ),
            # Scenario 4: one product with multiple invalid scopes
            (
                [
                    "urn:nhsd:apim:app:level3:personal-demographics-service",
                    "urn:nhsd:apim:app:level3:ambulance-analytics",
                ],
                [],
            ),
            # Scenario 5: multiple products with multiple invalid scopes
            (
                [
                    "urn:nhsd:apim:app:level3:personal-demographics-service",
                    "urn:nhsd:apim:app:level3:ambulance-analytics",
                ],
                [
                    "urn:nhsd:apim:app:level3:example-1",
                    "urn:nhsd:apim:app:level3:example-2",
                ],
            ),
            # Scenario 6: one product with invalid scope (wrong formation)
            (["ThisDoesNotExist"], []),
            # Scenario 7: one product with invalid scope (special characters)
            (["#£$?!&%*.;@~_-"], []),
            # Scenario 8: one product with invalid scope (empty string)
            ([""], []),
            # Scenario 8: one product with invalid scope (None object)
            ([None], []),
            # Scenario 9: one product with invalid scope, one product with no scope
            (["urn:nhsd:apim:user:aal3personal-demographics-service"], []),
        ],
    )
    def test_cis2_token_exchange_error_user_restricted_scope_combination(
        self,
        product_1_scopes,
        product_2_scopes,
        test_app_and_products,
        nhsd_apim_proxy_url,
        products_api,
        token_data_token_exchange,
        _jwt_keys,
        cis2_subject_token_claims
    ):
        app, products = test_app_and_products

        # Update product scopes
        for product, product_scopes in zip(products, [product_1_scopes, product_2_scopes]):
            product["scopes"] = product_scopes
            products_api.put_product_by_name(product["name"], product)

        # Get app-restricted token
        claims = {
            "sub": app["credentials"][0]["consumerKey"],
            "iss": app["credentials"][0]["consumerKey"],
            "jti": str(uuid4()),
            "aud": nhsd_apim_proxy_url + "/token",
            "exp": int(time()) + 300,  # 5 minutes in the future
        }

        token_data_token_exchange["client_assertion"] = create_client_assertion(
            claims,
            _jwt_keys["private_key_pem"]
        )
        token_data_token_exchange["subject_token"] = create_subject_token(cis2_subject_token_claims)

        resp = requests.post(
            nhsd_apim_proxy_url + "/token",
            data=token_data_token_exchange
        )
        body = resp.json()

        assert resp.status_code == 401
        assert "message_id" in body.keys()  # We assert the key but not he value for message_id
        del body["message_id"]
        assert body == {
            "error": "unauthorized_client",
            "error_description": "you have tried to request authorization but your "
            "application is not configured to use this authorization grant type",
        }

#     @pytest.mark.parametrize(
#         "external_scope",
#         [
#             # passing in external scopes via form params
#             "invavlid scope",
#             "$£$12vdg@@fd",
#             "   external  scope",
#             [
#                 "urn:nhsd:apim:user:aal3personal-demographics-service",
#                 "urn:nhsd:apim:app:level3:example-2",
#             ],
#         ],
#     )
#     async def test_token_exchange_remove_external_scopes(self, external_scope):
#         client_assertion_jwt = self.oauth.create_jwt(kid="test-1")
#         id_token_jwt = self.oauth.create_id_token_jwt()

#         data = {
#             "scope": external_scope,
#             "grant_type": "urn:ietf:params:oauth:grant-type:token-exchange",
#             "subject_token_type": "urn:ietf:params:oauth:token-type:id_token",
#             "client_assertion_type": "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
#             "subject_token": id_token_jwt,
#             "client_assertion": client_assertion_jwt,
#         }

#         resp = await self.oauth.get_token_response(
#             grant_type="token_exchange", data=data
#         )

#         assert resp["status_code"] == 200


# @pytest.mark.asyncio
# class TestTokenExchangeNhsLoginHappyCases:
#     @pytest.mark.simulated_auth
#     @pytest.mark.token_exchange
#     @pytest.mark.errors
#     @pytest.mark.parametrize(
#         "product_1_scopes, product_2_scopes, expected_filtered_scopes",
#         [
#             # Scenario 1: one product with valid scope
#             (
#                 ["urn:nhsd:apim:user-nhs-login:P9:personal-demographics-service"],
#                 [],
#                 ["urn:nhsd:apim:user-nhs-login:P9:personal-demographics-service"],
#             ),
#             # Scenario 2: one product with valid scope, one product with invalid scope
#             (
#                 ["urn:nhsd:apim:user-nhs-login:P9:personal-demographics-service"],
#                 ["urn:nhsd:apim:app:level3:ambulance-analytics"],
#                 ["urn:nhsd:apim:user-nhs-login:P9:personal-demographics-service"],
#             ),
#             # Scenario 3: multiple products with valid scopes
#             (
#                 ["urn:nhsd:apim:user-nhs-login:P9:personal-demographics-service"],
#                 ["urn:nhsd:apim:user-nhs-login:P9:ambulance-analytics"],
#                 [
#                     "urn:nhsd:apim:user-nhs-login:P9:personal-demographics-service,"
#                     "urn:nhsd:apim:user-nhs-login:P9:ambulance-analytics"
#                 ],
#             ),
#             # Scenario 4: one product with multiple valid scopes
#             (
#                 [
#                     "urn:nhsd:apim:user-nhs-login:P9:personal-demographics-service",
#                     "urn:nhsd:apim:user-nhs-login:P9:ambulance-analytics",
#                 ],
#                 [],
#                 [
#                     "urn:nhsd:apim:user-nhs-login:P9:personal-demographics-service",
#                     "urn:nhsd:apim:user-nhs-login:P9:ambulance-analytics",
#                 ],
#             ),
#             # Scenario 5: multiple products with multiple valid scopes
#             (
#                 [
#                     "urn:nhsd:apim:user-nhs-login:P9:personal-demographics-service",
#                     "urn:nhsd:apim:user-nhs-login:P9:ambulance-analytics",
#                 ],
#                 [
#                     "urn:nhsd:apim:user-nhs-login:P9:example-1",
#                     "urn:nhsd:apim:user-nhs-login:P9:example-2",
#                 ],
#                 [
#                     "urn:nhsd:apim:user-nhs-login:P9:personal-demographics-service",
#                     "urn:nhsd:apim:user-nhs-login:P9:ambulance-analytics",
#                     "urn:nhsd:apim:user-nhs-login:P9:example-1",
#                     "urn:nhsd:apim:user-nhs-login:P9:example-2",
#                 ],
#             ),
#             # Scenario 6: one product with multiple scopes (valid and invalid)
#             (
#                 [
#                     "urn:nhsd:apim:user-nhs-login:P9:personal-demographics-service",
#                     "urn:nhsd:apim:app:level3:ambulance-analytics",
#                 ],
#                 [],
#                 ["urn:nhsd:apim:user-nhs-login:P9:personal-demographics-service"],
#             ),
#             # Scenario 7: multiple products with multiple scopes (valid and invalid)
#             (
#                 [
#                     "urn:nhsd:apim:user-nhs-login:P9:personal-demographics-service",
#                     "urn:nhsd:apim:app:level3:ambulance-analytics",
#                 ],
#                 [
#                     "urn:nhsd:apim:user-nhs-login:P9:example-1",
#                     "urn:nhsd:apim:app:level3:example-2",
#                 ],
#                 [
#                     "urn:nhsd:apim:user-nhs-login:P9:personal-demographics-service",
#                     "urn:nhsd:apim:user-nhs-login:P9:example-1",
#                 ],
#             ),
#             # Scenario 8: one product with valid scope with trailing and leading spaces
#             (
#                 [" urn:nhsd:apim:user-nhs-login:P9:personal-demographics-service "],
#                 [],
#                 ["urn:nhsd:apim:user-nhs-login:P9:personal-demographics-service"],
#             ),
#         ],
#     )
#     async def test_nhs_login_token_exchange_user_restricted_scope_combination(
#         self,
#         apigee_start_trace,
#         get_token_nhs_login_token_exchange,
#         expected_filtered_scopes,
#     ):
#         expected_status_code = 200
#         expected_expires_in = "599"
#         expected_token_type = "Bearer"
#         expected_issued_token_type = "urn:ietf:params:oauth:token-type:access_token"

#         # When
#         resp = get_token_nhs_login_token_exchange

#         apigee_trace = apigee_start_trace
#         filtered_scopes = await apigee_trace.get_apigee_variable_from_trace(
#             name="apigee.user_restricted_scopes"
#         )
#         assert (
#             filtered_scopes is not None
#         ), "variable apigee.user_restricted_scopes not found in the trace"
#         filtered_scopes = filtered_scopes.split(" ")

#         # Then
#         assert expected_status_code == resp["status_code"], resp["body"]
#         assert "access_token" in resp["body"]
#         assert expected_expires_in == resp["body"]["expires_in"]
#         assert expected_token_type == resp["body"]["token_type"]
#         assert expected_issued_token_type == resp["body"]["issued_token_type"]
#         assert expected_filtered_scopes.sort() == filtered_scopes.sort()

#     @pytest.mark.token_exchange
#     @pytest.mark.errors
#     @pytest.mark.parametrize(
#         "product_1_scopes, product_2_scopes",
#         [
#             # Scenario 1: multiple products with no scopes
#             ([], []),
#             # Scenario 2: one product with invalid scope, one product with no scope
#             (["urn:nhsd:apim:user-nhs-login:P0:personal-demographics-service"], []),
#             # Scenario 3: multiple products with invalid scopes
#             (
#                 ["urn:nhsd:apim:app:level3:personal-demographics-service"],
#                 ["urn:nhsd:apim:app:level3:ambulance-analytics"],
#             ),
#             # Scenario 4: one product with multiple invalid scopes
#             (
#                 [
#                     "urn:nhsd:apim:app:level3:personal-demographics-service",
#                     "urn:nhsd:apim:app:level3:ambulance-analytics",
#                 ],
#                 [],
#             ),
#             # Scenario 5: multiple products with multiple invalid scopes
#             (
#                 [
#                     "urn:nhsd:apim:app:level3:personal-demographics-service",
#                     "urn:nhsd:apim:app:level3:ambulance-analytics",
#                 ],
#                 [
#                     "urn:nhsd:apim:app:level3:example-1",
#                     "urn:nhsd:apim:app:level3:example-2",
#                 ],
#             ),
#             # Scenario 6: one product with invalid scope (wrong formation)
#             (["ThisDoesNotExist"], []),
#             # Scenario 7: one product with invalid scope (special characters)
#             (["#£$?!&%*.;@~_-"], []),
#             # Scenario 8: one product with invalid scope (empty string)
#             ([""], []),
#             # Scenario 8: one product with invalid scope (None object)
#             ([None], []),
#             # Scenario 9: one product with invalid scope, one product with no scope
#             (["urn:nhsd:apim:user-nhs-login:P0personal-demographics-service"], []),
#         ],
#     )
#     async def test_nhs_login_token_exchange_error_user_restricted_scope_combination(
#         self, get_token_nhs_login_token_exchange
#     ):
#         expected_status_code = 401
#         expected_error = "unauthorized_client"
#         expected_error_description = (
#             "you have tried to request authorization but your "
#             "application is not configured to use this authorization grant type"
#         )

#         # When
#         resp = get_token_nhs_login_token_exchange
#         # Then
#         assert expected_status_code == resp["status_code"]
#         assert expected_error == resp["body"]["error"]
#         assert expected_error_description == resp["body"]["error_description"]


