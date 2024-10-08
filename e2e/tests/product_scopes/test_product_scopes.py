import pytest
import requests
import random

from time import time
from uuid import uuid4

from e2e.tests.utils.helpers import (
    create_client_assertion,
    get_auth_info,
    get_auth_item,
    get_variable_from_trace,
    create_subject_token,
    create_nhs_login_subject_token,
)


class TestProductScopes:
    """Test suite for testing the interacting with scopes on products and tokens"""

    def update_product_multiple_scope_sets(
        self, products_api_client, products, product_1_scopes, product_2_scopes
    ):
        for product, product_scopes in zip(
            products, [product_1_scopes, product_2_scopes]
        ):
            product["scopes"] = product_scopes
            products_api_client.put_product_by_name(product["name"], product)

    def update_product_single_scope_set(self, products_api_client, products, scopes):
        for product in products:
            product["scopes"] = scopes
            products_api_client.put_product_by_name(product["name"], product)

    def create_client_credentials_token_data(
        self, client_id, identity_url, token_data, private_key
    ):
        claims = {
            "sub": client_id,
            "iss": client_id,
            "jti": str(uuid4()),
            "aud": identity_url + "/token",
            "exp": int(time()) + 300,  # 5 minutes in the future
        }

        token_data["client_assertion"] = create_client_assertion(claims, private_key)

        return token_data

    def create_authorization_code_token_data(
        self, client_id, client_secret, callback_url, identity_url, auth_pattern
    ):
        auth_pattern_mock_cis2_usernames_map = {
            "cis2_combined_aal1": "656005750110",
            "cis2_combined_aal2": "656005750109",
            "cis2_combined_aal3": "656005750104",
        }
        username = auth_pattern_mock_cis2_usernames_map.get(auth_pattern, "656005750104")
        authorize_params = {
            "client_id": client_id,
            "redirect_uri": callback_url,
            "response_type": "code",
            "state": random.getrandbits(32),
        }

        if auth_pattern == "nhs_login_combined":
            username = "9912003071"
            authorize_params["scope"] = "nhs-login"

        auth_info = get_auth_info(
            url=identity_url + "/authorize",
            authorize_params=authorize_params,
            username=username,
        )

        return {
            "client_id": client_id,
            "client_secret": client_secret,
            "redirect_uri": callback_url,
            "grant_type": "authorization_code",
            "code": get_auth_item(auth_info, "code"),
        }

    def create_token_exchange_token_data(
        self,
        client_id,
        identity_url,
        token_data,
        private_key,
        subject_token_claims,
        is_nhs_login=False,
    ):
        claims = {
            "sub": client_id,
            "iss": client_id,
            "jti": str(uuid4()),
            "aud": identity_url + "/token",
            "exp": int(time()) + 300,  # 5 minutes in the future
        }

        token_data["client_assertion"] = create_client_assertion(claims, private_key)
        if is_nhs_login:
            token_data["subject_token"] = create_nhs_login_subject_token(
                subject_token_claims["claims"], subject_token_claims["headers"]
            )
        else:
            token_data["subject_token"] = create_subject_token(subject_token_claims)

        return token_data

    def hit_authorize_and_callback_endpoints(
        self, client_id, callback_url, identity_url, auth_pattern, header_filters
    ):
        auth_pattern_mock_cis2_usernames_map = {
            "cis2_combined_aal1": "656005750110",
            "cis2_combined_aal2": "656005750109",
            "cis2_combined_aal3": "656005750104",
        }
        username = auth_pattern_mock_cis2_usernames_map.get(auth_pattern, "656005750104")
        authorize_params = {
            "client_id": client_id,
            "redirect_uri": callback_url,
            "response_type": "code",
            "state": random.getrandbits(32),
        }

        if auth_pattern == "nhs_login_combined":
            username = "9912003071"
            authorize_params["scope"] = "nhs-login"

        get_auth_info(
            url=identity_url + "/authorize",
            authorize_params=authorize_params,
            username=username,
            callback_headers=header_filters,
        )

    @pytest.mark.happy_path
    @pytest.mark.parametrize(
        "product_1_scopes,product_2_scopes,expected_filtered_scopes,auth_pattern",
        [
            pytest.param(
                ["urn:nhsd:apim:app:level3:personal-demographics"],
                [],
                ["urn:nhsd:apim:app:level3:personal-demographics"],
                "client_credentials",
                id="App-restricted: one product with valid scope",
            ),
            pytest.param(
                ["urn:nhsd:apim:app:level3:personal-demographics-service"],
                ["urn:nhsd:apim:user-nhs-id:aal3:personal-demographics-service"],
                ["urn:nhsd:apim:app:level3:personal-demographics-service"],
                "client_credentials",
                id="App-restricted: one product with valid scope, one product with invalid scope",
            ),
            pytest.param(
                ["urn:nhsd:apim:app:level3:personal-demographics-service"],
                ["urn:nhsd:apim:app:level3:ambulance-analytics"],
                [
                    "urn:nhsd:apim:app:level3:personal-demographics-service",
                    "urn:nhsd:apim:app:level3:ambulance-analytics",
                ],
                "client_credentials",
                id="App-restricted: multiple products with valid scopes",
            ),
            pytest.param(
                [
                    "urn:nhsd:apim:app:level3:personal-demographics",
                    "urn:nhsd:apim:app:level3:ambulance-analytics",
                ],
                [],
                [
                    "urn:nhsd:apim:app:level3:personal-demographics",
                    "urn:nhsd:apim:app:level3:ambulance-analytics",
                ],
                "client_credentials",
                id="App-restricted: one product with multiple valid scopes",
            ),
            pytest.param(
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
                "client_credentials",
                id="App-restricted: multiple products with multiple valid scopes",
            ),
            pytest.param(
                [
                    "urn:nhsd:apim:app:level3:ambulance-analytics",
                    "urn:nhsd:apim:user-nhs-id:aal3:personal-demographics-service",
                ],
                [],
                ["urn:nhsd:apim:app:level3:ambulance-analytics"],
                "client_credentials",
                id="App-restricted: one product with multiple scopes (valid and invalid)",
            ),
            pytest.param(
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
                "client_credentials",
                id="App-restricted: multiple products with multiple scopes (valid and invalid)",
            ),
            pytest.param(
                ["urn:nhsd:apim:user-nhs-id:aal3:personal-demographics-service"],
                [],
                ["urn:nhsd:apim:user-nhs-id:aal3:personal-demographics-service"],
                "cis2_combined_aal3",
                id="User-restricted-CIS2-combined: one product with valid scope (authed as aal3 user)",
            ),
            pytest.param(
                ["urn:nhsd:apim:user-nhs-id:aal2:personal-demographics-service"],
                [],
                ["urn:nhsd:apim:user-nhs-id:aal2:personal-demographics-service"],
                "cis2_combined_aal2",
                id="User-restricted-CIS2-combined: one product with valid scope (authed as aal2 user)",
            ),
            pytest.param(
                ["urn:nhsd:apim:user-nhs-id:aal1:personal-demographics-service"],
                [],
                ["urn:nhsd:apim:user-nhs-id:aal1:personal-demographics-service"],
                "cis2_combined_aal1",
                id="User-restricted-CIS2-combined: one product with valid scope (authed as aal1 user)",
            ),
            pytest.param(
                ["urn:nhsd:apim:user-nhs-id:aal3:personal-demographics-service"],
                ["urn:nhsd:apim:app:level3:ambulance-analytics"],
                ["urn:nhsd:apim:user-nhs-id:aal3:personal-demographics-service"],
                "cis2_combined_aal3",
                id="User-restricted-CIS2-combined: one product with valid scope, one product with invalid scope",
            ),
            pytest.param(
                ["urn:nhsd:apim:user-nhs-id:aal3:personal-demographics-service"],
                ["urn:nhsd:apim:user-nhs-id:aal3:ambulance-analytics"],
                [
                    "urn:nhsd:apim:user-nhs-id:aal3:personal-demographics-service",
                    "urn:nhsd:apim:user-nhs-id:aal3:ambulance-analytics",
                ],
                "cis2_combined_aal3",
                id="User-restricted-CIS2-combined: multiple products with valid scopes",
            ),
            pytest.param(
                [
                    "urn:nhsd:apim:user-nhs-id:aal3:personal-demographics-service",
                    "urn:nhsd:apim:user-nhs-id:aal3:ambulance-analytics",
                ],
                [],
                [
                    "urn:nhsd:apim:user-nhs-id:aal3:personal-demographics-service",
                    "urn:nhsd:apim:user-nhs-id:aal3:ambulance-analytics",
                ],
                "cis2_combined_aal3",
                id="User-restricted-CIS2-combined: one product with multiple valid scopes",
            ),
            pytest.param(
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
                "cis2_combined_aal3",
                id="User-restricted-CIS2-combined: multiple products with multiple valid scopes",
            ),
            pytest.param(
                [
                    "urn:nhsd:apim:user-nhs-id:aal3:personal-demographics-service",
                    "urn:nhsd:apim:app:level3:ambulance-analytics",
                ],
                [],
                ["urn:nhsd:apim:user-nhs-id:aal3:personal-demographics-service"],
                "cis2_combined_aal3",
                id="User-restricted-CIS2-combined: one product with multiple scopes (valid and invalid)",
            ),
            pytest.param(
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
                "cis2_combined_aal3",
                id="User-restricted-CIS2-combined: multiple products with multiple scopes (valid and invalid)",
            ),
            pytest.param(
                ["urn:nhsd:apim:user-nhs-login:P9:personal-demographics-service"],
                [],
                ["urn:nhsd:apim:user-nhs-login:P9:personal-demographics-service"],
                "nhs_login_combined",
                id="User-restricted-NHS-Login-combined: one product with valid scope",
            ),
            pytest.param(
                ["urn:nhsd:apim:user-nhs-login:P9:personal-demographics-service"],
                ["urn:nhsd:apim:app:level3:ambulance-analytics"],
                ["urn:nhsd:apim:user-nhs-login:P9:personal-demographics-service"],
                "nhs_login_combined",
                id="User-restricted-NHS-Login-combined: one product with valid scope, one product with invalid scope",
            ),
            pytest.param(
                ["urn:nhsd:apim:user-nhs-login:P9:personal-demographics-service"],
                ["urn:nhsd:apim:user-nhs-login:P9:ambulance-analytics"],
                [
                    "urn:nhsd:apim:user-nhs-login:P9:personal-demographics-service",
                    "urn:nhsd:apim:user-nhs-login:P9:ambulance-analytics",
                ],
                "nhs_login_combined",
                id="User-restricted-NHS-Login-combined: multiple products with valid scopes",
            ),
            pytest.param(
                [
                    "urn:nhsd:apim:user-nhs-login:P9:personal-demographics-service",
                    "urn:nhsd:apim:user-nhs-login:P9:ambulance-analytics",
                ],
                [],
                [
                    "urn:nhsd:apim:user-nhs-login:P9:personal-demographics-service",
                    "urn:nhsd:apim:user-nhs-login:P9:ambulance-analytics",
                ],
                "nhs_login_combined",
                id="User-restricted-NHS-Login-combined: one product with multiple valid scopes",
            ),
            pytest.param(
                [
                    "urn:nhsd:apim:user-nhs-login:P9:personal-demographics-service",
                    "urn:nhsd:apim:user-nhs-login:P9:ambulance-analytics",
                ],
                [
                    "urn:nhsd:apim:user-nhs-login:P9:example-1",
                    "urn:nhsd:apim:user-nhs-login:P9:example-2",
                ],
                [
                    "urn:nhsd:apim:user-nhs-login:P9:personal-demographics-service",
                    "urn:nhsd:apim:user-nhs-login:P9:ambulance-analytics",
                    "urn:nhsd:apim:user-nhs-login:P9:example-1",
                    "urn:nhsd:apim:user-nhs-login:P9:example-2",
                ],
                "nhs_login_combined",
                id="User-restricted-NHS-Login-combined: multiple products with multiple valid scopes",
            ),
            pytest.param(
                [
                    "urn:nhsd:apim:user-nhs-login:P9:personal-demographics-service",
                    "urn:nhsd:apim:app:level3:ambulance-analytics",
                ],
                [],
                ["urn:nhsd:apim:user-nhs-login:P9:personal-demographics-service"],
                "nhs_login_combined",
                id="User-restricted-NHS-Login-combined: one product with multiple scopes (valid and invalid)",
            ),
            pytest.param(
                [
                    "urn:nhsd:apim:user-nhs-login:P9:personal-demographics-service",
                    "urn:nhsd:apim:app:level3:ambulance-analytics",
                ],
                [
                    "urn:nhsd:apim:user-nhs-login:P9:example-1",
                    "urn:nhsd:apim:app:level3:example-2",
                ],
                [
                    "urn:nhsd:apim:user-nhs-login:P9:personal-demographics-service",
                    "urn:nhsd:apim:user-nhs-login:P9:example-1",
                ],
                "nhs_login_combined",
                id="User-restricted-NHS-Login-combined: multiple products with multiple scopes (valid and invalid)",
            ),
            pytest.param(
                ["urn:nhsd:apim:user-nhs-id:aal3:personal-demographics-service"],
                [],
                ["urn:nhsd:apim:user-nhs-id:aal3:personal-demographics-service"],
                "cis2_seperate_aal3",
                id="User-restricted-CIS2-seperate: one product with valid scope (authed as aal3 user)",
            ),
            pytest.param(
                ["urn:nhsd:apim:user-nhs-id:aal2:personal-demographics-service"],
                [],
                ["urn:nhsd:apim:user-nhs-id:aal2:personal-demographics-service"],
                "cis2_separate_aal2",
                id="User-restricted-CIS2-separate: one product with valid scope (authed as aal2 user)",
            ),
            pytest.param(
                ["urn:nhsd:apim:user-nhs-id:aal1:personal-demographics-service"],
                [],
                ["urn:nhsd:apim:user-nhs-id:aal1:personal-demographics-service"],
                "cis2_separate_aal1",
                id="User-restricted-CIS2-separate: one product with valid scope (authed as aal1 user)",
            ),
            pytest.param(
                ["urn:nhsd:apim:user-nhs-id:aal3:personal-demographics-service"],
                ["urn:nhsd:apim:app:level3:ambulance-analytics"],
                ["urn:nhsd:apim:user-nhs-id:aal3:personal-demographics-service"],
                "cis2_seperate_aal3",
                id="User-restricted-CIS2-seperate: one product with valid scope, one product with invalid scope",
            ),
            pytest.param(
                ["urn:nhsd:apim:user-nhs-id:aal3:personal-demographics-service"],
                ["urn:nhsd:apim:user-nhs-id:aal3:ambulance-analytics"],
                [
                    "urn:nhsd:apim:user-nhs-id:aal3:personal-demographics-service",
                    "urn:nhsd:apim:user-nhs-id:aal3:ambulance-analytics",
                ],
                "cis2_seperate_aal3",
                id="User-restricted-CIS2-seperate: multiple products with valid scopes",
            ),
            pytest.param(
                [
                    "urn:nhsd:apim:user-nhs-id:aal3:personal-demographics-service",
                    "urn:nhsd:apim:user-nhs-id:aal3:ambulance-analytics",
                ],
                [],
                [
                    "urn:nhsd:apim:user-nhs-id:aal3:personal-demographics-service",
                    "urn:nhsd:apim:user-nhs-id:aal3:ambulance-analytics",
                ],
                "cis2_seperate_aal3",
                id="User-restricted-CIS2-seperate: one product with multiple valid scopes",
            ),
            pytest.param(
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
                "cis2_seperate_aal3",
                id="User-restricted-CIS2-seperate: multiple products with multiple valid scopes",
            ),
            pytest.param(
                [
                    "urn:nhsd:apim:user-nhs-id:aal3:personal-demographics-service",
                    "urn:nhsd:apim:app:level3:ambulance-analytics",
                ],
                [],
                ["urn:nhsd:apim:user-nhs-id:aal3:personal-demographics-service"],
                "cis2_seperate_aal3",
                id="User-restricted-CIS2-seperate: one product with multiple scopes (valid and invalid)",
            ),
            pytest.param(
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
                "cis2_seperate_aal3",
                id="User-restricted-CIS2-seperate: multiple products with multiple scopes (valid and invalid)",
            ),
            pytest.param(
                ["urn:nhsd:apim:user-nhs-login:P9:personal-demographics-service"],
                [],
                ["urn:nhsd:apim:user-nhs-login:P9:personal-demographics-service"],
                "nhs_login_separate",
                id="User-restricted-NHS-Login-seperate: one product with valid scope",
            ),
            pytest.param(
                ["urn:nhsd:apim:user-nhs-login:P9:personal-demographics-service"],
                ["urn:nhsd:apim:app:level3:ambulance-analytics"],
                ["urn:nhsd:apim:user-nhs-login:P9:personal-demographics-service"],
                "nhs_login_separate",
                id="User-restricted-NHS-Login-seperate: one product with valid scope, one product with invalid scope",
            ),
            pytest.param(
                ["urn:nhsd:apim:user-nhs-login:P9:personal-demographics-service"],
                ["urn:nhsd:apim:user-nhs-login:P9:ambulance-analytics"],
                [
                    "urn:nhsd:apim:user-nhs-login:P9:personal-demographics-service",
                    "urn:nhsd:apim:user-nhs-login:P9:ambulance-analytics",
                ],
                "nhs_login_separate",
                id="User-restricted-NHS-Login-seperate: multiple products with valid scopes",
            ),
            pytest.param(
                [
                    "urn:nhsd:apim:user-nhs-login:P9:personal-demographics-service",
                    "urn:nhsd:apim:user-nhs-login:P9:ambulance-analytics",
                ],
                [],
                [
                    "urn:nhsd:apim:user-nhs-login:P9:personal-demographics-service",
                    "urn:nhsd:apim:user-nhs-login:P9:ambulance-analytics",
                ],
                "nhs_login_separate",
                id="User-restricted-NHS-Login-seperate: one product with multiple valid scopes",
            ),
            pytest.param(
                [
                    "urn:nhsd:apim:user-nhs-login:P9:personal-demographics-service",
                    "urn:nhsd:apim:user-nhs-login:P9:ambulance-analytics",
                ],
                [
                    "urn:nhsd:apim:user-nhs-login:P9:example-1",
                    "urn:nhsd:apim:user-nhs-login:P9:example-2",
                ],
                [
                    "urn:nhsd:apim:user-nhs-login:P9:personal-demographics-service",
                    "urn:nhsd:apim:user-nhs-login:P9:ambulance-analytics",
                    "urn:nhsd:apim:user-nhs-login:P9:example-1",
                    "urn:nhsd:apim:user-nhs-login:P9:example-2",
                ],
                "nhs_login_separate",
                id="User-restricted-NHS-Login-seperate: multiple products with multiple valid scopes",
            ),
            pytest.param(
                [
                    "urn:nhsd:apim:user-nhs-login:P9:personal-demographics-service",
                    "urn:nhsd:apim:app:level3:ambulance-analytics",
                ],
                [],
                ["urn:nhsd:apim:user-nhs-login:P9:personal-demographics-service"],
                "nhs_login_separate",
                id="User-restricted-NHS-Login-seperate: one product with multiple scopes (valid and invalid)",
            ),
            pytest.param(
                [
                    "urn:nhsd:apim:user-nhs-login:P9:personal-demographics-service",
                    "urn:nhsd:apim:app:level3:ambulance-analytics",
                ],
                [
                    "urn:nhsd:apim:user-nhs-login:P9:example-1",
                    "urn:nhsd:apim:app:level3:example-2",
                ],
                [
                    "urn:nhsd:apim:user-nhs-login:P9:personal-demographics-service",
                    "urn:nhsd:apim:user-nhs-login:P9:example-1",
                ],
                "nhs_login_separate",
                id="User-restricted-NHS-Login-seperate: multiple products with multiple scopes (valid and invalid)",
            ),
        ],
    )
    def test_valid_scope_combinations(
        self,
        product_1_scopes,
        product_2_scopes,
        expected_filtered_scopes,
        auth_pattern,
        test_app_and_products_for_scopes,
        nhsd_apim_proxy_url,
        products_api,
        access_token_api,
        token_data_client_credentials,
        token_data_token_exchange,
        _jwt_keys,
        cis2_subject_token_claims,
        nhs_login_id_token,
    ):
        app, products = test_app_and_products_for_scopes

        self.update_product_multiple_scope_sets(
            products_api_client=products_api,
            products=products,
            product_1_scopes=product_1_scopes,
            product_2_scopes=product_2_scopes,
        )

        if auth_pattern == "client_credentials":
            token_data = self.create_client_credentials_token_data(
                client_id=app["credentials"][0]["consumerKey"],
                identity_url=nhsd_apim_proxy_url,
                token_data=token_data_client_credentials,
                private_key=_jwt_keys["private_key_pem"],
            )
        elif auth_pattern in ["cis2_combined_aal3", "cis2_combined_aal2", "cis2_combined_aal1", "nhs_login_combined"]:
            token_data = self.create_authorization_code_token_data(
                client_id=app["credentials"][0]["consumerKey"],
                client_secret=app["credentials"][0]["consumerSecret"],
                callback_url=app["callbackUrl"],
                identity_url=nhsd_apim_proxy_url,
                auth_pattern=auth_pattern,
            )
        elif auth_pattern in ["cis2_seperate_aal3", "cis2_separate_aal2", "cis2_separate_aal1"]:
            auth_pattern_aal_map = {
                "cis2_separate_aal1": 1,
                "cis2_separate_aal2": 2,
                "cis2_seperate_aal3": 3,
            }

            cis2_subject_token_claims["authentication_assurance_level"] = auth_pattern_aal_map.get(auth_pattern)
            token_data = self.create_token_exchange_token_data(
                client_id=app["credentials"][0]["consumerKey"],
                identity_url=nhsd_apim_proxy_url,
                token_data=token_data_token_exchange,
                private_key=_jwt_keys["private_key_pem"],
                subject_token_claims=cis2_subject_token_claims,
            )
        elif auth_pattern == "nhs_login_separate":
            token_data = self.create_token_exchange_token_data(
                client_id=app["credentials"][0]["consumerKey"],
                identity_url=nhsd_apim_proxy_url,
                token_data=token_data_token_exchange,
                private_key=_jwt_keys["private_key_pem"],
                subject_token_claims=nhs_login_id_token,
                is_nhs_login=True,
            )
        else:
            raise Exception("auth_pattern not configured")

        resp = requests.post(
            nhsd_apim_proxy_url + "/token",
            headers={"Content-Type": "application/x-www-form-urlencoded"},
            data=token_data,
        )

        assert resp.status_code == 200
        body = resp.json()
        access_token = body["access_token"]

        # Compare scopes
        token_data = access_token_api.get_token_details(access_token)
        token_scopes = token_data["scope"].split(" ")

        assert sorted(token_scopes) == sorted(expected_filtered_scopes)

    @pytest.mark.happy_path
    @pytest.mark.parametrize(
        "external_scope,expected_scopes,auth_pattern",
        [
            pytest.param(
                "invalid_scope",
                ["urn:nhsd:apim:app:level3:personal-demographics"],
                "client_credentials",
                id="App-restricted: form param scope removed (not a real scope)",
            ),
            pytest.param(
                "$£$12vdg@@fd",
                ["urn:nhsd:apim:app:level3:personal-demographics"],
                "client_credentials",
                id="App-restricted: form param scope removed (special characters)",
            ),
            pytest.param(
                "   external  scope",
                ["urn:nhsd:apim:app:level3:personal-demographics"],
                "client_credentials",
                id="App-restricted: form param scope removed (white space)",
            ),
            pytest.param(
                [
                    "urn:nhsd:apim:user:aal3personal-demographics-service",
                    "urn:nhsd:apim:app:level3:example-2",
                ],
                ["urn:nhsd:apim:app:level3:personal-demographics"],
                "client_credentials",
                id="App-restricted: form param scope removed (invalid scopes)",
            ),
            pytest.param(
                "invalid_scope",
                ["urn:nhsd:apim:user-nhs-id:aal3:personal-demographics-service"],
                "cis2_combined_aal3",
                id="User-restricted-CIS2-combined: form param scope removed (not a real scope)",
            ),
            pytest.param(
                "$£$12vdg@@fd",
                ["urn:nhsd:apim:user-nhs-id:aal3:personal-demographics-service"],
                "cis2_combined_aal3",
                id="User-restricted-CIS2-combined: form param scope removed (special characters)",
            ),
            pytest.param(
                "   external  scope",
                ["urn:nhsd:apim:user-nhs-id:aal3:personal-demographics-service"],
                "cis2_combined_aal3",
                id="User-restricted-CIS2-combined: form param scope removed (white space)",
            ),
            pytest.param(
                [
                    "urn:nhsd:apim:user:aal3personal-demographics-service",
                    "urn:nhsd:apim:app:level3:example-2",
                ],
                ["urn:nhsd:apim:user-nhs-id:aal3:personal-demographics-service"],
                "cis2_combined_aal3",
                id="User-restricted-CIS2-combined: form param scope removed (invalid scopes)",
            ),
            pytest.param(
                "invalid_scope",
                ["urn:nhsd:apim:user-nhs-login:P9:personal-demographics-service"],
                "nhs_login_combined",
                id="User-restricted-NHS-Login-combined: form param scope removed (not a real scope)",
            ),
            pytest.param(
                "$£$12vdg@@fd",
                ["urn:nhsd:apim:user-nhs-login:P9:personal-demographics-service"],
                "nhs_login_combined",
                id="User-restricted-NHS-Login-combined: form param scope removed (special characters)",
            ),
            pytest.param(
                "   external  scope",
                ["urn:nhsd:apim:user-nhs-login:P9:personal-demographics-service"],
                "nhs_login_combined",
                id="User-restricted-NHS-Login-combined: form param scope removed (white space)",
            ),
            pytest.param(
                [
                    "urn:nhsd:apim:user:aal3personal-demographics-service",
                    "urn:nhsd:apim:app:level3:example-2",
                ],
                ["urn:nhsd:apim:user-nhs-login:P9:personal-demographics-service"],
                "nhs_login_combined",
                id="User-restricted-NHS-Login-combined: form param scope removed (invalid scopes)",
            ),
            pytest.param(
                "invalid_scope",
                ["urn:nhsd:apim:user-nhs-id:aal3:personal-demographics-service"],
                "cis2_seperate_aal3",
                id="User-restricted-CIS2-seperate: form param scope removed (not a real scope)",
            ),
            pytest.param(
                "$£$12vdg@@fd",
                ["urn:nhsd:apim:user-nhs-id:aal3:personal-demographics-service"],
                "cis2_seperate_aal3",
                id="User-restricted-CIS2-seperate: form param scope removed (special characters)",
            ),
            pytest.param(
                "   external  scope",
                ["urn:nhsd:apim:user-nhs-id:aal3:personal-demographics-service"],
                "cis2_seperate_aal3",
                id="User-restricted-CIS2-seperate: form param scope removed (white space)",
            ),
            pytest.param(
                [
                    "urn:nhsd:apim:user:aal3personal-demographics-service",
                    "urn:nhsd:apim:app:level3:example-2",
                ],
                ["urn:nhsd:apim:user-nhs-id:aal3:personal-demographics-service"],
                "cis2_seperate_aal3",
                id="User-restricted-CIS2-seperate: form param scope removed (invalid scopes)",
            ),
            pytest.param(
                "invalid_scope",
                ["urn:nhsd:apim:user-nhs-login:P9:personal-demographics-service"],
                "nhs_login_separate",
                id="User-restricted-NHS-Login-seperate: form param scope removed (not a real scope)",
            ),
            pytest.param(
                "$£$12vdg@@fd",
                ["urn:nhsd:apim:user-nhs-login:P9:personal-demographics-service"],
                "nhs_login_separate",
                id="User-restricted-NHS-Login-seperate: form param scope removed (special characters)",
            ),
            pytest.param(
                "   external  scope",
                ["urn:nhsd:apim:user-nhs-login:P9:personal-demographics-service"],
                "nhs_login_separate",
                id="User-restricted-NHS-Login-seperate: form param scope removed (white space)",
            ),
            pytest.param(
                [
                    "urn:nhsd:apim:user:aal3personal-demographics-service",
                    "urn:nhsd:apim:app:level3:example-2",
                ],
                ["urn:nhsd:apim:user-nhs-login:P9:personal-demographics-service"],
                "nhs_login_separate",
                id="User-restricted-NHS-Login-seperate: form param scope removed (invalid scopes)",
            ),
        ],
    )
    def test_flow_removes_external_scopes(
        self,
        external_scope,
        expected_scopes,
        auth_pattern,
        test_app_and_products_for_scopes,
        nhsd_apim_proxy_url,
        products_api,
        access_token_api,
        token_data_client_credentials,
        token_data_token_exchange,
        _jwt_keys,
        cis2_subject_token_claims,
        nhs_login_id_token,
    ):
        app, products = test_app_and_products_for_scopes

        self.update_product_single_scope_set(
            products_api_client=products_api, products=products, scopes=expected_scopes
        )

        if auth_pattern == "client_credentials":
            token_data = self.create_client_credentials_token_data(
                client_id=app["credentials"][0]["consumerKey"],
                identity_url=nhsd_apim_proxy_url,
                token_data=token_data_client_credentials,
                private_key=_jwt_keys["private_key_pem"],
            )
        elif auth_pattern == "cis2_combined_aal3" or auth_pattern == "nhs_login_combined":
            token_data = self.create_authorization_code_token_data(
                client_id=app["credentials"][0]["consumerKey"],
                client_secret=app["credentials"][0]["consumerSecret"],
                callback_url=app["callbackUrl"],
                identity_url=nhsd_apim_proxy_url,
                auth_pattern=auth_pattern,
            )
        elif auth_pattern == "cis2_seperate_aal3":
            token_data = self.create_token_exchange_token_data(
                client_id=app["credentials"][0]["consumerKey"],
                identity_url=nhsd_apim_proxy_url,
                token_data=token_data_token_exchange,
                private_key=_jwt_keys["private_key_pem"],
                subject_token_claims=cis2_subject_token_claims,
            )
        elif auth_pattern == "nhs_login_separate":
            token_data = self.create_token_exchange_token_data(
                client_id=app["credentials"][0]["consumerKey"],
                identity_url=nhsd_apim_proxy_url,
                token_data=token_data_token_exchange,
                private_key=_jwt_keys["private_key_pem"],
                subject_token_claims=nhs_login_id_token,
                is_nhs_login=True,
            )
        else:
            raise Exception("auth_pattern not configured")

        token_data["scope"] = external_scope

        resp = requests.post(
            nhsd_apim_proxy_url + "/token",
            headers={"Content-Type": "application/x-www-form-urlencoded"},
            data=token_data,
        )

        assert resp.status_code == 200
        body = resp.json()
        access_token = body["access_token"]

        # Compare scopes
        token_data = access_token_api.get_token_details(access_token)
        token_scopes = token_data["scope"].split(" ")

        assert token_scopes == expected_scopes

    @pytest.mark.errors
    @pytest.mark.parametrize(
        "product_1_scopes,product_2_scopes,auth_pattern",
        [
            pytest.param(
                [],
                [],
                "client_credentials",
                id="App-restricted: multiple products with no scopes",
            ),
            pytest.param(
                ["urn:nhsd:apim:user-nhs-id:aal2:personal-demographics-service"],
                [],
                "client_credentials",
                id="App-restricted: one product with user_restricted invalid scope, one product with no scope",
            ),
            pytest.param(
                ["urn:nhsd:apim:user-nhs-id:aal3:personal-demographics-service"],
                ["urn:nhsd:apim:user-nhs-id:aal3:ambulance-analytics"],
                "client_credentials",
                id="App-restricted: multiple products with invalid scopes",
            ),
            pytest.param(
                [
                    "urn:nhsd:apim:user-nhs-id:aal3:personal-demographics-service",
                    "urn:nhsd:apim:user-nhs-id:aal3:ambulance-analytics",
                ],
                [],
                "client_credentials",
                id="App-restricted: one product with multiple invalid scopes",
            ),
            pytest.param(
                [
                    "urn:nhsd:apim:user-nhs-id:aal3:personal-demographics-service",
                    "urn:nhsd:apim:user-nhs-id:aal3:ambulance-analytics",
                ],
                [
                    "urn:nhsd:apim:user-nhs-id:aal3:example-1",
                    "urn:nhsd:apim:user-nhs-id:aal3:example-2",
                ],
                "client_credentials",
                id="App-restricted: multiple products with multiple invalid scopes",
            ),
            pytest.param(
                ["ThisDoesNotExist"],
                [],
                "client_credentials",
                id="App-restricted: one product with invalid scope (wrong formation)",
            ),
            pytest.param(
                ["#£$?!&%*.;@~_-"],
                [],
                "client_credentials",
                id="App-restricted: one product with invalid scope (special caracters)",
            ),
            pytest.param(
                [""],
                [],
                "client_credentials",
                id="App-restricted: one product with invalid scope (empty string)",
            ),
            pytest.param(
                [None],
                [],
                "client_credentials",
                id="App-restricted: one product with invalid scope (None object)",
            ),
            pytest.param(
                ["urn:nshd:apim:app:level3personal-demographics-service"],
                [],
                "client_credentials",
                id="App-restricted: one product with invalid scope (missing colon)",
            ),
            pytest.param(
                [],
                [],
                "cis2_combined_aal3",
                id="User-restricted-CIS2-combined: multiple products with no scopes",
            ),
            pytest.param(
                ["urn:nhsd:apim:user-nhs-id:aal2:personal-demographics-service"],
                [],
                "cis2_combined_aal3",
                id="User-restricted-CIS2-combined: one product with invalid scope (authed as aal3 user), one product with no scope",
            ),
            pytest.param(
                ["urn:nhsd:apim:user-nhs-id:aal3:personal-demographics-service"],
                [],
                "cis2_combined_aal2",
                id="User-restricted-CIS2-combined: one product with invalid scope (authed as aal2 user), one product with no scope",
            ),
            pytest.param(
                ["urn:nhsd:apim:user-nhs-id:aal3:personal-demographics-service"],
                [],
                "cis2_combined_aal1",
                id="User-restricted-CIS2-combined: one product with invalid scope (authed as aal1 user), one product with no scope",
            ),
            pytest.param(
                ["urn:nhsd:apim:app:level3:personal-demographics-service"],
                ["urn:nhsd:apim:app:level3:ambulance-analytics"],
                "cis2_combined_aal3",
                id="User-restricted-CIS2-combined: multiple products with invalid scopes",
            ),
            pytest.param(
                [
                    "urn:nhsd:apim:app:level3:personal-demographics-service",
                    "urn:nhsd:apim:app:level3:ambulance-analytics",
                ],
                [],
                "cis2_combined_aal3",
                id="User-restricted-CIS2-combined: one product with multiple invalid scopes",
            ),
            pytest.param(
                [
                    "urn:nhsd:apim:app:level3:personal-demographics-service",
                    "urn:nhsd:apim:app:level3:ambulance-analytics",
                ],
                [
                    "urn:nhsd:apim:app:level3:example-1",
                    "urn:nhsd:apim:app:level3:example-2",
                ],
                "cis2_combined_aal3",
                id="User-restricted-CIS2-combined: multiple products with multiple invalid scopes",
            ),
            pytest.param(
                ["ThisDoesNotExist"],
                [],
                "cis2_combined_aal3",
                id="User-restricted-CIS2-combined: one product with invalid scope (wrong formation)",
            ),
            pytest.param(
                ["#£$?!&%*.;@~_-"],
                [],
                "cis2_combined_aal3",
                id="User-restricted-CIS2-combined: one product with invalid scope (special characters)",
            ),
            pytest.param(
                [""],
                [],
                "cis2_combined_aal3",
                id="User-restricted-CIS2-combined: one product with invalid scope (empty string)",
            ),
            pytest.param(
                [None],
                [],
                "cis2_combined_aal3",
                id="User-restricted-CIS2-combined: one product with invalid scope (None object)",
            ),
            pytest.param(
                ["urn:nhsd:apim:user:aal3personal-demographics-service"],
                [],
                "cis2_combined_aal3",
                id="User-restricted-CIS2-combined: one product with invalid scope (missing colon), one product with no scope",
            ),
            pytest.param(
                [],
                [],
                "nhs_login_combined",
                id="User-restricted-NHS-Login-combined: multiple products with no scopes",
            ),
            pytest.param(
                ["urn:nhsd:apim:user-nhs-login:P0:personal-demographics-service"],
                [],
                "nhs_login_combined",
                id="User-restricted-NHS-Login-combined: one product with invalid scope, one product with no scope",
            ),
            pytest.param(
                ["urn:nhsd:apim:app:level3:personal-demographics-service"],
                ["urn:nhsd:apim:app:level3:ambulance-analytics"],
                "nhs_login_combined",
                id="User-restricted-NHS-Login-combined: multiple products with invalid scopes",
            ),
            pytest.param(
                [
                    "urn:nhsd:apim:app:level3:personal-demographics-service",
                    "urn:nhsd:apim:app:level3:ambulance-analytics",
                ],
                [],
                "nhs_login_combined",
                id="User-restricted-NHS-Login-combined: one product with multiple invalid scopes",
            ),
            pytest.param(
                [
                    "urn:nhsd:apim:app:level3:personal-demographics-service",
                    "urn:nhsd:apim:app:level3:ambulance-analytics",
                ],
                [
                    "urn:nhsd:apim:app:level3:example-1",
                    "urn:nhsd:apim:app:level3:example-2",
                ],
                "nhs_login_combined",
                id="User-restricted-NHS-Login-combined: multiple products with multiple invalid scopes",
            ),
            pytest.param(
                ["ThisDoesNotExist"],
                [],
                "nhs_login_combined",
                id="User-restricted-NHS-Login-combined: one product with invalid scope (wrong formation)",
            ),
            pytest.param(
                ["#£$?!&%*.;@~_-"],
                [],
                "nhs_login_combined",
                id="User-restricted-NHS-Login-combined: one product with invalid scope (special characters)",
            ),
            pytest.param(
                [""],
                [],
                "nhs_login_combined",
                id="User-restricted-NHS-Login-combined: one product with invalid scope (empty string)",
            ),
            pytest.param(
                [None],
                [],
                "nhs_login_combined",
                id="User-restricted-NHS-Login-combined: one product with invalid scope (None object)",
            ),
            pytest.param(
                ["urn:nhsd:apim:user-nhs-login:P0personal-demographics-service"],
                [],
                "nhs_login_combined",
                id="User-restricted-NHS-Login-combined: one product with invalid scope (missing colon), one product with no scope",
            ),
            pytest.param(
                [],
                [],
                "cis2_seperate_aal3",
                id="User-restricted-CIS2-seperate: multiple products with no scopes",
            ),
            pytest.param(
                ["urn:nhsd:apim:user-nhs-id:aal2:personal-demographics-service"],
                [],
                "cis2_seperate_aal3",
                id="User-restricted-CIS2-seperate: one product with invalid scope (authed as aal3 user), one product with no scope",
            ),
            pytest.param(
                ["urn:nhsd:apim:user-nhs-id:aal3:personal-demographics-service"],
                [],
                "cis2_separate_aal2",
                id="User-restricted-CIS2-separate: one product with invalid scope (authed as aal2 user), one product with no scope",
            ),
            pytest.param(
                ["urn:nhsd:apim:user-nhs-id:aal3:personal-demographics-service"],
                [],
                "cis2_separate_aal1",
                id="User-restricted-CIS2-separate: one product with invalid scope (authed as aal1 user), one product with no scope",
            ),
            pytest.param(
                ["urn:nhsd:apim:app:level3:personal-demographics-service"],
                ["urn:nhsd:apim:app:level3:ambulance-analytics"],
                "cis2_seperate_aal3",
                id="User-restricted-CIS2-seperate: multiple products with invalid scopes",
            ),
            pytest.param(
                [
                    "urn:nhsd:apim:app:level3:personal-demographics-service",
                    "urn:nhsd:apim:app:level3:ambulance-analytics",
                ],
                [],
                "cis2_seperate_aal3",
                id="User-restricted-CIS2-seperate: one product with multiple invalid scopes",
            ),
            pytest.param(
                [
                    "urn:nhsd:apim:app:level3:personal-demographics-service",
                    "urn:nhsd:apim:app:level3:ambulance-analytics",
                ],
                [
                    "urn:nhsd:apim:app:level3:example-1",
                    "urn:nhsd:apim:app:level3:example-2",
                ],
                "cis2_seperate_aal3",
                id="User-restricted-CIS2-seperate: multiple products with multiple invalid scopes",
            ),
            pytest.param(
                ["ThisDoesNotExist"],
                [],
                "cis2_seperate_aal3",
                id="User-restricted-CIS2-seperate: one product with invalid scope (wrong formation)",
            ),
            pytest.param(
                ["#£$?!&%*.;@~_-"],
                [],
                "cis2_seperate_aal3",
                id="User-restricted-CIS2-seperate: one product with invalid scope (special characters)",
            ),
            pytest.param(
                [""],
                [],
                "cis2_seperate_aal3",
                id="User-restricted-CIS2-seperate: one product with invalid scope (empty string)",
            ),
            pytest.param(
                [None],
                [],
                "cis2_seperate_aal3",
                id="User-restricted-CIS2-seperate: one product with invalid scope (None object)",
            ),
            pytest.param(
                ["urn:nhsd:apim:user:aal3personal-demographics-service"],
                [],
                "cis2_seperate_aal3",
                id="User-restricted-CIS2-seperate: one product with invalid scope (missing colon), one product with no scope",
            ),
            pytest.param(
                [],
                [],
                "nhs_login_separate",
                id="User-restricted-NHS-Login-seperate: multiple products with no scopes",
            ),
            pytest.param(
                ["urn:nhsd:apim:user-nhs-login:P0:personal-demographics-service"],
                [],
                "nhs_login_separate",
                id="User-restricted-NHS-Login-seperate: one product with invalid scope, one product with no scope",
            ),
            pytest.param(
                ["urn:nhsd:apim:app:level3:personal-demographics-service"],
                ["urn:nhsd:apim:app:level3:ambulance-analytics"],
                "nhs_login_separate",
                id="User-restricted-NHS-Login-seperate: multiple products with invalid scopes",
            ),
            pytest.param(
                [
                    "urn:nhsd:apim:app:level3:personal-demographics-service",
                    "urn:nhsd:apim:app:level3:ambulance-analytics",
                ],
                [],
                "nhs_login_separate",
                id="User-restricted-NHS-Login-seperate: one product with multiple invalid scopes",
            ),
            pytest.param(
                [
                    "urn:nhsd:apim:app:level3:personal-demographics-service",
                    "urn:nhsd:apim:app:level3:ambulance-analytics",
                ],
                [
                    "urn:nhsd:apim:app:level3:example-1",
                    "urn:nhsd:apim:app:level3:example-2",
                ],
                "nhs_login_separate",
                id="User-restricted-NHS-Login-seperate: multiple products with multiple invalid scopes",
            ),
            pytest.param(
                ["ThisDoesNotExist"],
                [],
                "nhs_login_separate",
                id="User-restricted-NHS-Login-seperate: one product with invalid scope (wrong formation)",
            ),
            pytest.param(
                ["#£$?!&%*.;@~_-"],
                [],
                "nhs_login_separate",
                id="User-restricted-NHS-Login-seperate: one product with invalid scope (special characters)",
            ),
            pytest.param(
                [""],
                [],
                "nhs_login_separate",
                id="User-restricted-NHS-Login-seperate: one product with invalid scope (empty string)",
            ),
            pytest.param(
                [None],
                [],
                "nhs_login_separate",
                id="User-restricted-NHS-Login-seperate: one product with invalid scope (None object)",
            ),
            pytest.param(
                ["urn:nhsd:apim:user-nhs-login:P0personal-demographics-service"],
                [],
                "nhs_login_separate",
                id="User-restricted-NHS-Login-seperate: one product with invalid scope, one product with no scope",
            ),
        ],
    )
    def test_scope_combination_errors(
        self,
        product_1_scopes,
        product_2_scopes,
        auth_pattern,
        test_app_and_products_for_scopes,
        nhsd_apim_proxy_url,
        products_api,
        token_data_client_credentials,
        token_data_token_exchange,
        _jwt_keys,
        cis2_subject_token_claims,
        nhs_login_id_token,
        trace,
    ):
        app, products = test_app_and_products_for_scopes

        self.update_product_multiple_scope_sets(
            products_api_client=products_api,
            products=products,
            product_1_scopes=product_1_scopes,
            product_2_scopes=product_2_scopes,
        )

        if auth_pattern == "client_credentials":
            token_data = self.create_client_credentials_token_data(
                client_id=app["credentials"][0]["consumerKey"],
                identity_url=nhsd_apim_proxy_url,
                token_data=token_data_client_credentials,
                private_key=_jwt_keys["private_key_pem"],
            )
            resp = requests.post(
                nhsd_apim_proxy_url + "/token",
                headers={"Content-Type": "application/x-www-form-urlencoded"},
                data=token_data,
            )
            status_code = resp.status_code
            error_content = resp.json()

        elif auth_pattern in ["cis2_combined_aal3", "cis2_combined_aal2", "cis2_combined_aal1", "nhs_login_combined"]:
            # Set up trace
            session_name = str(uuid4())
            header_filters = {"trace_id": session_name}
            trace.post_debugsession(session=session_name, header_filters=header_filters)

            self.hit_authorize_and_callback_endpoints(
                client_id=app["credentials"][0]["consumerKey"],
                callback_url=app["callbackUrl"],
                identity_url=nhsd_apim_proxy_url,
                auth_pattern=auth_pattern,
                header_filters=header_filters,
            )
            # Get variables from trace
            status_code = get_variable_from_trace(
                trace, session_name, "error.status.code"
            )
            error_content = get_variable_from_trace(
                trace, session_name, "error.content"
            )

            trace.delete_debugsession_by_name(session_name)

        elif auth_pattern in ["cis2_seperate_aal3", "cis2_separate_aal2", "cis2_separate_aal1"]:
            auth_pattern_aal_map = {
                "cis2_separate_aal1": 1,
                "cis2_separate_aal2": 2,
                "cis2_seperate_aal3": 3,
            }

            cis2_subject_token_claims["authentication_assurance_level"] = auth_pattern_aal_map.get(auth_pattern)
            token_data = self.create_token_exchange_token_data(
                client_id=app["credentials"][0]["consumerKey"],
                identity_url=nhsd_apim_proxy_url,
                token_data=token_data_token_exchange,
                private_key=_jwt_keys["private_key_pem"],
                subject_token_claims=cis2_subject_token_claims,
            )
            resp = requests.post(
                nhsd_apim_proxy_url + "/token",
                headers={"Content-Type": "application/x-www-form-urlencoded"},
                data=token_data,
            )
            status_code = resp.status_code
            error_content = resp.json()

        elif auth_pattern == "nhs_login_separate":
            token_data = self.create_token_exchange_token_data(
                client_id=app["credentials"][0]["consumerKey"],
                identity_url=nhsd_apim_proxy_url,
                token_data=token_data_token_exchange,
                private_key=_jwt_keys["private_key_pem"],
                subject_token_claims=nhs_login_id_token,
                is_nhs_login=True,
            )
            resp = requests.post(
                nhsd_apim_proxy_url + "/token",
                headers={"Content-Type": "application/x-www-form-urlencoded"},
                data=token_data,
            )
            status_code = resp.status_code
            error_content = resp.json()

        else:
            raise Exception("auth_pattern not configured")

        assert status_code == 401
        assert (
            "message_id" in error_content.keys()
        )  # We assert the key but not he value for message_id
        del error_content["message_id"]
        assert error_content == {
            "error": "unauthorized_client",
            "error_description": "you have tried to request authorization but your "
            "application is not configured to use this authorization grant type",
        }
