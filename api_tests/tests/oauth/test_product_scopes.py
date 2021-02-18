from api_tests.config_files import config
import pytest
import random
from api_test_utils.apigee_api_apps import ApigeeApiDeveloperApps
from api_test_utils.apigee_api_products import ApigeeApiProducts
from api_test_utils.oauth_helper import OauthHelper


@pytest.mark.asyncio
class TestProductScopes:
    @pytest.fixture()
    async def test_app_and_product(self):
        apigee_product = ApigeeApiProducts()
        apigee_product2 = ApigeeApiProducts()
        await apigee_product.create_new_product()
        await apigee_product.update_proxies([config.SERVICE_NAME])
        await apigee_product2.create_new_product()
        await apigee_product2.update_proxies([config.SERVICE_NAME])

        apigee_app = ApigeeApiDeveloperApps()
        await apigee_app.create_new_app()

        # Set default JWT Testing resource url
        await apigee_app.set_custom_attributes(
            {
                'jwks-resource-url': 'https://raw.githubusercontent.com/NHSDigital/'
                                     'identity-service-jwks/main/jwks/internal-dev/'
                                     '9baed6f4-1361-4a8e-8531-1f8426e3aba8.json'
            }
        )

        await apigee_app.add_api_product(
            api_products=[
                apigee_product.name,
                apigee_product2.name
            ]
        )

        [await product.update_ratelimits(
            quota=60000,
            quota_interval="1",
            quota_time_unit="minute",
            rate_limit="1000ps"
        ) for product in [apigee_product, apigee_product2]]

        yield apigee_product, apigee_product2, apigee_app

        await apigee_app.destroy_app()
        await apigee_product.destroy_product()
        await apigee_product2.destroy_product()

    @pytest.mark.apm_1701
    @pytest.mark.happy_path
    @pytest.mark.asyncio
    @pytest.mark.parametrize('product_1_scopes, product_2_scopes', [
        # Scenario 1: one product with valid scope
        (
            ['urn:nhsd:apim:app:level3:personal-demographics'],
            []
        ),
        # Scenario 2: one product with valid scope, one product with invalid scope
        (
            ['urn:nhsd:apim:app:level3:personal-demographics-service'],
            ['urn:nhsd:apim:user-nhs-id:aal3:personal-demographics-service']
        ),
        # Scenario 3: multiple products with valid scopes
        (
            ['urn:nhsd:apim:app:level3:personal-demographics-service'],
            ['urn:nhsd:apim:app:level3:ambulance-analytics']
        ),
        # Scenario 4: one product with multiple valid scopes
        (
            ['urn:nhsd:apim:app:level3:personal-demographics', 'urn:nhsd:apim:app:level3:ambulance-analytics'],
            []
        ),
        # Scenario 5: multiple products with multiple valid scopes
        (
            ['urn:nhsd:apim:app:level3:personal-demographics', 'urn:nhsd:apim:app:level3:ambulance-analytics'],
            ['urn:nhsd:apim:app:level3:example-1', 'urn:nhsd:apim:app:level3:example-2']
        ),
        # Scenario 6: one product with multiple scopes (valid and invalid)
        (
            ['urn:nhsd:apim:app:level3:ambulance-analytics',
            'urn:nhsd:apim:user-nhs-id:aal3:personal-demographics-service'],
            []
        ),
        # Scenario 7: multiple products with multiple scopes (valid and invalid)
        (
            ['urn:nhsd:apim:app:level3:ambulance-analytics',
            'urn:nhsd:apim:user-nhs-id:aal3:personal-demographics-service'],
            ['urn:nhsd:apim:app:level3:example-1', 'urn:nhsd:apim:user-nhs-id:aal3:example-2']
        ),
        # Scenario 8: one product with valid scope with trailing and leading spaces
        (
            [' urn:nhsd:apim:app:level3:ambulance-analytics '],
            []
        ),
    ])
    async def test_valid_application_restricted_scope_combination(
        self,
        product_1_scopes,
        product_2_scopes,
        test_app_and_product,
    ):
        test_product, test_product2, test_app = test_app_and_product

        await test_product.update_scopes(product_1_scopes)
        await test_product2.update_scopes(product_2_scopes)

        jwt = self.oauth.create_jwt(kid='test-1', client_id=test_app.client_id)
        resp = await self.oauth.get_token_response(grant_type="client_credentials", _jwt=jwt)

        assert list(resp['body'].keys()) == ['access_token', 'expires_in', 'token_type']
        assert resp['status_code'] == 200

    @pytest.mark.apm_1701
    @pytest.mark.errors
    @pytest.mark.asyncio
    @pytest.mark.parametrize('product_1_scopes, product_2_scopes', [
        # Scenario 1: multiple products with no scopes
        (
            [],
            []
        ),
        # Scenario 2: one product with invalid scope, one product with no scope
        (
            ['urn:nhsd:apim:user-nhs-id:aal2:personal-demographics-service'],
            []
        ),
        # Scenario 3: multiple products with invalid scopes
        (
            ['urn:nhsd:apim:user-nhs-id:aal3:personal-demographics-service'],
            ['urn:nhsd:apim:user-nhs-id:aal3:ambulance-analytics']
        ),
        # Scenario 4: one product with multiple invalid scopes
        (
            ['urn:nhsd:apim:user-nhs-id:aal3:personal-demographics-service',
            'urn:nhsd:apim:user-nhs-id:aal3:ambulance-analytics'],
            []
        ),
        # Scenario 5: multiple products with multiple invalid scopes
        (
            ['urn:nhsd:apim:user-nhs-id:aal3:personal-demographics-service',
            'urn:nhsd:apim:user-nhs-id:aal3:ambulance-analytics'],
            ['urn:nhsd:apim:user-nhs-id:aal3:example-1', 'urn:nhsd:apim:user-nhs-id:aal3:example-2']
        ),
        # Scenario 6: one product with invalid scope (wrong formation)
        (
            ['ThisDoesNotExist'],
            []
        ),
        # Scenario 7: one product with invalid scope (special caracters)
        (
            ['#£$?!&%*.;@~_-'],
            []
        ),
        # Scenario 8: one product with invalid scope (empty string)
        (
            [""],
            []
        ),
        # Scenario 8: one product with invalid scope (None object)
        (
            [None],
            []
        ),
        # Scenario 9: one product with invalid scope (missing colon)
        (
            ['urn:nshd:apim:app:level3personal-demographics-service'],
            []
        )
    ])
    async def test_error_application_restricted_scope_combination(
        self,
        product_1_scopes,
        product_2_scopes,
        test_app_and_product
    ):
        test_product, test_product2, test_app = test_app_and_product

        await test_product.update_scopes(product_1_scopes)
        await test_product2.update_scopes(product_2_scopes)

        resp = await self.oauth.get_token_response(
            grant_type="client_credentials",
            _jwt=self.oauth.create_jwt(kid='test-1', client_id=test_app.client_id)
        )

        assert resp['status_code'] == 401
        assert resp['body'] == {
            "error": "unauthorized_client",
            "error_description": "you have tried to requests authorization but your "
                                 "application is not configured to use this authorization grant type",
        }

    @pytest.mark.apm_1701
    @pytest.mark.happy_path
    @pytest.mark.asyncio
    @pytest.mark.parametrize('product_1_scopes, product_2_scopes', [
        # Scenario 1: one product with valid scope
        (
            ['urn:nhsd:apim:user-nhs-id:aal3:personal-demographics-service'],
            []
        ),
        # Scenario 2: one product with valid scope, one product with invalid scope
        (
            ['urn:nhsd:apim:user-nhs-id:aal3:personal-demographics-service'],
            ['urn:nhsd:apim:app:level3:ambulance-analytics']
        ),
        # Scenario 3: multiple products with valid scopes
        (
            ['urn:nhsd:apim:user-nhs-id:aal3:personal-demographics-service'],
            ['urn:nhsd:apim:user-nhs-id:aal3:ambulance-analytics']
        ),
        # Scenario 4: one product with multiple valid scopes
        (
            ['urn:nhsd:apim:user-nhs-id:aal3:personal-demographics-service',
             'urn:nhsd:apim:user-nhs-id:aal3:ambulance-analytics'],
            []
        ),
        # Scenario 5: multiple products with multiple valid scopes
        (
            ['urn:nhsd:apim:user-nhs-id:aal3:personal-demographics-service',
             'urn:nhsd:apim:user-nhs-id:aal3:ambulance-analytics'],
            ['urn:nhsd:apim:user-nhs-id:aal3:example-1', 'urn:nhsd:apim:user-nhs-id:aal3:example-2']
        ),
        # Scenario 6: one product with multiple scopes (valid and invalid)
        (
            ['urn:nhsd:apim:user-nhs-id:aal3:personal-demographics-service',
             'urn:nhsd:apim:app:level3:ambulance-analytics'],
            []
        ),
        # Scenario 7: multiple products with multiple scopes (valid and invalid)
        (
            ['urn:nhsd:apim:user-nhs-id:aal3:personal-demographics-service',
             'urn:nhsd:apim:app:level3:ambulance-analytics'],
            ['urn:nhsd:apim:user-nhs-id:aal3:example-1', 'urn:nhsd:apim:app:level3:example-2']
        ),
        # Scenario 8: one product with valid scope with trailing and leading spaces
        (
            [' urn:nhsd:apim:user-nhs-id:aal3:personal-demographics-service '],
            []
        ),
    ])
    async def test_user_restricted_scope_combination(
        self,
        product_1_scopes,
        product_2_scopes,
        test_app_and_product,
        helper
    ):
        test_product, test_product2, test_app = test_app_and_product

        await test_product.update_scopes(product_1_scopes)
        await test_product2.update_scopes(product_2_scopes)

        callback_url = await test_app.get_callback_url()

        oauth = OauthHelper(test_app.client_id, test_app.client_secret, callback_url)

        assert helper.check_endpoint(
            verb="POST",
            endpoint=config.TOKEN_URL,
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
                "code": await oauth.get_authenticated_with_simulated_auth(),
            },
        )

    @pytest.mark.apm_1701
    @pytest.mark.errors
    @pytest.mark.asyncio
    @pytest.mark.parametrize('product_1_scopes, product_2_scopes', [
        # Scenario 1: multiple products with no scopes
        (
            [],
            []
        ),
        # Scenario 2: one product with invalid scope, one product with no scope
        (
            ['urn:nhsd:apim:user-nhs-id:aal2:personal-demographics-service'],
            []
        ),
        # Scenario 3: multiple products with invalid scopes
        (
            ['urn:nhsd:apim:app:level3:personal-demographics-service'],
            ['urn:nhsd:apim:app:level3:ambulance-analytics']
        ),
        # Scenario 4: one product with multiple invalid scopes
        (
            ['urn:nhsd:apim:app:level3:personal-demographics-service', 'urn:nhsd:apim:app:level3:ambulance-analytics'],
            []
        ),
        # Scenario 5: multiple products with multiple invalid scopes
        (
            ['urn:nhsd:apim:app:level3:personal-demographics-service', 'urn:nhsd:apim:app:level3:ambulance-analytics'],
            ['urn:nhsd:apim:app:level3:example-1', 'urn:nhsd:apim:app:level3:example-2']
        ),
        # Scenario 6: one product with invalid scope (wrong formation)
        (
            ['ThisDoesNotExist'],
            []
        ),
        # Scenario 7: one product with invalid scope (special characters)
        (
            ['#£$?!&%*.;@~_-'],
            []
        ),
        # Scenario 8: one product with invalid scope (empty string)
        (
            [""],
            []
        ),
        # Scenario 8: one product with invalid scope (None object)
        (
            [None],
            []
        ),
        # Scenario 9: one product with invalid scope, one product with no scope
        (
            ['urn:nhsd:apim:user:aal3personal-demographics-service'],
            []
        ),
    ])
    async def test_error_user_restricted_scope_combination(
        self,
        product_1_scopes,
        product_2_scopes,
        test_app_and_product,
        helper
    ):
        test_product, test_product2, test_app = test_app_and_product

        await test_product.update_scopes(product_1_scopes)
        await test_product2.update_scopes(product_2_scopes)

        callback_url = await test_app.get_callback_url()

        assert helper.check_endpoint(
            verb="GET",
            endpoint=f"{config.OAUTH_BASE_URI}/{config.OAUTH_PROXY}/authorize",
            expected_status_code=401,
            expected_response={
                "error": "unauthorized_client",
                "error_description": "you have tried to requests authorization but "
                                     "your application is not configured to use this authorization grant type"
            },
            params={
                "client_id": test_app.get_client_id(),
                "redirect_uri": callback_url,
                "response_type": "code",
                "state": random.getrandbits(32)
            },
        )
