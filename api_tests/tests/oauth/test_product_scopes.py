from api_tests.scripts import config
import pytest
from api_test_utils.apigee_api_apps import ApigeeApiDeveloperApps
from api_test_utils.apigee_api_products import ApigeeApiProducts
from api_test_utils.oauth_helper import OauthHelper
import random
import requests
import jwt
from uuid import uuid4
from time import time, sleep
import json


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

        assert list(resp['body'].keys()) == ['access_token', 'expires_in', 'token_type', 'issued_at']
        assert resp['status_code'] == 200

    @pytest.mark.apm_1701
    @pytest.mark.errors
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
            endpoint=f"{config.OAUTH_URL}/token",
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

        # Given
        expected_status_code = 401
        expected_error = 'unauthorized_client'
        expected_error_description = 'you have tried to requests authorization but your application is not configured to use this authorization grant type'

        # When
        await test_product.update_scopes(product_1_scopes)
        await test_product2.update_scopes(product_2_scopes)

        callback_url = await test_app.get_callback_url()

        response = await self.oauth.hit_oauth_endpoint(
            method="GET",
            endpoint="authorize",
            params={
                "client_id": test_app.get_client_id(),
                "redirect_uri": callback_url,
                "response_type": "code",
                "state": "1234567890",
            },
            allow_redirects=False,
        )

        state = helper.get_param_from_url(
            url=response["headers"]["Location"], param="state"
        )

        # Make simulated auth request to authenticate
        response = await self.oauth.hit_oauth_endpoint(
            method="POST",
            endpoint="simulated_auth",
            params={
                "response_type": "code",
                "client_id": test_app.get_client_id(),
                "redirect_uri": callback_url,
                "scope": "openid",
                "state": state,
            },
            headers={"Content-Type": "application/x-www-form-urlencoded"},
            data={"state": state},
            allow_redirects=False,
        )

        # # Make initial callback request
        auth_code = helper.get_param_from_url(
            url=response["headers"]["Location"], param="code"
        )

        response = await self.oauth.hit_oauth_endpoint(
            method="GET",
            endpoint="callback",
            params={"code": auth_code, "client_id": "some-client-id", "state": state},
            allow_redirects=False,
        )

        # Then
        assert expected_status_code == response['status_code']
        assert expected_error == response['body']['error']
        assert expected_error_description == response['body']['error_description']


    @pytest.mark.token_exchange
    @pytest.mark.errors
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
    async def test_token_exchange_error_user_restricted_scope_combination(
        self,
        product_1_scopes,
        product_2_scopes,
        test_app_and_product,
        helper
    ):
        expected_status_code = 401
        expected_error = 'unauthorized_client'
        expected_error_description = "you have tried to requests authorization but your " \
                                     "application is not configured to use this authorization grant type"

        test_product, test_product2, test_app = test_app_and_product

        await test_product.update_scopes(product_1_scopes)
        await test_product2.update_scopes(product_2_scopes)

        id_token_claims = {
            'at_hash': 'tf_-lqpq36lwO7WmSBIJ6Q',
            'sub': '787807429511',
            'auditTrackingId': '91f694e6-3749-42fd-90b0-c3134b0d98f6-1546391',
            'amr': ['N3_SMARTCARD'],
            'iss': 'https://am.nhsint.auth-ptl.cis2.spineservices.nhs.uk:443'
                   '/openam/oauth2/realms/root/realms/NHSIdentity/realms/Healthcare',
            'tokenName': 'id_token',
            'aud': '969567331415.apps.national',
            'c_hash': 'bc7zzGkClC3MEiFQ3YhPKg',
            'acr': 'AAL3_ANY',
            'org.forgerock.openidconnect.ops': '-I45NjmMDdMa-aNF2sr9hC7qEGQ',
            's_hash': 'LPJNul-wow4m6Dsqxbning',
            'azp': '969567331415.apps.national',
            'auth_time': 1610559802,
            'realm': '/NHSIdentity/Healthcare',
            'exp': int(time()) + 6000,
            'tokenType': 'JWTToken',
            'iat': int(time()) - 100
        }

        client_assertion_jwt = self.oauth.create_jwt(kid="test-1", client_id=test_app.client_id)
        id_token_jwt = self.oauth.create_id_token_jwt(kid="identity-service-tests-1", claims=id_token_claims)

        # When
        resp = await self.oauth.get_token_response(
            grant_type="token_exchange",
            data={
                'grant_type': 'urn:ietf:params:oauth:grant-type:token-exchange',
                'subject_token_type': 'urn:ietf:params:oauth:token-type:id_token',
                'client_assertion_type': 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer',
                'subject_token': id_token_jwt,
                'client_assertion': client_assertion_jwt
            }
        )

        # Then
        assert expected_status_code == resp['status_code']
        assert expected_error == resp['body']['error']
        assert expected_error_description == resp['body']['error_description']

    @pytest.mark.token_exchange
    @pytest.mark.errors
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
    async def test_cis2_token_exchange_user_restricted_scope_combination(
        self,
        product_1_scopes,
        product_2_scopes,
        test_app_and_product,
        helper
    ):
        expected_status_code = 200
        expected_expires_in = '599'
        expected_token_type = 'Bearer'
        expected_issued_token_type = 'urn:ietf:params:oauth:token-type:access_token'

        test_product, test_product2, test_app = test_app_and_product

        await test_product.update_scopes(product_1_scopes)
        await test_product2.update_scopes(product_2_scopes)

        id_token_claims = {
            'at_hash': 'tf_-lqpq36lwO7WmSBIJ6Q',
            'sub': '787807429511',
            'auditTrackingId': '91f694e6-3749-42fd-90b0-c3134b0d98f6-1546391',
            'amr': ['N3_SMARTCARD'],
            'iss': 'https://am.nhsint.auth-ptl.cis2.spineservices.nhs.uk:443'
                   '/openam/oauth2/realms/root/realms/NHSIdentity/realms/Healthcare',
            'tokenName': 'id_token',
            'aud': '969567331415.apps.national',
            'c_hash': 'bc7zzGkClC3MEiFQ3YhPKg',
            'acr': 'AAL3_ANY',
            'org.forgerock.openidconnect.ops': '-I45NjmMDdMa-aNF2sr9hC7qEGQ',
            's_hash': 'LPJNul-wow4m6Dsqxbning',
            'azp': '969567331415.apps.national',
            'auth_time': 1610559802,
            'realm': '/NHSIdentity/Healthcare',
            'exp': int(time()) + 6000,
            'tokenType': 'JWTToken',
            'iat': int(time()) - 100
        }

        client_assertion_jwt = self.oauth.create_jwt(kid="test-1", client_id=test_app.client_id)
        id_token_jwt = self.oauth.create_id_token_jwt(kid="identity-service-tests-1", claims=id_token_claims)

        # When
        resp = await self.oauth.get_token_response(
            grant_type="token_exchange",
            data={
                'grant_type': 'urn:ietf:params:oauth:grant-type:token-exchange',
                'subject_token_type': 'urn:ietf:params:oauth:token-type:id_token',
                'client_assertion_type': 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer',
                'subject_token': id_token_jwt,
                'client_assertion': client_assertion_jwt
            }
        )

        # Then
        assert expected_status_code == resp['status_code'], resp['body']
        assert 'access_token' in resp['body']
        assert expected_expires_in == resp['body']['expires_in']
        assert expected_token_type == resp['body']['token_type']
        assert expected_issued_token_type == resp['body']['issued_token_type']

    @pytest.mark.parametrize('external_scope', [
        # passing in external scopes via form params
        'invavlid scope',
        '$£$12vdg@@fd',
        '   external  scope',
        ['urn:nhsd:apim:user:aal3personal-demographics-service', 'urn:nhsd:apim:app:level3:example-2']
    ])
    async def test_client_credentials_flow_remove_external_scopes(self, test_app_and_product, external_scope):
        product_scope = ['urn:nhsd:apim:app:level3:personal-demographics']
        test_product, test_product2, test_app = test_app_and_product

        await test_product.update_scopes(product_scope)
        await test_product2.update_scopes(product_scope)

        jwt = self.oauth.create_jwt(kid='test-1', client_id=test_app.client_id)

        data = {
            'scope': external_scope,
            'grant_type': 'client_credentials',
            'client_assertion_type': 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer',
            'client_assertion': jwt,
        }

        resp = await self.oauth.get_token_response(grant_type="client_credentials", data=data)

        assert list(resp['body'].keys()) == ['access_token', 'expires_in', 'token_type', 'issued_at']
        assert resp['status_code'] == 200

    @pytest.mark.parametrize('external_scope', [
        # passing in external scopes via form params
        'invavlid scope',
        '$£$12vdg@@fd',
        '   external  scope',
        ['urn:nhsd:apim:user:aal3personal-demographics-service', 'urn:nhsd:apim:app:level3:example-2']
    ])    
    async def test_token_exchange_remove_external_scopes(self, test_app_and_product, external_scope):
        client_assertion_jwt = self.oauth.create_jwt(kid='test-1')
        id_token_jwt = self.oauth.create_id_token_jwt()

        data = {
            'scope': external_scope,
            'grant_type': 'urn:ietf:params:oauth:grant-type:token-exchange',
            'subject_token_type': 'urn:ietf:params:oauth:token-type:id_token',
            'client_assertion_type': 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer',
            'subject_token': id_token_jwt,
            'client_assertion': client_assertion_jwt
        }

        resp = await self.oauth.get_token_response(
            grant_type="token_exchange",
            data=data
        )

        assert resp['status_code'] == 200

    @pytest.mark.parametrize('external_scope', [
        # passing in external scopes via form params
        'invavlid scope',
        '$£$12vdg@@fd',
        '   external  scope',
        ['urn:nhsd:apim:user:aal3personal-demographics-service', 'urn:nhsd:apim:app:level3:example-2']
    ])    
    async def test_authorization_code_flow_remove_external_scopes(self, test_app_and_product, helper, external_scope):
        product_scope=['urn:nhsd:apim:user-nhs-id:aal3:personal-demographics-service']
        test_product, test_product2, test_app = test_app_and_product

        await test_product.update_scopes(product_scope)
        await test_product2.update_scopes(product_scope)

        callback_url = await test_app.get_callback_url()

        oauth = OauthHelper(test_app.client_id, test_app.client_secret, callback_url)

        assert helper.check_endpoint(
            verb="POST",
            endpoint=f"{config.OAUTH_URL}/token",
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
                "scope": external_scope,
                "client_id": test_app.get_client_id(),
                "client_secret": test_app.get_client_secret(),
                "redirect_uri": callback_url,
                "grant_type": "authorization_code",
                "code": await oauth.get_authenticated_with_simulated_auth(),
            },
        )

    @pytest.mark.token_exchange
    @pytest.mark.errors
    @pytest.mark.parametrize('product_1_scopes, product_2_scopes', [
        # Scenario 1: one product with valid scope
        (
            ['urn:nhsd:apim:user-nhs-login:P9:personal-demographics-service'],
            []
        ),
        # Scenario 2: one product with valid scope, one product with invalid scope
        (
            ['urn:nhsd:apim:user-nhs-login:P9:personal-demographics-service'],
            ['urn:nhsd:apim:app:level3:ambulance-analytics']
        ),
        # Scenario 3: multiple products with valid scopes
        (
            ['urn:nhsd:apim:user-nhs-login:P9:personal-demographics-service'],
            ['urn:nhsd:apim:user-nhs-login:P9:ambulance-analytics']
        ),
        # Scenario 4: one product with multiple valid scopes
        (
            ['urn:nhsd:apim:user-nhs-login:P9:personal-demographics-service',
             'urn:nhsd:apim:user-nhs-login:P9:ambulance-analytics'],
            []
        ),
        # Scenario 5: multiple products with multiple valid scopes
        (
            ['urn:nhsd:apim:user-nhs-login:P9:personal-demographics-service',
             'urn:nhsd:apim:user-nhs-login:P9:ambulance-analytics'],
            ['urn:nhsd:apim:user-nhs-login:P9:example-1', 'urn:nhsd:apim:user-nhs-login:P9:example-2']
        ),
        # Scenario 6: one product with multiple scopes (valid and invalid)
        (
            ['urn:nhsd:apim:user-nhs-login:P9:personal-demographics-service',
             'urn:nhsd:apim:app:level3:ambulance-analytics'],
            []
        ),
        # Scenario 7: multiple products with multiple scopes (valid and invalid)
        (
            ['urn:nhsd:apim:user-nhs-login:P9:personal-demographics-service',
             'urn:nhsd:apim:app:level3:ambulance-analytics'],
            ['urn:nhsd:apim:user-nhs-login:P9:example-1', 'urn:nhsd:apim:app:level3:example-2']
        ),
        # Scenario 8: one product with valid scope with trailing and leading spaces
        (
            [' urn:nhsd:apim:user-nhs-login:P9:personal-demographics-service '],
            []
        ),
    ])
    async def test_nhs_login_token_exchange_user_restricted_scope_combination(
        self,
        product_1_scopes,
        product_2_scopes,
        test_app_and_product,
        helper
    ):
        expected_status_code = 200
        expected_expires_in = '599'
        expected_token_type = 'Bearer'
        expected_issued_token_type = 'urn:ietf:params:oauth:token-type:access_token'

        test_product, test_product2, test_app = test_app_and_product

        await test_product.update_scopes(product_1_scopes)
        await test_product2.update_scopes(product_2_scopes)

        id_token_claims = {
            "sub": "8dc9fc1d-c3cb-48e1-ba62-b1532539ab6d",
            "birthdate": "1939-09-26",
            "nhs_number": "9482807146",
            "iss": "https://auth.aos.signin.nhs.uk",
            "nonce": "randomnonce",
            "vtm": "https://auth.aos.signin.nhs.uk/trustmark/auth.aos.signin.nhs.uk",
            "aud": "java_test_client",
            "id_status": "verified",
            "token_use": "id",
            "surname": "CARTHY",
            "auth_time": 1617272144,
            "vot": "P9.Cp.Cd",
            "identity_proofing_level": "P9",
            "exp": int(time()) + 6000,
            "iat": int(time()) - 100,
            "family_name": "CARTHY",
            "jti": "b6d6a28e-b0bb-44e3-974f-bb245c0b688a"
        }

        with open(config.ID_TOKEN_NHS_LOGIN_PRIVATE_KEY_ABSOLUTE_PATH, "r") as f:
            contents = f.read()

        client_assertion_jwt = self.oauth.create_jwt(kid="test-1", client_id=test_app.client_id)
        id_token_jwt = self.oauth.create_id_token_jwt(algorithm='RS512', claims=id_token_claims, signing_key=contents)

        # When
        resp = await self.oauth.get_token_response(
            grant_type="token_exchange",
            data={
                'grant_type': 'urn:ietf:params:oauth:grant-type:token-exchange',
                'subject_token_type': 'urn:ietf:params:oauth:token-type:id_token',
                'client_assertion_type': 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer',
                'subject_token': id_token_jwt,
                'client_assertion': client_assertion_jwt
            }
        )

        # Then
        assert expected_status_code == resp['status_code'], resp['body']
        assert 'access_token' in resp['body']
        assert expected_expires_in == resp['body']['expires_in']
        assert expected_token_type == resp['body']['token_type']
        assert expected_issued_token_type == resp['body']['issued_token_type']
