from api_tests.config_files import config
import pytest
from uuid import uuid4
from time import time, sleep
from api_test_utils.apigee_api_apps import ApigeeApiDeveloperApps
from api_test_utils.apigee_api_products import ApigeeApiProducts


@pytest.mark.usefixtures("setup")
class TestJwtUnattendedAccessSuite:
    """ A test suit to verify all the happy path oauth endpoints """
    @pytest.fixture()
    async def test_app_and_product(self):
        apigee_product = ApigeeApiProducts()
        apigee_product2 = ApigeeApiProducts()
        await apigee_product.create_new_product()
        await apigee_product.update_proxies([config.SERVICE_NAME])
        await apigee_product2.create_new_product()
        await apigee_product2.update_proxies([config.SERVICE_NAME])

        apigee_app = ApigeeApiDeveloperApps()
        await apigee_app.create_new_app(
            callback_url=config.REDIRECT_URI
        )

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

        yield apigee_product, apigee_product2, apigee_app

        await apigee_app.destroy_app()
        await apigee_product.destroy_product()
        await apigee_product2.destroy_product()

    @pytest.mark.parametrize('jwt_claims, expected_response, expected_status_code', [
        # Incorrect JWT algorithm using “HS256” instead of “RS512”
        (
            {
                'kid': 'test-1',
                'algorithm': 'HS256',
            },
            {
                'error': 'invalid_request',
                'error_description': "Invalid 'alg' header in JWT - unsupported JWT algorithm - must be 'RS512'"
            },
            400
        ),

        # Missing JWT algorithm
        # (
        #     {
        #         'kid': 'test-1',
        #         'algorithm': None,
        #     },
        #     {
        #         'error': 'invalid_request',
        #         'error_description': "Missing 'alg' header in JWT"
        #     },
        #     400
        # ),

        # Invalid “sub” & “iss” in jwt claims
        (
            {
                'kid': 'test-1',
                'claims': {
                    "sub": 'INVALID',
                    "iss": 'INVALID',
                    "jti": str(uuid4()),
                    "aud": config.TOKEN_URL,
                    "exp": int(time()) + 10,
                }
            },
            {'error': 'invalid_request', 'error_description': 'Invalid iss/sub claims in JWT'},
            401
        ),

        # Invalid “sub” in jwt claims and different from “iss”
        (
            {
                'kid': 'test-1',
                'claims': {
                    "sub": 'INVALID',
                    "iss": config.JWT_APP_KEY,
                    "jti": str(uuid4()),
                    "aud": config.TOKEN_URL,
                    "exp": int(time()) + 10,
                }
            },
            {'error': 'invalid_request', 'error_description': 'Missing or non-matching iss/sub claims in JWT'},
            400
        ),

        #  Invalid “iss” in jwt claims and different from “sub"
        (
            {
                'kid': 'test-1',
                'claims': {
                    "sub": config.JWT_APP_KEY,
                    "iss": 'INVALID',
                    "jti": str(uuid4()),
                    "aud": config.TOKEN_URL,
                    "exp": int(time()) + 10,
                }
            },
            {'error': 'invalid_request', 'error_description': 'Missing or non-matching iss/sub claims in JWT'},
            400
        ),

        # Missing “sub” in jwt claims
        (
            {
                'kid': 'test-1',
                'claims': {
                    "iss": config.JWT_APP_KEY,
                    "jti": str(uuid4()),
                    "aud": config.TOKEN_URL,
                    "exp": int(time()) + 10,
                }
            },
            {'error': 'invalid_request', 'error_description': 'Missing or non-matching iss/sub claims in JWT'},
            400
        ),

        # Missing “iss” in jwt claims
        (
            {
                'kid': 'test-1',
                'claims': {
                    "sub": config.JWT_APP_KEY,
                    "jti": str(uuid4()),
                    "aud": config.TOKEN_URL,
                    "exp": int(time()) + 10,
                }
            },
            {'error': 'invalid_request', 'error_description': 'Missing or non-matching iss/sub claims in JWT'},
            400
        ),

        # Invalid “jti” in jwt claims e.g using an INT type instead of a STRING
        (
            {
                'kid': 'test-1',
                'claims': {
                    "sub": config.JWT_APP_KEY,
                    "iss": config.JWT_APP_KEY,
                    "jti": 1234567890,
                    "aud": config.TOKEN_URL,
                    "exp": int(time()) + 10,
                }
            },
            {'error': 'invalid_request', 'error_description': 'Failed to decode JWT'},
            400
        ),

        #  Missing “jti” in jwt claims
        (
            {
                'kid': 'test-1',
                'claims': {
                    "sub": config.JWT_APP_KEY,
                    "iss": config.JWT_APP_KEY,
                    "aud": config.TOKEN_URL,
                    "exp": int(time()) + 10,
                }
            },
            {'error': 'invalid_request', 'error_description': 'Missing jti claim in JWT'},
            400
        ),

        # Reusing the same “jti”
        (
            {
                'kid': 'test-1',
                'claims': {
                    "sub": config.JWT_APP_KEY,
                    "iss": config.JWT_APP_KEY,
                    "jti": '6cd46139-af51-4f78-b850-74fcdf70c75b',
                    "aud": config.TOKEN_URL,
                    "exp": int(time()) + 10,
                }
            },
            {'error': 'invalid_request', 'error_description': 'Non-unique jti claim in JWT'},
            400
        ),

        # Invalid “aud” in jwt claims
        (
            {
                'kid': 'test-1',
                'claims': {
                    "sub": config.JWT_APP_KEY,
                    "iss": config.JWT_APP_KEY,
                    "jti": str(uuid4()),
                    "aud": config.TOKEN_URL + 'INVALID',
                    "exp": int(time()) + 10,
                }
            },
            {'error': 'invalid_request', 'error_description': 'Missing or invalid aud claim in JWT'},
            401
        ),

        # Missing “aud” in jwt claims
        (
            {
                'kid': 'test-1',
                'claims': {
                    "sub": config.JWT_APP_KEY,
                    "iss": config.JWT_APP_KEY,
                    "jti": str(uuid4()),
                    "exp": int(time()) + 10,
                }
            },
            {'error': 'invalid_request', 'error_description': 'Missing or invalid aud claim in JWT'},
            401
        ),

        # Invalid “exp” in jwt claims e.g. using a STRING type
        (
            {
                'kid': 'test-1',
                'claims': {
                    "sub": config.JWT_APP_KEY,
                    "iss": config.JWT_APP_KEY,
                    "jti": str(uuid4()),
                    "aud": config.TOKEN_URL,
                    "exp": 'INVALID',
                }
            },
            {'error': 'invalid_request', 'error_description': 'Failed to decode JWT'},
            400
        ),

        # Missing “exp” in jwt claims
        (
            {
                'kid': 'test-1',
                'claims': {
                    "sub": config.JWT_APP_KEY,
                    "iss": config.JWT_APP_KEY,
                    "jti": str(uuid4()),
                    "aud": config.TOKEN_URL,
                }
            },
            {'error': 'invalid_request', 'error_description': 'Missing exp claim in JWT'},
            400
        ),

        # “Exp” in the past
        (
            {
                'kid': 'test-1',
                'claims': {
                    "sub": config.JWT_APP_KEY,
                    "iss": config.JWT_APP_KEY,
                    "jti": str(uuid4()),
                    "aud": config.TOKEN_URL,
                    "exp": int(time()) - 10,
                }
            },
            {'error': 'invalid_request', 'error_description': 'Invalid exp claim in JWT - JWT has expired'},
            400
        ),

        # “Exp” too far into the future (more than 5 minuets)
        (
            {
                'kid': 'test-1',
                'claims': {
                    "sub": config.JWT_APP_KEY,
                    "iss": config.JWT_APP_KEY,
                    "jti": str(uuid4()),
                    "aud": config.TOKEN_URL,
                    "exp": int(time()) + 320,  # this includes the +10 seconds grace
                }
            },
            {'error': 'invalid_request',
             'error_description': 'Invalid exp claim in JWT - more than 5 minutes in future'},
            400
        )
    ])
    @pytest.mark.apm_1521
    @pytest.mark.errors
    def test_invalid_jwt_claims(self, jwt_claims, expected_response, expected_status_code):
        assert self.oauth.check_jwt_token_response(
            jwt=self.oauth.create_jwt(**jwt_claims),
            expected_response=expected_response,
            expected_status_code=expected_status_code
        )

    @pytest.mark.apm_1521
    @pytest.mark.usefixtures('get_token_using_jwt')
    @pytest.mark.skip(reason="NOT YET IMPLEMENTED")
    def test_jwt_signed_access_token_does_expire(self):
        # Wait for token to expire
        sleep(5)

        # Check refresh token still works after access token has expired
        assert self.oauth.check_endpoint(
            verb='GET',
            endpoint='hello_world',
            expected_status_code=401,
            expected_response={
                'fault': {
                    'faultstring': 'Access Token expired', 'detail': {
                        'errorcode': 'keymanagement.service.access_token_expired'
                    }
                }
            },
            headers={
                'Authorization': f'Bearer {self.jwt_signed_token}',
                'NHSD-Session-URID': '',
            }
        )

    @pytest.mark.happy_path
    @pytest.mark.usefixtures('get_token_using_jwt')
    def test_successful_jwt_token_response(self):
        assert self.jwt_response['expires_in'] == '599', f"UNEXPECTED 'expires_in' {self.jwt_response['expires_in']}"
        assert list(self.jwt_response.keys()) == ['access_token', 'expires_in', 'token_type'], \
            f'UNEXPECTED RESPONSE: {self.jwt_response.keys()}'

    @pytest.mark.apm_1521
    @pytest.mark.errors
    @pytest.mark.parametrize('form_data, expected_response', [
        # Invalid formdata “client_assertion_type”
        (
            {
                "client_assertion_type": "INVALID",
                "grant_type": "client_credentials",
            },
            {
                'error': 'invalid_request',
                'error_description': "Missing or invalid client_assertion_type - "
                                     "must be 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer"
            }

        ),

        # Missing formdata “client_assertion_type”
        (
            {
                "grant_type": "client_credentials",
            },
            {
                'error': 'invalid_request',
                'error_description': "Missing or invalid client_assertion_type - "
                                     "must be 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer"
            }
        ),

        # Invalid formdata “client_assertion”
        (
            {
                "client_assertion_type": "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
                "client_assertion": "INVALID",
                "grant_type": "client_credentials",
            },
            {'error': 'invalid_request', 'error_description': 'Malformed JWT in client_assertion'}
        ),

        # Missing formdata “client_assertion”
        (
            {
                "client_assertion_type": "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
                "client_assertion": None,
                "grant_type": "client_credentials",
            },
            {'error': 'invalid_request', 'error_description': 'Missing client_assertion'}
        ),

        # Invalid formdata “grant_type”
        (
            {
                "client_assertion_type": "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
                "grant_type": "INVALID",
            },
            {'error': 'unsupported_grant_type', 'error_description': 'grant_type is invalid'}
        ),

        # Missing formdata "grant_type"
        (
            {
                "client_assertion_type": "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
            },
            {
                'error': 'invalid_request',
                'error_description': 'grant_type is missing'
            }
        )

    ])
    def test_invalid_form_data(self, form_data, expected_response):
        assert self.oauth.check_jwt_token_response(
            jwt=self.oauth.create_jwt(kid='test-1'),
            form_data=form_data,
            expected_response=expected_response,
            expected_status_code=400
        )

    @pytest.mark.apm_1521
    @pytest.mark.errors
    @pytest.mark.parametrize('jwt_details, expected_response, expected_status_code', [
        # Invalid KID
        (
            {
                'kid': 'INVALID',
            },
            {'error': 'invalid_request', 'error_description': "Invalid 'kid' header in JWT - no matching public key"},
            401
        ),

        # Missing KID Header
        (
            {
                'kid': None,

            },
            {'error': 'invalid_request', 'error_description': "Missing 'kid' header in JWT"},
            400
        ),

    ])
    def test_invalid_jwt(self, jwt_details, expected_response, expected_status_code):
        assert self.oauth.check_jwt_token_response(
            jwt=self.oauth.create_jwt(**jwt_details),
            expected_response=expected_response,
            expected_status_code=expected_status_code
        )

    @pytest.mark.parametrize('jwt_component_name', [
        # Modified header
        "header",

        # Modified data
        "data",

        # Modified signature
        "signature",
    ])
    def test_manipulated_jwt_json(self, jwt_component_name):
        assert self.oauth.check_jwt_token_response(
            jwt=self.oauth.modified_jwt(jwt_component_name),
            expected_response={'error': 'invalid_request', 'error_description': 'Malformed JWT in client_assertion'},
            expected_status_code=400
        )

    def test_invalid_jwks_resource_url(self):
        config.JWT_APP_KEY = config.JWT_APP_KEY_WITH_INVALID_JWKS_URL
        assert self.oauth.check_jwt_token_response(
            jwt=self.oauth.create_jwt(kid='test-1'),
            expected_response={
                'error': 'public_key error',
                'error_description': 'You need to register a public key to use this authentication method - please contact support to configure'
            },
            expected_status_code=403
        )

    @pytest.mark.apm_1701
    @pytest.mark.happy_path
    @pytest.mark.asyncio
    @pytest.mark.parametrize('product_1_scopes, product_2_scopes', [
        # Scenario 1: Valid scope set, single product
        (
            ['urn:nhsd:apim:app:jwks:personal-demographics'],
            []
        ),
        # Scenario 2: Multiple valid scopes set, single product
        (
            ['urn:nhsd:apim:app:jwks:personal-demographics', 'urn:nhsd:apim:app:jwks:ambulance-analytics'],
            []
        ),
        # Scenario 3: Single valid scopes set, different products
        (
            ['urn:nhsd:apim:app:jwks:personal-demographics-service'],
            ['urn:nhsd:apim:usr:aal3:personal-demographics-service']
        ),
        # Scenario 4: Multiple valid scopes set, multiple products
        (
            ['urn:nhsd:apim:app:jwks:personal-demographics-service'],
            ['urn:nhsd:apim:app:jwks:ambulance-analytics']
        )
    ])
    async def test_valid_application_restricted_scope_combination(
        self,
        product_1_scopes,
        product_2_scopes,
        test_app_and_product
    ):
        test_product, test_product2, test_app = test_app_and_product

        await test_product.update_scopes(product_1_scopes)
        await test_product2.update_scopes(product_2_scopes)

        config.JWT_APP_KEY = test_app.get_client_id()
        jwt = self.oauth.create_jwt(kid='test-1')
        response = self.oauth.get_jwt_token_response(jwt)
        assert list(response[0].keys()) == ['access_token', 'expires_in', 'token_type']
        assert response[1] == 200

    @pytest.mark.apm_1701
    @pytest.mark.errors
    @pytest.mark.asyncio
    @pytest.mark.parametrize('product_1_scopes, product_2_scopes', [
        # Scenario 1: No scopes set, multiple products
        (
            [],
            []
        ),
        # Scenario 2: Invalid scope set, single product
        (
            ['urn:nshd:apim:usr:aal3:personal-demographics'],
            []
        ),
        # Scenario 3: Multiple invalid scopes set, single product
        (
            ['urn:nhsd:apim:user:aal3:personal-demographics', 'urn:nhsd:apim:user:aal3:ambulance-analytics'],
            []
        ),
        # Scenario 3: Invalid scopes set, multiple products
        (
            ['urn:nshd:apim:usr:aal3:personal-demographics'],
            ['urn:nshd:apim:usr:aal3:ambulance-analytics']
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

        config.JWT_APP_KEY = test_app.get_client_id()
        assert self.oauth.check_jwt_token_response(
            jwt=self.oauth.create_jwt(kid='test-1'),
            expected_response={
                "error": "unauthorized_client",
                "error_description": "the authenticated client is not authorized to use this authorization grant type",
            },
            expected_status_code=401
        )
