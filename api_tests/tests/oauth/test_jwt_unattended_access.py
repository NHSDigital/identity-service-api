from api_tests.config_files import config
import pytest
import uuid
from time import time, sleep


@pytest.mark.usefixtures("setup")
class TestJwtUnattendedAccessSuite:
    """ A test suit to verify all the happy path oauth endpoints """

    @pytest.mark.apm_1521
    @pytest.mark.happy_path
    @pytest.mark.usefixtures('get_token_using_jwt')
    def test_request_with_jwt_access_token(self):
        assert self.oauth.check_endpoint(
            verb='GET',
            endpoint='hello_world',
            expected_status_code=200,
            expected_response={"message": "hello user!"},
            headers={
                'Authorization': f'Bearer {self.jwt_signed_token}',
                'NHSD-Session-URID': 'ROLD-ID',
            }
        )

    @pytest.mark.parametrize('jwt_claims, expected_response', [
        # Incorrect JWT algorithm using “HS256” instead of “RS512”
        (
            {
                'kid': 'test-rs512',
                'secret_key': 'jwtRS512.key',
                'algorithm': 'HS256',
            },
            {'error': 'invalid_request', 'error_description': 'Unsupported JWT Algorithm'}
        ),

        # Invalid “subject” & “iss” in jwt claims
        (
            {
                'kid': 'test-rs512',
                'secret_key': 'jwtRS512.key',
                'claims': {
                    "subject": 'INVALID',
                    "iss": 'INVALID',
                    "jti": str(uuid.uuid4()),
                    "aud": config.TOKEN_URL,
                    "exp": int(time()) + 10,
                }
            },
            {'error': 'invalid_request', 'error_message': 'invalid sub/iss claims'}
        ),

        # Invalid “subject” in jwt claims and different from “iss”
        (
            {
                'kid': 'test-rs512',
                'secret_key': 'jwtRS512.key',
                'claims': {
                    "subject": 'INVALID',
                    "iss": config.JWT_APP_KEY,
                    "jti": str(uuid.uuid4()),
                    "aud": config.TOKEN_URL,
                    "exp": int(time()) + 10,
                }
            },
            {'error': 'invalid_request', 'error_description': 'iss/sub claims missing or invalid (should be same)'}
        ),

        #  Invalid “iss” in jwt claims and different from “subject"
        (
            {
                'kid': 'test-rs512',
                'secret_key': 'jwtRS512.key',
                'claims': {
                    "subject": config.JWT_APP_KEY,
                    "iss": 'INVALID',
                    "jti": str(uuid.uuid4()),
                    "aud": config.TOKEN_URL,
                    "exp": int(time()) + 10,
                }
            },
            {'error': 'invalid_request', 'error_description': 'iss/sub claims missing or invalid (should be same)'}
        ),

        # Missing “subject” in jwt claims
        (
            {
                'kid': 'test-rs512',
                'secret_key': 'jwtRS512.key',
                'claims': {
                    "iss": config.JWT_APP_KEY,
                    "jti": str(uuid.uuid4()),
                    "aud": config.TOKEN_URL,
                    "exp": int(time()) + 10,
                }
            },
            {'error': 'invalid_request', 'error_description': 'iss/sub claims missing or invalid (should be same)'}
        ),

        # Missing “iss” in jwt claims
        (
            {
                'kid': 'test-rs512',
                'secret_key': 'jwtRS512.key',
                'claims': {
                    "subject": config.JWT_APP_KEY,
                    "jti": str(uuid.uuid4()),
                    "aud": config.TOKEN_URL,
                    "exp": int(time()) + 10,
                }
            },
            {'error': 'invalid_request', 'error_description': 'iss/sub claims missing or invalid (should be same)'}
        ),

        # Invalid “jti” in jwt claims e.g using an INT type instead of a STRING
        (
            {
                'kid': 'test-rs512',
                'secret_key': 'jwtRS512.key',
                'claims': {
                    "subject": config.JWT_APP_KEY,
                    "iss": config.JWT_APP_KEY,
                    "jti": 1234567890,
                    "aud": config.TOKEN_URL,
                    "exp": int(time()) + 10,
                }
            },
            {'error': 'invalid_request', 'error_message': 'Failed to decode JWT'}
        ),

        #  Missing “jti” in jwt claims
        (
            {
                'kid': 'test-rs512',
                'secret_key': 'jwtRS512.key',
                'claims': {
                    "subject": config.JWT_APP_KEY,
                    "iss": config.JWT_APP_KEY,
                    "aud": config.TOKEN_URL,
                    "exp": int(time()) + 10,
                }
            },
            {'error': 'invalid_request', 'error_description': 'jti claim missing'}
        ),

        # Reusing the same “jti”
        (
            {
                'kid': 'test-rs512',
                'secret_key': 'jwtRS512.key',
                'claims': {
                    "subject": config.JWT_APP_KEY,
                    "iss": config.JWT_APP_KEY,
                    "jti": '6cd46139-af51-4f78-b850-74fcdf70c75b',
                    "aud": config.TOKEN_URL,
                    "exp": int(time()) + 10,
                }
            },
            {'error': 'invalid_request', 'error_description': 'jti claim must be unique'}
        ),

        # Invalid “aud” in jwt claims
        (
            {
                'kid': 'test-rs512',
                'secret_key': 'jwtRS512.key',
                'claims': {
                    "subject": config.JWT_APP_KEY,
                    "iss": config.JWT_APP_KEY,
                    "jti": str(uuid.uuid4()),
                    "aud": config.TOKEN_URL + 'INVALID',
                    "exp": int(time()) + 10,
                }
            },
            {'error': 'invalid_request', 'error_message': 'aud claim missing or invalid'}
        ),

        # Missing “aud” in jwt claims
        (
            {
                'kid': 'test-rs512',
                'secret_key': 'jwtRS512.key',
                'claims': {
                    "subject": config.JWT_APP_KEY,
                    "iss": config.JWT_APP_KEY,
                    "jti": str(uuid.uuid4()),
                    "exp": int(time()) + 10,
                }
            },
            {'error': 'invalid_request', 'error_message': 'aud claim missing or invalid'}
        ),

        # Invalid “exp” in jwt claims e.g. using a STRING type
        (
            {
                'kid': 'test-rs512',
                'secret_key': 'jwtRS512.key',
                'claims': {
                    "subject": config.JWT_APP_KEY,
                    "iss": config.JWT_APP_KEY,
                    "jti": str(uuid.uuid4()),
                    "aud": config.TOKEN_URL,
                    "exp": 'INVALID',
                }
            },
            {'error': 'invalid_request', 'error_message': 'Failed to decode JWT'}
        ),

        # Missing “exp” in jwt claims
        (
            {
                'kid': 'test-rs512',
                'secret_key': 'jwtRS512.key',
                'claims': {
                    "subject": config.JWT_APP_KEY,
                    "iss": config.JWT_APP_KEY,
                    "jti": str(uuid.uuid4()),
                    "aud": config.TOKEN_URL,
                }
            },
            {'error': 'invalid_request', 'error_description': 'exp claim missing'}
        ),

        # “Exp” in the past
        (
            {
                'kid': 'test-rs512',
                'secret_key': 'jwtRS512.key',
                'claims': {
                    "subject": config.JWT_APP_KEY,
                    "iss": config.JWT_APP_KEY,
                    "jti": str(uuid.uuid4()),
                    "aud": config.TOKEN_URL,
                    "exp": int(time()) - 10,
                }
            },
            {'error': 'invalid_request', 'error_description': 'JWT token has expired'}
        ),

        # “Exp” too far into the future (more than 5 minuets)
        # (
        #     {
        #         'kid': 'test-rs512',
        #         'secret_key': 'jwtRS512.key',
        #         'claims': {
        #             "subject": config.JWT_APP_KEY,
        #             "iss": config.JWT_APP_KEY,
        #             "jti": str(uuid.uuid4()),
        #             "aud": config.TOKEN_URL,
        #             "exp": int(time()) + 311,  # this includes the +10 seconds grace
        #         }
        #     },
        #     {'error': 'invalid_request', 'error_description': 'JWT token has expired'}
        # )
    ])
    @pytest.mark.apm_1521
    @pytest.mark.errors
    def test_invalid_jwt_claims(self, jwt_claims, expected_response):
        assert self.oauth.check_jwt_token_response(
            jwt=self.oauth.create_jwt(**jwt_claims),
            expected_response=expected_response
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
        assert self.jwt_response['expires_in'] == '3599', f"UNEXPECTED 'expires_in' {self.jwt_response['expires_in']}"
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
            {'error': 'invalid_request',
             'error_description': "client_assertion_type form param is required. "
                                  "(Supported value for Client Credentials Grant is "
                                  "'urn:ietf:params:oauth:client-assertion-type:jwt-bearer')"}
        ),

        # Missing formdata “client_assertion_type”
        (
            {
                "grant_type": "client_credentials",
            },
            {'error': 'invalid_request',
             'error_description': "client_assertion_type form param is required. "
                                  "(Supported value for Client Credentials Grant is "
                                  "'urn:ietf:params:oauth:client-assertion-type:jwt-bearer')"}
        ),

        # Invalid formdata “client_assertion”
        (
            {
                "client_assertion_type": "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
                "client_assertion": "INVALID",
                "grant_type": "client_credentials",
            },
            {'error': 'invalid_request', 'error_message': 'Failed to decode JWT'}
        ),

        # Missing formdata “client_assertion”
        (
            {
                "client_assertion_type": "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
                "client_assertion": None,
                "grant_type": "client_credentials",
            },
            {'error': 'invalid_request', 'error_message': 'client_assertion is missing'}
        ),

        # Invalid formdata “grant_type”
        (
            {
                "client_assertion_type": "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
                "grant_type": "INVALID",
            },
            {'error': 'invalid_request', 'error_description': "Unsupported grant_type 'INVALID'"}
        ),

        # Missing formdata "grant_type"
        (
            {
                "client_assertion_type": "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
            },
            {'error': 'invalid_request', 'error_description': 'Not Found'}
        )

    ])
    def test_invalid_form_data(self, form_data, expected_response):
        assert self.oauth.check_jwt_token_response(
            jwt=self.oauth.create_jwt(kid='test-rs512', secret_key='jwtRS512.key'),
            form_data=form_data,
            expected_response=expected_response
        )

    @pytest.mark.apm_1521
    @pytest.mark.errors
    @pytest.mark.parametrize('jwt_details, expected_response', [
        # Invalid KID
        (
            {
                'kid': 'INVALID',
                'secret_key': 'jwtRS512.key'
            },
            {'error': 'invalid_request', 'error_message': 'No matching public key'}
        ),

        # Missing KID Header
        (
            {
                'kid': None,
                'secret_key': 'jwtRS512.key',
            },
            {'error': 'invalid_request', 'error_description': "JWT header value 'kid' is missing"}
        ),

        # Public key mismatch
        (
            {
                'kid': 'test-rs512',
                'secret_key': 'invalidRS512.key',
            },
            {'error': 'unknown_error',
             'error_description': 'An unknown error occurred processing this request. '
                                  'Contact us for assistance diagnosing this issue: '
                                  'https://digital.nhs.uk/developer/help-and-support quoting Message ID'}
        ),
    ])
    def test_invalid_jwt(self, jwt_details, expected_response):
        assert self.oauth.check_jwt_token_response(
            jwt=self.oauth.create_jwt(**jwt_details),
            expected_response=expected_response
        )

    @pytest.mark.parametrize('jwt_component_name, expected_response', [
        # Modified header
        (
            "header",
            {'error': 'unknown_error', 'error_description':
                'An unknown error occurred processing this request. Contact us for assistance diagnosing this issue: '
                'https://digital.nhs.uk/developer/help-and-support quoting Message ID'}
        ),

        # Modified data
        (
            "data",
            {'error': 'unknown_error', 'error_description':
                'An unknown error occurred processing this request. Contact us for assistance diagnosing this issue: '
                'https://digital.nhs.uk/developer/help-and-support quoting Message ID'}
        ),

        # Modified signature
        (
            "signature",
            {'error': 'unknown_error', 'error_description':
                'An unknown error occurred processing this request. Contact us for assistance diagnosing this issue: '
                'https://digital.nhs.uk/developer/help-and-support quoting Message ID'}
        ),
    ])
    def test_manipulated_jwt_json(self, jwt_component_name, expected_response):
        assert self.oauth.check_jwt_token_response(
            jwt=self.oauth.modified_jwt(jwt_component_name),
            expected_response=expected_response)

    def test_invalid_jwks_resource_url(self):
        config.JWT_APP_KEY = config.JWT_APP_KEY_WITH_INVALID_JWKS_URL
        assert self.oauth.check_jwt_token_response(
            jwt=self.oauth.create_jwt(kid='test-rs512', secret_key='jwtRS512.key'),
            expected_response={'error': 'unknown_error',
                               'error_description': 'An unknown error occurred processing this request. '
                                                    'Contact us for assistance diagnosing this issue: '
                                                    'https://digital.nhs.uk/developer/help-and-support '
                                                    'quoting Message ID'})
