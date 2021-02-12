from api_tests.config_files import config
import pytest
from uuid import uuid4
from time import time, sleep
from random import choice
from string import ascii_letters


@pytest.mark.asyncio
@pytest.mark.usefixtures("setup")
class TestJwtUnattendedAccessSuite:
    """ A test suit to verify all the happy path oauth endpoints """

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
                    "exp": int(time()) + 330,  # this includes the +30 seconds grace
                }
            },
            {'error': 'invalid_request',
             'error_description': 'Invalid exp claim in JWT - more than 5 minutes in future'},
            400
        )
    ])
    @pytest.mark.apm_1521
    @pytest.mark.errors
    async def test_invalid_jwt_claims(self, jwt_claims, expected_response, expected_status_code):
        jwt = self.oauth.create_jwt(**jwt_claims)
        resp = await self.oauth.get_token_response(grant_type='client_credentials', _jwt=jwt)

        assert resp['status_code'] == expected_status_code
        assert resp['body'] == expected_response

    @pytest.mark.happy_path
    async def test_successful_jwt_token_response(self):
        jwt = self.oauth.create_jwt(kid="test-1", client_id=config.JWT_APP_KEY)
        resp = await self.oauth.get_token_response("client_credentials", _jwt=jwt)

        assert resp['body']['expires_in'] == '599', f"UNEXPECTED 'expires_in' {resp['expires_in']}"
        assert list(resp['body'].keys()) == ['access_token', 'expires_in', 'token_type'], \
            f'UNEXPECTED RESPONSE: {list(resp["body"].keys())}'

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
    async def test_invalid_form_data(self, form_data, expected_response):
        jwt = self.oauth.create_jwt(kid="test-1")
        resp = await self.oauth.get_token_response("client_credentials", _jwt=jwt, data=form_data)

        assert resp['status_code'] == 400
        assert resp['body'] == expected_response

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
    async def test_invalid_jwt(self, jwt_details, expected_response, expected_status_code):
        jwt = self.oauth.create_jwt(**jwt_details, client_id=config.JWT_APP_KEY)
        resp = await self.oauth.get_token_response("client_credentials", _jwt=jwt)

        assert resp['status_code'] == expected_status_code
        assert resp['body'] == expected_response

    @pytest.mark.skip("Investigate why this is currently failing")
    async def test_manipulated_jwt_json(self):
        jwt = self.oauth.create_jwt(kid='test-1', client_id=config.JWT_APP_KEY)
        chars = choice(ascii_letters) + choice(ascii_letters)

        resp = await self.oauth.get_token_response(grant_type="client_credentials", _jwt=f"{jwt[:-2]}{chars}")

        assert resp['status_code'] == 400
        assert resp['body'] == {'error': 'invalid_request', 'error_description': 'Malformed JWT in client_assertion'}

    async def test_invalid_jwks_resource_url(self):
        jwt = self.oauth.create_jwt(kid='test-1', client_id=config.JWT_APP_KEY_WITH_INVALID_JWKS_URL)
        resp = await self.oauth.get_token_response("client_credentials", _jwt=jwt)

        assert resp['status_code'] == 403
        assert resp['body'] == {
                'error': 'public_key error',
                'error_description': 'You need to register a public key to use this '
                                     'authentication method - please contact support to configure'
            }
