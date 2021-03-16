from api_tests.scripts.config import OAUTH_URL
import pytest
from uuid import uuid4
from time import time
from random import choice
from string import ascii_letters


@pytest.mark.asyncio
class TestJwtUnattendedAccess:
    """ A test suit to verify all the happy path oauth endpoints """
    def _update_secrets(self, request):
        if request.get("claims", None):
            if request["claims"].get("sub", None) == "/replace_me":
                request["claims"]['sub'] = self.oauth.client_id

            if request["claims"].get("iss", None) == "/replace_me":
                request["claims"]['iss'] = self.oauth.client_id
        else:
            if request.get("sub", None) == "/replace_me":
                request['sub'] = self.oauth.client_id
            if request.get("iis", None) == "/replace_me":
                request["iis"] = self.oauth.client_id

    @pytest.mark.parametrize('jwt_claims, expected_response, expected_status_code', [
        # 1. Incorrect JWT algorithm using “HS256” instead of “RS512”
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

        # 2. Invalid “sub” & “iss” in jwt claims
        (
            {
                'kid': 'test-1',
                'claims': {
                    "sub": 'INVALID',
                    "iss": 'INVALID',
                    "jti": str(uuid4()),
                    "aud": f"{OAUTH_URL}/token",
                    "exp": int(time()) + 10,
                }
            },
            {'error': 'invalid_request', 'error_description': 'Invalid iss/sub claims in JWT'},
            401
        ),

        # 3. Invalid “sub” in jwt claims and different from “iss”
        (
            {
                'kid': 'test-1',
                'claims': {
                    "sub": 'INVALID',
                    "iss": "/replace_me",
                    "jti": str(uuid4()),
                    "aud": f"{OAUTH_URL}/token",
                    "exp": int(time()) + 10,
                }
            },
            {'error': 'invalid_request', 'error_description': 'Missing or non-matching iss/sub claims in JWT'},
            400
        ),

        #  4. Invalid “iss” in jwt claims and different from “sub"
        (
            {
                'kid': 'test-1',
                'claims': {
                    "sub": "/replace_me",
                    "iss": 'INVALID',
                    "jti": str(uuid4()),
                    "aud": f"{OAUTH_URL}/token",
                    "exp": int(time()) + 10,
                }
            },
            {'error': 'invalid_request', 'error_description': 'Missing or non-matching iss/sub claims in JWT'},
            400
        ),

        # 5. Missing “sub” in jwt claims
        (
            {
                'kid': 'test-1',
                'claims': {
                    "iss": "/replace_me",
                    "jti": str(uuid4()),
                    "aud": f"{OAUTH_URL}/token",
                    "exp": int(time()) + 10,
                }
            },
            {'error': 'invalid_request', 'error_description': 'Missing or non-matching iss/sub claims in JWT'},
            400
        ),

        # 6. Missing “iss” in jwt claims
        (
            {
                'kid': 'test-1',
                'claims': {
                    "sub": "/replace_me",
                    "jti": str(uuid4()),
                    "aud": f"{OAUTH_URL}/token",
                    "exp": int(time()) + 10,
                }
            },
            {'error': 'invalid_request', 'error_description': 'Missing or non-matching iss/sub claims in JWT'},
            400
        ),

        # 7. Invalid “jti” in jwt claims e.g using an INT type instead of a STRING
        (
            {
                'kid': 'test-1',
                'claims': {
                    "sub": "/replace_me",
                    "iss": "/replace_me",
                    "jti": 1234567890,
                    "aud": f"{OAUTH_URL}/token",
                    "exp": int(time()) + 10,
                }
            },
            {'error': 'invalid_request', 'error_description': 'Failed to decode JWT'},
            400
        ),

        #  8. Missing “jti” in jwt claims
        (
            {
                'kid': 'test-1',
                'claims': {
                    "sub": "/replace_me",
                    "iss": "/replace_me",
                    "aud": f"{OAUTH_URL}/token",
                    "exp": int(time()) + 10,
                }
            },
            {'error': 'invalid_request', 'error_description': 'Missing jti claim in JWT'},
            400
        ),

        # 9. Invalid “aud” in jwt claims
        (
            {
                'kid': 'test-1',
                'claims': {
                    "sub": "/replace_me",
                    "iss": "/replace_me",
                    "jti": str(uuid4()),
                    "aud": f"{OAUTH_URL}/token" + 'INVALID',
                    "exp": int(time()) + 10,
                }
            },
            {'error': 'invalid_request', 'error_description': 'Missing or invalid aud claim in JWT'},
            401
        ),

        # 10. Missing “aud” in jwt claims
        (
            {
                'kid': 'test-1',
                'claims': {
                    "sub": "/replace_me",
                    "iss": "/replace_me",
                    "jti": str(uuid4()),
                    "exp": int(time()) + 10,
                }
            },
            {'error': 'invalid_request', 'error_description': 'Missing or invalid aud claim in JWT'},
            401
        ),

        # 11. Invalid “exp” in jwt claims e.g. using a STRING type
        (
            {
                'kid': 'test-1',
                'claims': {
                    "sub": "/replace_me",
                    "iss": "/replace_me",
                    "jti": str(uuid4()),
                    "aud": f"{OAUTH_URL}/token",
                    "exp": 'INVALID',
                }
            },
            {'error': 'invalid_request', 'error_description': 'Failed to decode JWT'},
            400
        ),

        # 12. Missing “exp” in jwt claims
        (
            {
                'kid': 'test-1',
                'claims': {
                    "sub": "/replace_me",
                    "iss": "/replace_me",
                    "jti": str(uuid4()),
                    "aud": f"{OAUTH_URL}/token",
                }
            },
            {'error': 'invalid_request', 'error_description': 'Missing exp claim in JWT'},
            400
        ),

        # 13. “Exp” in the past
        (
            {
                'kid': 'test-1',
                'claims': {
                    "sub": "/replace_me",
                    "iss": "/replace_me",
                    "jti": str(uuid4()),
                    "aud": f"{OAUTH_URL}/token",
                    "exp": int(time()) - 10,
                }
            },
            {'error': 'invalid_request', 'error_description': 'Invalid exp claim in JWT - JWT has expired'},
            400
        ),

        # 14. “Exp” too far into the future (more than 5 minuets)
        (
            {
                'kid': 'test-1',
                'claims': {
                    "sub": "/replace_me",
                    "iss": "/replace_me",
                    "jti": str(uuid4()),
                    "aud": f"{OAUTH_URL}/token",
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
    async def test_invalid_jwt_claims(self, jwt_claims, expected_response, expected_status_code, helper):
        self._update_secrets(jwt_claims)
        jwt = self.oauth.create_jwt(**jwt_claims)
        resp = await self.oauth.get_token_response(grant_type='client_credentials', _jwt=jwt)

        assert helper.check_response(resp, expected_status_code, expected_response)

    @pytest.mark.apm_1521
    @pytest.mark.errors
    async def test_reusing_same_jti(self, helper):
        jwt = self.oauth.create_jwt(claims={
            "sub": self.oauth.client_id,
            "iss": self.oauth.client_id,
            "jti": '6cd46139-af51-4f78-b850-74fcdf70c75b',
            "aud": f"{OAUTH_URL}/token",
            "exp": int(time()) + 10,
        },
            kid="test-1",
        )
        resp = await self.oauth.get_token_response(grant_type='client_credentials', _jwt=jwt)

        if resp['status_code'] == 200:
            resp = await self.oauth.get_token_response(grant_type='client_credentials', _jwt=jwt)
        assert helper.check_response(
            resp, 400, {'error': 'invalid_request', 'error_description': 'Non-unique jti claim in JWT'})

    @pytest.mark.happy_path
    async def test_successful_jwt_token_response(self):
        jwt = self.oauth.create_jwt(kid="test-1")
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
        jwt = self.oauth.create_jwt(**jwt_details)
        resp = await self.oauth.get_token_response("client_credentials", _jwt=jwt)

        assert resp['status_code'] == expected_status_code
        assert resp['body'] == expected_response

    @pytest.mark.skip("Fails in the pipeline")
    async def test_manipulated_jwt_json(self):
        jwt = self.oauth.create_jwt(kid='test-1')
        chars = choice(ascii_letters) + choice(ascii_letters)

        resp = await self.oauth.get_token_response(grant_type="client_credentials", _jwt=f"{jwt[:-2]}{chars}")

        assert resp['status_code'] == 400
        assert resp['body'] == {'error': 'invalid_request', 'error_description': 'Malformed JWT in client_assertion'}

    async def test_invalid_jwks_resource_url(self, test_app):
        test_app.set_custom_attributes(attributes={"jwks_resource_url": "http://invalid_url"})

        jwt = self.oauth.create_jwt(kid='test-1', client_id=test_app.client_id)
        resp = await self.oauth.get_token_response("client_credentials", _jwt=jwt)

        assert resp['status_code'] == 403
        assert resp['body'] == {
                'error': 'public_key error',
                'error_description': 'You need to register a public key to use this '
                                     'authentication method - please contact support to configure'
            }

    @pytest.mark.happy_path
    @pytest.mark.token_exchange
    async def test_token_exchange_happy_path(self):
        # Given
        expected_status_code = 200
        expected_expires_in = '599'
        expected_token_type = 'Bearer'
        expected_issued_token_type = 'urn:ietf:params:oauth:token-type:access_token'

        id_token_jwt = self.oauth.create_id_token_jwt()
        client_assertion_jwt = self.oauth.create_jwt(kid='test-1')

        # When
        resp = await self.oauth.get_token_response(
            grant_type="token_exchange",
            _jwt=client_assertion_jwt,
            id_token_jwt=id_token_jwt
        )

        # Then
        assert expected_status_code == resp['status_code'], resp['body']
        assert 'access_token' in resp['body']
        assert expected_expires_in == resp['body']['expires_in']
        assert expected_token_type == resp['body']['token_type']
        assert expected_issued_token_type == resp['body']['issued_token_type']

    @pytest.mark.errors
    @pytest.mark.token_exchange
    async def test_token_exchange_invalid_client_assertion_type(self):
        # Given
        expected_status_code = 400
        expected_error = 'invalid_request'
        expected_error_description = "Missing or invalid client_assertion_type - " \
                                     "must be 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer"

        # When
        resp = await self.oauth.get_token_response(
            grant_type="token_exchange",
            data={
                'client_assertion_type': 'Invalid',
                'grant_type': 'urn:ietf:params:oauth:grant-type:token-exchange',
                'subject_token_type': 'urn:ietf:params:oauth:token-type:id_token'
            }
        )

        # Then
        assert expected_status_code == resp['status_code']
        assert expected_error == resp['body']['error']
        assert expected_error_description == resp['body']['error_description']

    @pytest.mark.errors
    @pytest.mark.token_exchange
    async def test_token_exchange_invalid_subject_token_type(self):
        # Given
        expected_status_code = 400
        expected_error = 'invalid_request'
        expected_error_description = "missing or invalid subject_token_type - " \
                                     "must be 'urn:ietf:params:oauth:token-type:id_token'"

        # When
        resp = await self.oauth.get_token_response(
            grant_type="token_exchange",
            data={
                'client_assertion_type': 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer',
                'subject_token_type': 'Invalid',
                'grant_type': 'urn:ietf:params:oauth:grant-type:token-exchange'
            }
        )

        # Then
        assert expected_status_code == resp['status_code']
        assert expected_error == resp['body']['error']
        assert expected_error_description == resp['body']['error_description']

    @pytest.mark.errors
    @pytest.mark.token_exchange
    async def test_token_exchange_claims_assertion_invalid_kid(self):
        # Given
        expected_status_code = 400
        expected_error = 'invalid_request'
        expected_error_description = "Missing 'kid' header in JWT"

        client_assertion_jwt = self.oauth.create_jwt(kid=None)

        # When
        resp = await self.oauth.get_token_response(
            grant_type="token_exchange",
            data={
                'client_assertion_type': 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer',
                'subject_token_type': 'urn:ietf:params:oauth:token-type:id_token',
                'grant_type': 'urn:ietf:params:oauth:grant-type:token-exchange',
                'client_assertion': client_assertion_jwt
            }
        )

        # Then
        assert expected_status_code == resp['status_code']
        assert expected_error == resp['body']['error']
        assert expected_error_description == resp['body']['error_description']

    @pytest.mark.errors
    @pytest.mark.token_exchange
    async def test_token_exchange_claims_assertion_invalid_typ_header(self):
        # Given
        expected_status_code = 400
        expected_error = 'invalid_request'
        expected_error_description = "Invalid 'typ' header in JWT - must be 'JWT'"

        client_assertion_jwt = self.oauth.create_jwt(kid="test-1", headers={'typ': 'invalid'})

        # When
        resp = await self.oauth.get_token_response(
            grant_type="token_exchange",
            data={
                'client_assertion_type': 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer',
                'subject_token_type': 'urn:ietf:params:oauth:token-type:id_token',
                'grant_type': 'urn:ietf:params:oauth:grant-type:token-exchange',
                'client_assertion': client_assertion_jwt
            }
        )

        # Then
        assert expected_status_code == resp['status_code']
        assert expected_error == resp['body']['error']
        assert expected_error_description == resp['body']['error_description']

    @pytest.mark.errors
    @pytest.mark.token_exchange
    async def test_token_exchange_claims_assertion_invalid_iss_claim(self):
        # Given
        expected_status_code = 400
        expected_error = 'invalid_request'
        expected_error_description = "Missing or non-matching iss/sub claims in JWT"

        client_assertion_jwt = self.oauth.create_jwt(kid="test-1", claims={
            "sub": '',
            "jti": str(uuid4()),
            "aud": f"{OAUTH_URL}/token",
            "exp": int(time()) + 5,
        })

        # When
        resp = await self.oauth.get_token_response(
            grant_type="token_exchange",
            data={
                'client_assertion_type': 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer',
                'subject_token_type': 'urn:ietf:params:oauth:token-type:id_token',
                'grant_type': 'urn:ietf:params:oauth:grant-type:token-exchange',
                'client_assertion': client_assertion_jwt
            }
        )

        # Then
        assert expected_status_code == resp['status_code']
        assert expected_error == resp['body']['error']
        assert expected_error_description == resp['body']['error_description']

    @pytest.mark.errors
    @pytest.mark.token_exchange
    async def test_token_exchange_claims_assertion_missing_jti_claim(self):
        # Given
        expected_status_code = 400
        expected_error = 'invalid_request'
        expected_error_description = "Missing jti claim in JWT"

        client_assertion_jwt = self.oauth.create_jwt(kid="test-1", claims={
            "sub": self.oauth.client_id,
            "iss": self.oauth.client_id,
            "jti": '',
            "aud": f"{OAUTH_URL}/token",
            "exp": int(time()) + 5,
        })

        # When
        resp = await self.oauth.get_token_response(
            grant_type="token_exchange",
            data={
                'client_assertion_type': 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer',
                'subject_token_type': 'urn:ietf:params:oauth:token-type:id_token',
                'grant_type': 'urn:ietf:params:oauth:grant-type:token-exchange',
                'client_assertion': client_assertion_jwt
            }
        )

        # Then
        assert expected_status_code == resp['status_code']
        assert expected_error == resp['body']['error']
        assert expected_error_description == resp['body']['error_description']

    @pytest.mark.errors
    @pytest.mark.token_exchange
    async def test_token_exchange_claims_assertion_missing_exp_claim(self):
        # Given
        expected_status_code = 400
        expected_error = 'invalid_request'
        expected_error_description = "Missing exp claim in JWT"

        id_token_claims = self.oauth.create_jwt(kid="test-1", claims={
            "sub": self.oauth.client_id,
            "iss": self.oauth.client_id,
            "jti": str(uuid4()),
            "aud": f"{OAUTH_URL}/token",
        })

        # When
        resp = await self.oauth.get_token_response(
            grant_type="token_exchange",
            data={
                'client_assertion_type': 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer',
                'subject_token_type': 'urn:ietf:params:oauth:token-type:id_token',
                'grant_type': 'urn:ietf:params:oauth:grant-type:token-exchange',
                'client_assertion': id_token_claims
            }
        )

        # Temp fix
        if resp['body']['error_description'] == 'Non-unique jti claim in JWT':
            client_assertion_jwt = self.oauth.create_jwt(kid="test-1")
            id_token_jwt = self.oauth.create_id_token_jwt(kid="identity-service-tests-1", claims=id_token_claims)

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

    @pytest.mark.errors
    @pytest.mark.token_exchange
    async def test_token_exchange_claims_assertion_invalid_exp_claim(self):
        # Given
        expected_status_code = 400
        expected_error = 'invalid_request'
        expected_error_description = "Invalid exp claim in JWT - more than 5 minutes in future"

        client_assertion_jwt = self.oauth.create_jwt(kid="test-1", claims={
            "sub": self.oauth.client_id,
            "iss": self.oauth.client_id,
            "jti": str(uuid4()),
            "aud": f"{OAUTH_URL}/token",
            "exp": int(time()) + 50000,
        })

        # When
        resp = await self.oauth.get_token_response(
            grant_type="token_exchange",
            data={
                'client_assertion_type': 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer',
                'subject_token_type': 'urn:ietf:params:oauth:token-type:id_token',
                'grant_type': 'urn:ietf:params:oauth:grant-type:token-exchange',
                'client_assertion': client_assertion_jwt
            }
        )

        # Then
        assert expected_status_code == resp['status_code']
        assert expected_error == resp['body']['error']
        assert expected_error_description == resp['body']['error_description']

    @pytest.mark.errors
    @pytest.mark.token_exchange
    async def test_token_exchange_claims_assertion_invalid_jti_claim(self):
        # Given
        expected_status_code = 400
        expected_error = 'invalid_request'
        expected_error_description = "Non-unique jti claim in JWT"

        id_token_claims = {
            'at_hash': 'tf_-lqpq36lwO7WmSBIJ6Q',
            'sub': '787807429511',
            'auditTrackingId': '91f694e6-3749-42fd-90b0-c3134b0d98f6-1546391',
            'amr': ['N3_SMARTCARD'],
            'iss': 'https://am.nhsint.ptl.nhsd-esa.net:443/'
                   'openam/oauth2/realms/root/realms/NHSIdentity/realms/Healthcare',
            'tokenName': 'id_token',
            'aud': '969567331415.apps.national',
            'c_hash': 'bc7zzGkClC3MEiFQ3YhPKg',
            'acr': 'AAL3_ANY',
            'org.forgerock.openidconnect.ops': '-I45NjmMDdMa-aNF2sr9hC7qEGQ',
            's_hash': 'LPJNul-wow4m6Dsqxbning',
            'azp': '969567331415.apps.national',
            'auth_time': 1610559802,
            'realm': '/NHSIdentity/Healthcare',
            'exp': int(time()) + 600,
            'tokenType': 'JWTToken',
            'iat': int(time()) - 10
        }

        client_assertion_jwt = self.oauth.create_jwt(kid="test-1")
        id_token_jwt = self.oauth.create_id_token_jwt(kid="identity-service-tests-1", claims=id_token_claims)

        # When
        await self.oauth.get_token_response(
            grant_type="token_exchange",
            data={
                'grant_type': 'urn:ietf:params:oauth:grant-type:token-exchange',
                'subject_token_type': 'urn:ietf:params:oauth:token-type:id_token',
                'client_assertion_type': 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer',
                'subject_token': id_token_jwt,
                'client_assertion': client_assertion_jwt
            }
        )

        # Second request should fail
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

    @pytest.mark.errors
    @pytest.mark.token_exchange
    async def test_token_exchange_subject_token_missing_iss_or_sub_claim(self):
        # Given
        expected_status_code = 400
        expected_error = 'invalid_request'
        expected_error_description = "Missing or non-matching iss/sub claims in JWT"

        id_token_claims = {
            'at_hash': 'tf_-lqpq36lwO7WmSBIJ6Q',
            'sub': '787807429511',
            'auditTrackingId': '91f694e6-3749-42fd-90b0-c3134b0d98f6-1546391',
            'amr': ['N3_SMARTCARD'],
            'tokenName': 'id_token',
            'aud': '969567331415.apps.national',
            'c_hash': 'bc7zzGkClC3MEiFQ3YhPKg',
            'acr': 'AAL3_ANY',
            'org.forgerock.openidconnect.ops': '-I45NjmMDdMa-aNF2sr9hC7qEGQ',
            's_hash': 'LPJNul-wow4m6Dsqxbning',
            'azp': '969567331415.apps.national',
            'auth_time': 1610559802,
            'realm': '/NHSIdentity/Healthcare',
            'exp': int(time()) + 600,
            'tokenType': 'JWTToken',
            'iat': int(time()) - 10
        }

        client_assertion_jwt = self.oauth.create_jwt(kid="test-1")
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

    @pytest.mark.errors
    @pytest.mark.token_exchange
    async def test_token_exchange_subject_token_missing_aud_claim(self):
        # Given
        expected_status_code = 400
        expected_error = 'invalid_request'
        expected_error_description = "Missing aud claim in JWT"

        id_token_claims = {
            'at_hash': 'tf_-lqpq36lwO7WmSBIJ6Q',
            'sub': '787807429511',
            'auditTrackingId': '91f694e6-3749-42fd-90b0-c3134b0d98f6-1546391',
            'iss': 'https://am.nhsint.ptl.nhsd-esa.net:443'
                   '/openam/oauth2/realms/root/realms/NHSIdentity/realms/Healthcare',
            'amr': ['N3_SMARTCARD'],
            'tokenName': 'id_token',
            'c_hash': 'bc7zzGkClC3MEiFQ3YhPKg',
            'acr': 'AAL3_ANY',
            'org.forgerock.openidconnect.ops': '-I45NjmMDdMa-aNF2sr9hC7qEGQ',
            's_hash': 'LPJNul-wow4m6Dsqxbning',
            'azp': '969567331415.apps.national',
            'auth_time': 1610559802,
            'realm': '/NHSIdentity/Healthcare',
            'exp': int(time()) + 600,
            'tokenType': 'JWTToken',
            'iat': int(time()) - 10
        }

        client_assertion_jwt = self.oauth.create_jwt(kid="test-1")
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

        # Temp fix
        if resp['body']['error_description'] == 'Non-unique jti claim in JWT':
            client_assertion_jwt = self.oauth.create_jwt(kid="test-1")
            id_token_jwt = self.oauth.create_id_token_jwt(kid="identity-service-tests-1", claims=id_token_claims)

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

    @pytest.mark.errors
    @pytest.mark.token_exchange
    async def test_token_exchange_subject_token_missing_exp_claim(self):
        # Given
        expected_status_code = 400
        expected_error = 'invalid_request'
        expected_error_description = "Missing exp claim in JWT"

        id_token_claims = {
            'at_hash': 'tf_-lqpq36lwO7WmSBIJ6Q',
            'sub': '787807429511',
            'auditTrackingId': '91f694e6-3749-42fd-90b0-c3134b0d98f6-1546391',
            'amr': ['N3_SMARTCARD'],
            'iss': 'https://am.nhsint.ptl.nhsd-esa.net:443'
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
            #'exp': int(time()) + 600,
            'tokenType': 'JWTToken',
            'iat': int(time()) - 10
        }

        client_assertion_jwt = self.oauth.create_jwt(kid="test-1")
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

        # Temp fix
        if resp['body']['error_description'] == 'Non-unique jti claim in JWT':
            client_assertion_jwt = self.oauth.create_jwt(kid="test-1")
            id_token_jwt = self.oauth.create_id_token_jwt(kid="identity-service-tests-1", claims=id_token_claims)

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
