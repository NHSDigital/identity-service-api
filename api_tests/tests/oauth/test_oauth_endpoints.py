from api_tests.scripts import config
from api_tests.scripts.response_bank import BANK
import pytest
import random
import requests
import jwt
from uuid import uuid4
from time import time, sleep
import json


@pytest.mark.asyncio
class TestOauthEndpoints:
    """ A test suit to verify all the oauth endpoints """

    def _update_secrets(self, request):
        key = ("params", "data")[request.get('params', None) is None]
        if request[key].get("client_id", None) == "/replace_me":
            request[key]['client_id'] = self.oauth.client_id

        if request[key].get("client_secret", None) == "/replace_me":
            request[key]['client_secret'] = self.oauth.client_secret

        if request[key].get("redirect_uri", None) == "/replace_me":
            request[key]['redirect_uri'] = self.oauth.redirect_uri

    @pytest.mark.apm_801
    @pytest.mark.happy_path
    @pytest.mark.authorize_endpoint
    async def test_authorize_endpoint(self):
        resp = await self.oauth.hit_oauth_endpoint(
            method="GET",
            endpoint="authorize",
            params={
                "client_id": self.oauth.client_id,
                "redirect_uri": self.oauth.redirect_uri,
                "response_type": "code",
                "state": random.getrandbits(32)
            }
        )

        assert resp['status_code'] == 200
        # assert resp['body'] == BANK.get(self.name)["response"]

    @pytest.mark.apm_801
    @pytest.mark.happy_path
    @pytest.mark.token_endpoint
    async def test_token_endpoint(self):
        resp = await self.oauth.get_token_response(grant_type="authorization_code")

        assert resp['status_code'] == 200
        assert sorted(list(resp['body'].keys())) == [
            "access_token",
            "expires_in",
            "refresh_count",
            "refresh_token",
            "refresh_token_expires_in",
            "token_type",
        ]

    @pytest.mark.apm_1618
    @pytest.mark.apm_1475
    @pytest.mark.errors
    @pytest.mark.token_endpoint
    @pytest.mark.authorize_endpoint
    @pytest.mark.parametrize(
        "method, endpoint",
        [
            ("GET", "token"),
            ("POST", "authorize"),
        ],
    )
    async def test_token_endpoint_http_allowed_methods(self, method, endpoint):
        resp = await self.oauth.hit_oauth_endpoint(
            method=method,
            endpoint=endpoint
        )

        allow = ("POST", "GET")[method == "POST"]

        assert resp['status_code'] == 405
        assert resp['body'] == ""
        assert resp['headers'].get("Allow", "The Allow Header is Missing") == allow

    @pytest.mark.apm_993
    @pytest.mark.errors
    @pytest.mark.authorize_endpoint
    async def test_cache_invalidation(self, helper):
        """
        Test identity cache invalidation after use:
            * Given i am authorizing
            * When the first request has succeeded
            * When using the same state as the first request
            * Then it should return xxx
        """

        # Make authorize request to retrieve state2
        response = await self.oauth.hit_oauth_endpoint(
            method="GET",
            endpoint="authorize",
            params={
                "client_id": self.oauth.client_id,
                "redirect_uri": self.oauth.redirect_uri,
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
                "client_id": self.oauth.client_id,
                "redirect_uri": self.oauth.redirect_uri,
                "scope": "openid",
                "state": state,
            },
            headers={"Content-Type": "application/x-www-form-urlencoded"},
            data={"state": state},
            allow_redirects=False,
        )

        # Make initial callback request
        auth_code = helper.get_param_from_url(
            url=response["headers"]["Location"], param="code"
        )

        response = await self.oauth.hit_oauth_endpoint(
            method="GET",
            endpoint="callback",
            params={"code": auth_code, "client_id": "some-client-id", "state": state},
            allow_redirects=False,
        )

        # Verify auth code and state are returned
        # response_params = helper.get_params_from_url(response["headers"]["Location"])
        helper.verify_params_exist_in_url(params=['code', 'state'], url=response["headers"]["Location"])

        # Make second callback request with same state value
        assert helper.check_endpoint(
            verb="GET",
            endpoint=f"{config.OAUTH_BASE_URI}/{config.OAUTH_PROXY}/callback",
            expected_status_code=400,
            expected_response={
                "error": "invalid_request",
                "error_description": "invalid state parameter.",
            },
            params={"code": auth_code, "client_id": "some-client-id", "state": state},
        )

    @pytest.mark.apm_801
    @pytest.mark.apm_990
    @pytest.mark.apm_1475
    @pytest.mark.errors
    @pytest.mark.authorize_endpoint
    @pytest.mark.parametrize(
        "request_data",
        [
            # condition 1: invalid redirect uri
            {
                "expected_status_code": 400,
                "expected_response": {
                    "error": "invalid_request",
                    "error_description": "redirect_uri is invalid",
                },
                "params": {
                    "client_id": "/replace_me",
                    "redirect_uri": f"/invalid",  # invalid redirect uri
                    "response_type": "code",
                    "state": random.getrandbits(32),
                },
            },
            # condition 2: missing redirect uri
            {
                "expected_status_code": 400,
                "expected_response": {
                    "error": "invalid_request",
                    "error_description": "redirect_uri is missing",
                },
                "params": {
                    "client_id": "/replace_me",
                    "response_type": "code",
                    "state": random.getrandbits(32),
                },
            },
            # condition 3: invalid client id
            {
                "expected_status_code": 401,
                "expected_response": {
                    "error": "invalid_request",
                    "error_description": "client_id is invalid",
                },
                "params": {
                    "client_id": "invalid",  # invalid client id
                    "redirect_uri": "/replace_me",
                    "response_type": "code",
                    "state": random.getrandbits(32),
                },
            },
            # condition 4: missing client id
            {
                "expected_status_code": 401,
                "expected_response": {
                    "error": "invalid_request",
                    "error_description": "client_id is missing",
                },
                "params": {  # not providing client_id
                    "redirect_uri": "/replace_me",
                    "response_type": "code",
                    "state": random.getrandbits(32),
                }
            }
        ],
    )
    async def test_authorization_error_conditions(self, request_data: dict, helper):
        self._update_secrets(request_data)

        assert await helper.send_request_and_check_output(
            expected_status_code=request_data['expected_status_code'],
            expected_response=request_data['expected_response'],
            function=self.oauth.hit_oauth_endpoint,
            method="GET",
            endpoint="authorize",
            params=request_data["params"]
        )

    @pytest.mark.errors
    @pytest.mark.authorize_endpoint
    async def test_authorize_revoked_app(self, app, helper):
        await app.create_new_app(status="revoked")

        assert await helper.send_request_and_check_output(
            expected_status_code=401,
            expected_response={
                "error": "access_denied",
                "error_description": "The developer app associated with the API key is not approved or revoked",
            },
            function=self.oauth.hit_oauth_endpoint,
            method="GET",
            endpoint="authorize",
            params={
                "client_id": app.client_id,
                "redirect_uri": app.callback_url,
                "response_type": "code",
                "state": random.getrandbits(32),
            }
        )

    async def test_authorize_unsubscribed_error_condition(self, test_product, test_app, helper):
        await test_product.update_proxies(["hello-world-internal-dev"])
        await test_app.add_api_product([test_product.name])

        assert await helper.send_request_and_check_output(
            expected_status_code=401,
            expected_response={
                    'error': 'access_denied',
                    'error_description': 'API Key supplied does not have access to this resource. '
                                         'Please check the API Key you are using belongs to an app '
                                         'which has sufficient access to access this resource.'
                },
            function=self.oauth.hit_oauth_endpoint,
            method="GET",
            endpoint="authorize",
            params={
                "client_id": test_app.client_id,
                "redirect_uri": test_app.callback_url,
                "response_type": "code",
                "state": random.getrandbits(32),
            }
        )

    @pytest.mark.apm_1631
    @pytest.mark.errors
    @pytest.mark.token_endpoint
    async def test_token_unsubscribed_error_condition(self, test_product, test_app, helper):
        await test_product.update_proxies(["hello-world-internal-dev"])
        await test_app.add_api_product([test_product.name])

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
                "client_id": test_app.client_id,
                "client_secret": test_app.client_secret,
                "redirect_uri": test_app.callback_url,
                "grant_type": "authorization_code",
                "code": await self.oauth.get_authenticated_with_simulated_auth()
            }
        )

    @pytest.mark.apm_1475
    @pytest.mark.errors
    @pytest.mark.authorize_endpoint
    @pytest.mark.parametrize(
        "test_case",
        [
            # condition 1: missing state
            {
                "expected_status_code": 302,
                "expected_response": "",
                "expected_params": {
                    "error": "invalid_request",
                    "error_description": "state is missing",
                },
                "params": {
                    "client_id": "/replace_me",
                    "redirect_uri": "/replace_me",
                    "response_type": "code",
                },
            },
            # condition 2: missing response type
            {
                "expected_status_code": 302,
                "expected_response": "",
                "expected_params": {
                    "error": "invalid_request",
                    "error_description": "response_type is missing",
                },
                "params": {
                    "client_id": "/replace_me",
                    "redirect_uri": "/replace_me",
                    "state": random.getrandbits(32),
                },
            },
            # condition 5: invalid response type
            {
                "expected_status_code": 302,
                "expected_response": "",
                "expected_params": {
                    "error": "unsupported_response_type",
                    "error_description": "response_type is invalid",
                },
                "params": {
                    "client_id": "/replace_me",
                    "redirect_uri": "/replace_me",
                    "response_type": "invalid",  # invalid response type
                    "state": random.getrandbits(32),
                },
            },
        ],
    )
    async def test_authorization_error_redirects(self, test_case: dict, helper):
        self._update_secrets(test_case)

        resp = await self.oauth.hit_oauth_endpoint(
            method="GET",
            endpoint="authorize",
            params=test_case['params'],
            allow_redirects=False
        )

        assert resp['status_code'] == test_case['expected_status_code']
        assert resp['body'] == test_case['expected_response']

        helper.check_redirect(
            response=resp,
            expected_params=test_case["expected_params"],
            client_redirect=self.oauth.redirect_uri,
            state=test_case["params"].get("state")
        )

    @pytest.mark.apm_1618
    @pytest.mark.errors
    @pytest.mark.token_endpoint
    @pytest.mark.parametrize(
        "request_data, expected_response",
        [
            # condition 1: no data provided
            (
                {
                    "data": {}
                },

                {
                    "status_code": 400,
                    "body": {
                        "error": "invalid_request",
                        "error_description": "grant_type is missing",
                    }
                }
            ),

            # condition 2: invalid grant type
            (
                {
                    "headers": {"Content-Type": "application/x-www-form-urlencoded"},
                    "data": {
                        "client_id": "/replace_me",
                        "client_secret": "/replace_me",
                        "redirect_uri": "/replace_me",
                        "grant_type": "invalid",
                    }
                },

                {
                    "status_code": 400,
                    "body": {
                        "error": "unsupported_grant_type",
                        "error_description": "grant_type is invalid",
                    }
                }
            ),

            # condition 3: missing grant_type
            (
                {
                    "headers": {"Content-Type": "application/x-www-form-urlencoded"},
                    "data": {
                        "client_id": "/replace_me",
                        "client_secret": "/replace_me",
                        "redirect_uri": "/replace_me",
                    }
                },

                {
                    "status_code": 400,
                    "body": {
                        "error": "invalid_request",
                        "error_description": "grant_type is missing",
                    }
                }
            ),

            # condition 4: missing client_id
            (
                {
                    "headers": {"Content-Type": "application/x-www-form-urlencoded"},
                    "data": {
                        "client_secret": "/replace_me",
                        "redirect_uri": "/replace_me",
                        "grant_type": "authorization_code",
                    }
                },

                {
                    "status_code": 401,
                    "body": {
                        "error": "invalid_request",
                        "error_description": "client_id is missing",
                    }
                }
            ),

            # condition 5: invalid client_id
            (
                {
                    "headers": {"Content-Type": "application/x-www-form-urlencoded"},
                    "data": {
                        "client_id": "THISisANinvalidCLIENTid12345678",
                        "client_secret": "/replace_me",
                        "redirect_uri": "/replace_me",
                        "grant_type": "authorization_code",
                    }
                },

                {
                    "status_code": 401,
                    "body": {
                        "error": "invalid_client",
                        "error_description": "client_id or client_secret is invalid",
                    }
                }
            ),

            # condition 6: invalid client secret
            (
                {
                    "headers": {"Content-Type": "application/x-www-form-urlencoded"},
                    "data": {
                        "client_id": "/replace_me",
                        "client_secret": "ThisSecretIsInvalid",
                        "redirect_uri": "/replace_me",
                        "grant_type": "authorization_code",
                    }
                },

                {
                    "status_code": 401,
                    "body": {
                        "error": "invalid_client",
                        "error_description": "client_id or client_secret is invalid",
                    }
                }
            ),

            # condition 7: missing client secret
            (
                {
                    "headers": {"Content-Type": "application/x-www-form-urlencoded"},
                    "data": {
                        "client_id": "/replace_me",
                        "redirect_uri": "/replace_me",
                        "grant_type": "authorization_code",
                    }
                },

                {
                    "status_code": 401,
                    "body": {
                        "error": "invalid_request",
                        "error_description": "client_secret is missing",
                    }
                }
            ),

            # condition 8: redirect_uri is missing
            (
                {
                    "headers": {"Content-Type": "application/x-www-form-urlencoded"},
                    "data": {
                        "client_id": "/replace_me",
                        "client_secret": "/replace_me",
                        "grant_type": "authorization_code",
                    }
                },

                {
                    "status_code": 400,
                    "body": {
                        "error": "invalid_request",
                        "error_description": "redirect_uri is missing",
                    }
                }
            ),

            # condition 9: redirect_uri is invalid
            (
                {
                    "headers": {"Content-Type": "application/x-www-form-urlencoded"},
                    "data": {
                        "client_id": "/replace_me",
                        "client_secret": "/replace_me",
                        "redirect_uri": 'invalid',
                        "grant_type": "authorization_code",
                    }
                },

                {
                    "status_code": 400,
                    "body": {
                        "error": "invalid_request",
                        "error_description": "redirect_uri is invalid",
                    }
                }
            ),

            # condition 10: authorization code is missing
            (
                {
                    "headers": {"Content-Type": "application/x-www-form-urlencoded"},
                    "data": {
                        "client_id": "/replace_me",
                        "client_secret": "/replace_me",
                        "redirect_uri": "/replace_me",
                        "grant_type": "authorization_code",
                    }
                },

                {
                    "status_code": 400,
                    "body": {
                        "error": "invalid_request",
                        "error_description": "authorization_code is missing",
                    }
                }
            ),

            # condition 11: authorization code is invalid
            (
                {
                    "headers": {"Content-Type": "application/x-www-form-urlencoded"},
                    "data": {
                        "client_id": "/replace_me",
                        "client_secret": "/replace_me",
                        "redirect_uri": "/replace_me",
                        "grant_type": "authorization_code",
                        "code": "invalid",
                    }
                },

                {
                    "status_code": 400,
                    "body": {
                        "error": "invalid_grant",
                        "error_description": "authorization_code is invalid",
                    }
                }
            ),
        ],
    )
    async def test_token_error_conditions(self, request_data: dict, expected_response: dict, helper):
        self._update_secrets(request_data)
        assert await helper.send_request_and_check_output(
            expected_status_code=expected_response["status_code"],
            expected_response=expected_response["body"],
            function=self.oauth.get_token_response,
            grant_type="authorization_code",
            **request_data
        )

    @pytest.mark.apm_1064
    @pytest.mark.errors
    @pytest.mark.callback_endpoint
    async def test_callback_error_conditions(self, helper):
        assert await helper.send_request_and_check_output(
            expected_status_code=401,
            expected_response="",
            function=self.oauth.hit_oauth_endpoint,
            method="GET",
            endpoint="callback",
            params={
                "code": "some-code",
                "client_id": "invalid-client-id",
                "state": random.getrandbits(32),
            }
        )

    @pytest.mark.apm_1475
    @pytest.mark.errors
    @pytest.mark.token_endpoint
    @pytest.mark.parametrize(
        "test_case",
        [
            # condition 1: missing client id
            {
                "expected_status_code": 401,
                "expected_response": {
                    "error": "invalid_request",
                    "error_description": "client_id is missing",
                },
                "data": {
                    'client_secret': "/replace_me",
                    'grant_type': 'refresh_token',
                },
            },
            # condition 2: invalid client_id
            {
                "expected_status_code": 401,
                "expected_response": {
                    "error": "invalid_client",
                    "error_description": "client_id or client_secret is invalid",
                },
                "data": {
                    "client_id": "invalid-client-id",
                    'client_secret': "/replace_me",
                    'grant_type': 'refresh_token',
                },
            },
            # condition 2: missing client_secret
            {
                "expected_status_code": 401,
                "expected_response": {
                    "error": "invalid_request",
                    "error_description": "client_secret is missing",
                },
                "data": {
                    "client_id": "/replace_me",
                    'grant_type': 'refresh_token',
                },
            },
            # condition 4: invalid client_secret
            {
                "expected_status_code": 401,
                "expected_response": {
                    "error": "invalid_client",
                    "error_description": "client_id or client_secret is invalid",
                },
                "data": {
                    "client_id": "/replace_me",
                    'client_secret': 'invalid',
                    'grant_type': 'refresh_token',
                },
            },
            # condition 5: missing refresh_token
            {
                "expected_status_code": 400,
                "expected_response": {
                    "error": "invalid_request",
                    "error_description": "refresh_token is missing",
                },
                "data": {
                    "client_id": "/replace_me",
                    'client_secret': "/replace_me",
                    'grant_type': 'refresh_token',
                },
            },
            # condition 6: invalid refresh_token
            {
                "expected_status_code": 401,
                "expected_response": {
                    "error": "invalid_grant",
                    "error_description": "refresh_token is invalid",
                },
                "data": {
                    "client_id": "/replace_me",
                    'client_secret': "/replace_me",
                    'grant_type': 'refresh_token',
                    'refresh_token': 'invalid'
                },
            },
        ],
    )
    async def test_refresh_token_error_conditions(self, test_case: dict, helper):
        self._update_secrets(test_case)
        assert await helper.send_request_and_check_output(
            expected_status_code=test_case['expected_status_code'],
            expected_response=test_case['expected_response'],
            function=self.oauth.get_token_response,
            grant_type="refresh_token",
            data=test_case['data']
        )

    async def test_ping(self, helper):
        assert await helper.send_request_and_check_output(
            expected_status_code=200,
            expected_response=["version", "revision", "releaseId", "commitId"],
            function=self.oauth.hit_oauth_endpoint,
            method="GET",
            endpoint="_ping"
        )

    @pytest.mark.aea_756
    @pytest.mark.happy_path
    @pytest.mark.usefixtures("set_access_token")
    async def test_userinfo(self, helper):
        assert await helper.send_request_and_check_output(
            expected_status_code=200,
            expected_response=BANK.get(self.name)["response"],
            function=self.oauth.hit_oauth_endpoint,
            method="GET",
            endpoint="userinfo",
            headers={'Authorization': f'Bearer {self.oauth.access_token}'}
        )

    @pytest.mark.happy_path
    @pytest.mark.token_exchange
    @pytest.mark.usefixtures('get_token')
    def test_token_exchange_happy_path(self):
        # Given
        expected_status_code = 200
        expected_expires_in = '599'
        expected_token_type = 'Bearer'
        expected_issued_token_type = 'urn:ietf:params:oauth:token-type:access_token'

        id_token_claims = {
            'at_hash': 'tf_-lqpq36lwO7WmSBIJ6Q',
            'sub': '787807429511',
            'auditTrackingId': '91f694e6-3749-42fd-90b0-c3134b0d98f6-1546391',
            'amr': ['N3_SMARTCARD'],
            'iss': 'https://am.nhsint.ptl.nhsd-esa.net:443/openam/oauth2/realms/root/realms/NHSIdentity/realms/Healthcare',
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

        client_assertion_claims = {
            "sub": self.oauth.client_id,
            "iss": self.oauth.client_id,
            "jti": str(uuid4()),
            "aud": f"{config.OAUTH_URL}/token",
            "exp": int(time()) + 5,
        }

        id_token_jwt = jwt.encode(id_token_claims, config.ID_TOKEN_PRIVATE_KEY_ABSOLUTE_PATH, algorithm='RS256', headers={'kid': 'identity-service-tests-1'})
        client_assertion_jwt = jwt.encode(client_assertion_claims, config.JWT_PRIVATE_KEY_ABSOLUTE_PATH, algorithm='RS512', headers={'kid': 'test-1'})

        # When
        response = requests.post(
            url=f"{config.OAUTH_URL}/token",
            data={
                'grant_type': 'urn:ietf:params:oauth:grant-type:token-exchange',
                'subject_token_type': 'urn:ietf:params:oauth:token-type:id_token',
                'client_assertion_type': 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer',
                'subject_token': id_token_jwt,
                'client_assertion': client_assertion_jwt
            }
        )
        sleep(2)

        # Then
        response_dict = json.loads(response.text)

        assert expected_status_code == response.status_code, response.text
        assert 'access_token' in response_dict
        assert expected_expires_in == response_dict['expires_in']
        assert expected_token_type == response_dict['token_type']
        assert expected_issued_token_type == response_dict['issued_token_type']

    @pytest.mark.errors
    @pytest.mark.token_exchange
    @pytest.mark.skip(reason='feature turned off')
    @pytest.mark.usefixtures('get_token')
    def test_token_exchange_invalid_client_assertion_type(self):
        # Given
        expected_status_code = 400
        expected_error = 'invalid_request'
        expected_error_description = "Missing or invalid client_assertion_type - must be 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer"
        # When
        response = requests.post(
            url=f"{config.OAUTH_URL}/token",
            data={
                'client_assertion_type': 'Invalid',
                'grant_type': 'urn:ietf:params:oauth:grant-type:token-exchange',
                'subject_token_type': 'urn:ietf:params:oauth:token-type:id_token'
            }
        )
        sleep(2)

        response_dict = json.loads(response.text)

        # Then
        assert expected_status_code == response.status_code
        assert expected_error == response_dict['error']
        assert expected_error_description == response_dict['error_description']
        assert 'message_id' in response_dict

    @pytest.mark.errors
    @pytest.mark.token_exchange
    @pytest.mark.skip(reason='feature turned off')
    @pytest.mark.usefixtures('get_token')
    def test_token_exchange_invalid_subject_token_type(self):
        # Given
        expected_status_code = 400
        expected_error = 'invalid_request'
        expected_error_description = "missing or invalid subject_token_type - must be 'urn:ietf:params:oauth:token-type:id_token'"
        # When
        response = requests.post(
            url= f"{config.OAUTH_URL}/token",
            data= {
                'client_assertion_type': 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer',
                'subject_token_type': 'Invalid',
                'grant_type': 'urn:ietf:params:oauth:grant-type:token-exchange'
            }
        )
        sleep(2)

        response_dict = json.loads(response.text)

        # Then
        assert expected_status_code == response.status_code
        assert expected_error == response_dict['error']
        assert expected_error_description == response_dict['error_description']
        assert 'message_id' in response_dict

    @pytest.mark.errors
    @pytest.mark.token_exchange
    @pytest.mark.skip(reason='feature turned off')
    @pytest.mark.usefixtures('get_token')
    def test_token_exchange_claims_assertion_invalid_kid(self):
        # Given
        expected_status_code = 400
        expected_error = 'invalid_request'
        expected_error_description = "Missing 'kid' header in JWT"

        client_assertion_claims = {
            "sub": self.oauth.client_id,
            "iss": self.oauth.client_id,
            "jti": str(uuid4()),
            "aud": f"{config.OAUTH_URL}/token",
            "exp": int(time()) + 5,
        }

        client_assertion_jwt = jwt.encode(client_assertion_claims, config.JWT_PRIVATE_KEY_ABSOLUTE_PATH, algorithm='RS512')

        # When
        response = requests.post(
            url= f"{config.OAUTH_URL}/token",
            data= {
                'client_assertion_type': 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer',
                'subject_token_type': 'urn:ietf:params:oauth:token-type:id_token',
                'grant_type': 'urn:ietf:params:oauth:grant-type:token-exchange',
                'client_assertion': client_assertion_jwt
            }
        )

        sleep(2)

        response_dict = json.loads(response.text)

        # Then
        assert expected_status_code == response.status_code
        assert expected_error == response_dict['error']
        assert expected_error_description == response_dict['error_description']
        assert 'message_id' in response_dict

    @pytest.mark.errors
    @pytest.mark.token_exchange
    @pytest.mark.skip(reason='feature turned off')
    @pytest.mark.usefixtures('get_token')
    def test_token_exchange_claims_assertion_invalid_typ_header(self):
        # Given
        expected_status_code = 400
        expected_error = 'invalid_request'
        expected_error_description = "Invalid 'typ' header in JWT - must be 'JWT'"

        client_assertion_claims = {
            "sub": self.oauth.client_id,
            "iss": self.oauth.client_id,
            "jti": str(uuid4()),
            "aud": f"{config.OAUTH_URL}/token",
            "exp": int(time()) + 5,
        }

        client_assertion_jwt = jwt.encode(client_assertion_claims, config.JWT_PRIVATE_KEY_ABSOLUTE_PATH, algorithm='RS512', headers={'kid': 'test-1', 'typ': 'invalid'})

        # When
        response = requests.post(
            url= f"{config.OAUTH_URL}/token",
            data= {
                'client_assertion_type': 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer',
                'subject_token_type': 'urn:ietf:params:oauth:token-type:id_token',
                'grant_type': 'urn:ietf:params:oauth:grant-type:token-exchange',
                'client_assertion': client_assertion_jwt
            }
        )
        sleep(2)
        response_dict = json.loads(response.text)

        # Then
        assert expected_status_code == response.status_code
        assert expected_error == response_dict['error']
        assert expected_error_description == response_dict['error_description']
        assert 'message_id' in response_dict

    @pytest.mark.errors
    @pytest.mark.token_exchange
    @pytest.mark.skip(reason='feature turned off')
    @pytest.mark.usefixtures('get_token')
    def test_token_exchange_claims_assertion_invalid_iss_claim(self):
        # Given
        expected_status_code = 400
        expected_error = 'invalid_request'
        expected_error_description = "Missing or non-matching iss/sub claims in JWT"

        client_assertion_claims = {
            "sub": '',
            "jti": str(uuid4()),
            "aud": f"{config.OAUTH_URL}/token",
            "exp": int(time()) + 5,
        }

        client_assertion_jwt = jwt.encode(client_assertion_claims, config.JWT_PRIVATE_KEY_ABSOLUTE_PATH, algorithm='RS512', headers={'kid': 'test-1'})

        # When
        response = requests.post(
            url= f"{config.OAUTH_URL}/token",
            data= {
                'client_assertion_type': 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer',
                'subject_token_type': 'urn:ietf:params:oauth:token-type:id_token',
                'grant_type': 'urn:ietf:params:oauth:grant-type:token-exchange',
                'client_assertion': client_assertion_jwt
            }
        )
        sleep(2)

        response_dict = json.loads(response.text)

        # Then
        assert expected_status_code == response.status_code
        assert expected_error == response_dict['error']
        assert expected_error_description == response_dict['error_description']
        assert 'message_id' in response_dict

    @pytest.mark.errors
    @pytest.mark.token_exchange
    @pytest.mark.skip(reason='feature turned off')
    @pytest.mark.usefixtures('get_token')
    def test_token_exchange_claims_assertion_missing_jti_claim(self):
        # Given
        expected_status_code = 400
        expected_error = 'invalid_request'
        expected_error_description = "Missing jti claim in JWT"

        client_assertion_claims = {
            "sub": self.oauth.client_id,
            "iss": self.oauth.client_id,
            "jti": '',
            "aud": f"{config.OAUTH_URL}/token",
            "exp": int(time()) + 5,
        }

        client_assertion_jwt = jwt.encode(client_assertion_claims, config.JWT_PRIVATE_KEY_ABSOLUTE_PATH, algorithm='RS512', headers={'kid': 'test-1'})

        # When
        response = requests.post(
            url= f"{config.OAUTH_URL}/token",
            data= {
                'client_assertion_type': 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer',
                'subject_token_type': 'urn:ietf:params:oauth:token-type:id_token',
                'grant_type': 'urn:ietf:params:oauth:grant-type:token-exchange',
                'client_assertion': client_assertion_jwt
            }
        )
        sleep(2)

        response_dict = json.loads(response.text)

        # Then
        assert expected_status_code == response.status_code
        assert expected_error == response_dict['error']
        assert expected_error_description == response_dict['error_description']
        assert 'message_id' in response_dict

    @pytest.mark.errors
    @pytest.mark.token_exchange
    @pytest.mark.skip(reason='feature turned off')
    @pytest.mark.usefixtures('get_token')
    def test_token_exchange_claims_assertion_missing_exp_claim(self):
        # Given
        expected_status_code = 400
        expected_error = 'invalid_request'
        expected_error_description = "Missing exp claim in JWT"

        client_assertion_claims = {
            "sub": self.oauth.client_id,
            "iss": self.oauth.client_id,
            "jti": str(uuid4()),
            "aud": f"{config.OAUTH_URL}/token",
        }

        client_assertion_jwt = jwt.encode(client_assertion_claims, config.JWT_PRIVATE_KEY_ABSOLUTE_PATH, algorithm='RS512', headers={'kid': 'test-1'})

        # When
        response = requests.post(
            url= f"{config.OAUTH_URL}/token",
            data= {
                'client_assertion_type': 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer',
                'subject_token_type': 'urn:ietf:params:oauth:token-type:id_token',
                'grant_type': 'urn:ietf:params:oauth:grant-type:token-exchange',
                'client_assertion': client_assertion_jwt
            }
        )
        sleep(2)

        response_dict = json.loads(response.text)

        # Then
        assert expected_status_code == response.status_code
        assert expected_error == response_dict['error']
        assert expected_error_description == response_dict['error_description']
        assert 'message_id' in response_dict

    @pytest.mark.errors
    @pytest.mark.token_exchange
    @pytest.mark.skip(reason='feature turned off')
    @pytest.mark.usefixtures('get_token')
    def test_token_exchange_claims_assertion_invalid_exp_claim(self):
        # Given
        expected_status_code = 400
        expected_error = 'invalid_request'
        expected_error_description = "Invalid exp claim in JWT - more than 5 minutes in future"

        client_assertion_claims = {
            "sub": self.oauth.client_id,
            "iss": self.oauth.client_id,
            "jti": str(uuid4()),
            "aud": f"{config.OAUTH_URL}/token",
            "exp": int(time()) + 50000,
        }

        client_assertion_jwt = jwt.encode(client_assertion_claims, config.JWT_PRIVATE_KEY_ABSOLUTE_PATH, algorithm='RS512', headers={'kid': 'test-1'})

        # When
        response = requests.post(
            url= f"{config.OAUTH_URL}/token",
            data= {
                'client_assertion_type': 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer',
                'subject_token_type': 'urn:ietf:params:oauth:token-type:id_token',
                'grant_type': 'urn:ietf:params:oauth:grant-type:token-exchange',
                'client_assertion': client_assertion_jwt
            }
        )
        sleep(2)

        response_dict = json.loads(response.text)

        # Then
        assert expected_status_code == response.status_code
        assert expected_error == response_dict['error']
        assert expected_error_description == response_dict['error_description']
        assert 'message_id' in response_dict

    @pytest.mark.errors
    @pytest.mark.token_exchange
    @pytest.mark.skip(reason='feature turned off')
    @pytest.mark.usefixtures('get_token')
    def test_token_exchange_claims_assertion_invalid_jti_claim(self):
        # Given
        expected_status_code = 400
        expected_error = 'invalid_request'
        expected_error_description = "Non-unique jti claim in JWT"

        id_token_claims = {
            'at_hash': 'tf_-lqpq36lwO7WmSBIJ6Q',
            'sub': '787807429511',
            'auditTrackingId': '91f694e6-3749-42fd-90b0-c3134b0d98f6-1546391',
            'amr': ['N3_SMARTCARD'],
            'iss': 'https://am.nhsint.ptl.nhsd-esa.net:443/openam/oauth2/realms/root/realms/NHSIdentity/realms/Healthcare',
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

        client_assertion_claims = {
            "sub": self.oauth.client_id,
            "iss": self.oauth.client_id,
            "jti": str(uuid4()),
            "aud": f"{config.OAUTH_URL}/token",
            "exp": int(time()) + 5,
        }

        id_token_jwt = jwt.encode(id_token_claims, config.ID_TOKEN_PRIVATE_KEY_ABSOLUTE_PATH, algorithm='RS256', headers={'kid': 'identity-service-tests-1'})
        client_assertion_jwt = jwt.encode(client_assertion_claims, config.JWT_PRIVATE_KEY_ABSOLUTE_PATH, algorithm='RS512', headers={'kid': 'test-1'})

        # When
        response = requests.post(
            url=f"{config.OAUTH_URL}/token",
            data= {
                'grant_type': 'urn:ietf:params:oauth:grant-type:token-exchange',
                'subject_token_type': 'urn:ietf:params:oauth:token-type:id_token',
                'client_assertion_type': 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer',
                'subject_token': id_token_jwt,
                'client_assertion': client_assertion_jwt
            }
        )
        sleep(2)

        response = requests.post(
            url=f"{config.OAUTH_URL}/token",
            data= {
                'grant_type': 'urn:ietf:params:oauth:grant-type:token-exchange',
                'subject_token_type': 'urn:ietf:params:oauth:token-type:id_token',
                'client_assertion_type': 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer',
                'subject_token': id_token_jwt,
                'client_assertion': client_assertion_jwt
            }
        )

        # Then
        response_dict = json.loads(response.text)

        # Then
        assert expected_status_code == response.status_code
        assert expected_error == response_dict['error']
        assert expected_error_description == response_dict['error_description']
        assert 'message_id' in response_dict


    @pytest.mark.errors
    @pytest.mark.token_exchange
    @pytest.mark.skip(reason='feature turned off')
    @pytest.mark.usefixtures('get_token')
    def test_token_exchange_subject_token_missing_iss_or_sub_claim(self):
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

        client_assertion_claims = {
            "sub": self.oauth.client_id,
            "iss": self.oauth.client_id,
            "jti": str(uuid4()),
            "aud": f"{config.OAUTH_URL}/token",
            "exp": int(time()) + 5,
        }

        client_assertion_jwt = jwt.encode(client_assertion_claims, config.JWT_PRIVATE_KEY_ABSOLUTE_PATH, algorithm='RS512', headers={'kid': 'test-1'})
        id_token_jwt = jwt.encode(id_token_claims, config.ID_TOKEN_PRIVATE_KEY_ABSOLUTE_PATH, algorithm='RS256', headers={'kid': 'identity-service-tests-1'})

        # When
        response = requests.post(
            url= f"{config.OAUTH_URL}/token",
            data= {
                'grant_type': 'urn:ietf:params:oauth:grant-type:token-exchange',
                'subject_token_type': 'urn:ietf:params:oauth:token-type:id_token',
                'client_assertion_type': 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer',
                'subject_token': id_token_jwt,
                'client_assertion': client_assertion_jwt
            }
        )
        sleep(2)

        response_dict = json.loads(response.text)

        # Then
        assert expected_status_code == response.status_code
        assert expected_error == response_dict['error']
        assert expected_error_description == response_dict['error_description']
        assert 'message_id' in response_dict

    @pytest.mark.errors
    @pytest.mark.token_exchange
    @pytest.mark.skip(reason='feature turned off')
    @pytest.mark.usefixtures('get_token')
    def test_token_exchange_subject_token_missing_aud_claim(self):
        # Given
        expected_status_code = 400
        expected_error = 'invalid_request'
        expected_error_description = "Missing aud claim in JWT"

        id_token_claims = {
            'at_hash': 'tf_-lqpq36lwO7WmSBIJ6Q',
            'sub': '787807429511',
            'auditTrackingId': '91f694e6-3749-42fd-90b0-c3134b0d98f6-1546391',
            'iss': 'https://am.nhsint.ptl.nhsd-esa.net:443/openam/oauth2/realms/root/realms/NHSIdentity/realms/Healthcare',
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

        client_assertion_claims = {
            "sub": self.oauth.client_id,
            "iss": self.oauth.client_id,
            "jti": str(uuid4()),
            "aud": f"{config.OAUTH_URL}/token",
            "exp": int(time()) + 5,
        }

        client_assertion_jwt = jwt.encode(client_assertion_claims, config.JWT_PRIVATE_KEY_ABSOLUTE_PATH, algorithm='RS512', headers={'kid': 'test-1'})
        id_token_jwt = jwt.encode(id_token_claims, config.ID_TOKEN_PRIVATE_KEY_ABSOLUTE_PATH, algorithm='RS256', headers={'kid': 'identity-service-tests-1'})

        # When
        response = requests.post(
            url= f"{config.OAUTH_URL}/token",
            data= {
                'grant_type': 'urn:ietf:params:oauth:grant-type:token-exchange',
                'subject_token_type': 'urn:ietf:params:oauth:token-type:id_token',
                'client_assertion_type': 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer',
                'subject_token': id_token_jwt,
                'client_assertion': client_assertion_jwt
            }
        )
        sleep(2)

        response_dict = json.loads(response.text)

        # Then
        assert expected_status_code == response.status_code
        assert expected_error == response_dict['error']
        assert expected_error_description == response_dict['error_description']
        assert 'message_id' in response_dict

    @pytest.mark.errors
    @pytest.mark.token_exchange
    @pytest.mark.skip(reason='feature turned off')
    @pytest.mark.usefixtures('get_token')
    def test_token_exchange_subject_token_missing_exp_claim(self):
        # Given
        expected_status_code = 400
        expected_error = 'invalid_request'
        expected_error_description = "Missing exp claim in JWT"

        id_token_claims = {
            'at_hash': 'tf_-lqpq36lwO7WmSBIJ6Q',
            'sub': '787807429511',
            'auditTrackingId': '91f694e6-3749-42fd-90b0-c3134b0d98f6-1546391',
            'amr': ['N3_SMARTCARD'],
            'iss': 'https://am.nhsint.ptl.nhsd-esa.net:443/openam/oauth2/realms/root/realms/NHSIdentity/realms/Healthcare',
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

        client_assertion_claims = {
            "sub": self.oauth.client_id,
            "iss": self.oauth.client_id,
            "jti": str(uuid4()),
            "aud": f"{config.OAUTH_URL}/token",
            "exp": int(time()) + 5,
        }

        client_assertion_jwt = jwt.encode(client_assertion_claims, config.JWT_PRIVATE_KEY_ABSOLUTE_PATH, algorithm='RS512', headers={'kid': 'test-1'})
        id_token_jwt = jwt.encode(id_token_claims, config.ID_TOKEN_PRIVATE_KEY_ABSOLUTE_PATH, algorithm='RS256', headers={'kid': 'identity-service-tests-1'})

        # When
        response = requests.post(
            url= f"{config.OAUTH_URL}/token",
            data= {
                'grant_type': 'urn:ietf:params:oauth:grant-type:token-exchange',
                'subject_token_type': 'urn:ietf:params:oauth:token-type:id_token',
                'client_assertion_type': 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer',
                'subject_token': id_token_jwt,
                'client_assertion': client_assertion_jwt
            }
        )
        sleep(2)

        response_dict = json.loads(response.text)

        # Then
        assert expected_status_code == response.status_code
        assert expected_error == response_dict['error']
        assert expected_error_description == response_dict['error_description']
        assert 'message_id' in response_dict

