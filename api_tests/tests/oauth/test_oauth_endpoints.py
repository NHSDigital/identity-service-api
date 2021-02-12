from api_tests.config_files import config
from api_tests.scripts.response_bank import BANK
from api_tests.scripts.generic_request import GenericRequest
import pytest
import random


@pytest.mark.asyncio
class TestOauthEndpoints:
    """ A test suit to verify all the happy path oauth endpoints """

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
    @pytest.mark.asyncio
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
    @pytest.mark.asyncio
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
    def test_cache_invalidation(self, helper):
        """
        Test identity cache invalidation after use:
            * Given i am authorizing
            * When the first request has succeeded
            * When using the same state as the first request
            * Then it should return xxx
        """

        # Make authorize request to retrieve state2
        response = helper.check_and_return_endpoint(
            verb="GET",
            endpoint="authorize",
            expected_status_code=302,
            expected_response="",
            params={
                "client_id": config.CLIENT_ID,
                "redirect_uri": config.REDIRECT_URI,
                "response_type": "code",
                "state": "1234567890",
            },
            allow_redirects=False,
        )
        state2 = helper.get_param_from_url(
            url=response.headers["Location"], param="state"
        )

        # Make simulated auth request to authenticate
        response = helper.check_and_return_endpoint(
            verb="POST",
            endpoint="sim_auth",
            expected_status_code=302,
            expected_response="",
            params={
                "response_type": "code",
                "client_id": config.CLIENT_ID,
                "redirect_uri": config.REDIRECT_URI,
                "scope": "openid",
                "state": state2,
            },
            headers={"Content-Type": "application/x-www-form-urlencoded"},
            data={"state": state2},
            allow_redirects=False,
        )

        # Make initial callback request
        auth_code = helper.get_param_from_url(
            url=response.headers["Location"], param="code"
        )
        response = helper.check_and_return_endpoint(
            verb="GET",
            endpoint="callback",
            expected_status_code=302,
            expected_response="",
            params={"code": auth_code, "client_id": "some-client-id", "state": state2},
            allow_redirects=False,
        )

        # Verify auth code and state are returned
        response_params = helper.get_params_from_url(response.headers["Location"])
        assert response_params["code"]
        assert response_params["state"]

        # Make second callback request with same state value
        assert helper.check_endpoint(
            verb="GET",
            endpoint="callback",
            expected_status_code=400,
            expected_response={
                "error": "invalid_request",
                "error_description": "invalid state parameter.",
            },
            params={"code": auth_code, "client_id": "some-client-id", "state": state2},
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
                    "client_id": config.CLIENT_ID,
                    "redirect_uri": f"{config.REDIRECT_URI}/invalid",  # invalid redirect uri
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
                "params": {  # not providing redirect uri
                    "client_id": config.CLIENT_ID,
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
                    "redirect_uri": f"{config.REDIRECT_URI}/invalid",
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
                    "redirect_uri": config.REDIRECT_URI,
                    "response_type": "code",
                    "state": random.getrandbits(32),
                },
            },
            # condition 5: app not subscribed
            {
                "expected_status_code": 401,
                "expected_response": {
                    'error': 'access_denied',
                    'error_description': 'API Key supplied does not have access to this resource. '
                                         'Please check the API Key you are using belongs to an app '
                                         'which has sufficient access to access this resource.'
                },
                "params": {
                    "client_id": config.VALID_UNSUBSCRIBED_CLIENT_ID,
                    "redirect_uri": config.VALID_UNSUBSCRIBED_REDIRECT_URI,
                    "response_type": "code",
                    "state": random.getrandbits(32),
                },
            },
            # condition 6: app revoked
            {
                "expected_status_code": 401,
                "expected_response": {
                    "error": "access_denied",
                    "error_description": "The developer app associated with the API key is not approved or revoked",
                },
                "params": {
                    "client_id": config.VALID_UNAPPROVED_CLIENT_ID,
                    "redirect_uri": config.VALID_UNAPPROVED_CLIENT_REDIRECT_URI,
                    "response_type": "code",
                    "state": random.getrandbits(32),
                },
            },
        ],
    )
    @pytest.mark.asyncio
    async def test_authorization_error_conditions(self, request_data: dict):
        resp = await self.oauth.hit_oauth_endpoint(
            method="GET",
            endpoint="authorize",
            params=request_data["params"]
        )

        assert resp['status_code'] == request_data['expected_status_code']
        assert resp['body'] == request_data['expected_response']

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
                    "client_id": config.CLIENT_ID,
                    "redirect_uri": config.REDIRECT_URI,
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
                    "client_id": config.CLIENT_ID,
                    "redirect_uri": config.REDIRECT_URI,
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
                    "client_id": config.CLIENT_ID,
                    "redirect_uri": config.REDIRECT_URI,
                    "response_type": "invalid",  # invalid response type
                    "state": random.getrandbits(32),
                },
            },
        ],
    )
    async def test_authorization_error_redirects(self, test_case: dict, helper):
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
            client_redirect=config.REDIRECT_URI,
            state=test_case["params"].get("state")
        )

    @pytest.mark.apm_1631
    @pytest.mark.errors
    @pytest.mark.token_endpoint
    async def test_token_unsubscribed_error_conditions(self):
        resp = await self.oauth.get_token_response(
            grant_type="authorization_code",
            data={
                "client_id": config.VALID_UNSUBSCRIBED_CLIENT_ID,
                "client_secret": config.VALID_UNSUBSCRIBED_CLIENT_SECRET,
                "redirect_uri": config.VALID_UNSUBSCRIBED_REDIRECT_URI,
                "grant_type": "authorization_code",
                "code": await self.oauth.get_authenticated_with_simulated_auth()
            }
        )

        assert resp['status_code'] == 401
        assert resp['body'] == {
            "error": "access_denied",
            "error_description": "API Key supplied does not have access to this resource."
                                 " Please check the API Key you are using belongs to an app"
                                 " which has sufficient access to access this resource.",
        }

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
                        "client_id": config.CLIENT_ID,
                        "client_secret": config.CLIENT_SECRET,
                        "redirect_uri": config.REDIRECT_URI,
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
                        "client_id": config.CLIENT_ID,
                        "client_secret": config.CLIENT_SECRET,
                        "redirect_uri": config.REDIRECT_URI,
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
                        "client_secret": config.CLIENT_SECRET,
                        "redirect_uri": config.REDIRECT_URI,
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
                        "client_secret": config.CLIENT_SECRET,
                        "redirect_uri": config.REDIRECT_URI,
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
                        "client_id": config.CLIENT_ID,
                        "client_secret": "ThisSecretIsInvalid",
                        "redirect_uri": config.REDIRECT_URI,
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
                        "client_id": config.CLIENT_ID,
                        "redirect_uri": config.REDIRECT_URI,
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
                        "client_id": config.CLIENT_ID,
                        "client_secret": config.CLIENT_SECRET,
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
                        "client_id": config.CLIENT_ID,
                        "client_secret": config.CLIENT_SECRET,
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
                        "client_id": config.CLIENT_ID,
                        "client_secret": config.CLIENT_SECRET,
                        "redirect_uri": config.REDIRECT_URI,
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
                        "client_id": config.CLIENT_ID,
                        "client_secret": config.CLIENT_SECRET,
                        "redirect_uri": config.REDIRECT_URI,
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
    @pytest.mark.asyncio
    async def test_token_error_conditions(self, request_data: dict, expected_response: dict):
        resp = await self.oauth.get_token_response(grant_type="authorization_code", **request_data)

        assert resp["status_code"] == expected_response["status_code"]
        assert resp['body'] == expected_response["body"]

    @pytest.mark.apm_1064
    @pytest.mark.errors
    @pytest.mark.callback_endpoint
    async def test_callback_error_conditions(self):
        resp = await self.oauth.hit_oauth_endpoint(
            method="GET",
            endpoint="callback",
            params={
                "code": "some-code",
                "client_id": "invalid-client-id",
                "state": random.getrandbits(32),
            }
        )

        assert resp['status_code'] == 401
        assert resp['body'] == ""

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
                    'client_secret': config.CLIENT_SECRET,
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
                    'client_secret': config.CLIENT_SECRET,
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
                    "client_id": config.CLIENT_ID,
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
                    "client_id": config.CLIENT_ID,
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
                    "client_id": config.CLIENT_ID,
                    'client_secret': config.CLIENT_SECRET,
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
                    "client_id": config.CLIENT_ID,
                    'client_secret': config.CLIENT_SECRET,
                    'grant_type': 'refresh_token',
                    'refresh_token': 'invalid'
                },
            },
        ],
    )
    async def test_refresh_token_error_conditions(self, test_case: dict):
        resp = await self.oauth.get_token_response(grant_type="refresh_token", data=test_case['data'])

        assert resp['status_code'] == test_case['expected_status_code']
        assert resp['body'] == test_case['expected_response']

    async def test_ping(self):
        resp = await self.oauth.hit_oauth_endpoint(method='GET', endpoint='_ping')

        assert resp['status_code'] == 200
        assert list(resp['body'].keys()) == ["version", "revision", "releaseId", "commitId"]

    @pytest.mark.aea_756
    @pytest.mark.happy_path
    @pytest.mark.usefixtures("set_access_token")
    async def test_userinfo(self):
        resp = await self.oauth.hit_oauth_endpoint(
            method="GET",
            endpoint="userinfo",
            headers={'Authorization': f'Bearer {self.oauth.access_token}'}
        )
        assert resp['status_code'] == 200
        assert resp['body'] == BANK.get(self.name)["response"]
