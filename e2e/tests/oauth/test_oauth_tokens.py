from uuid import uuid4
import pytest
from time import sleep, time
from e2e.scripts.config import HELLO_WORLD_API_URL, ID_TOKEN_NHS_LOGIN_PRIVATE_KEY_ABSOLUTE_PATH, MOCK_IDP_BASE_URL
import requests

@pytest.mark.asyncio
class TestOauthTokens:
    """ A test suite to confirm Oauth tokens error responses are as expected"""

    @pytest.mark.apm_801
    @pytest.mark.happy_path
    @pytest.mark.usefixtures("set_access_token")
    def test_access_token(self, helper):
        assert helper.check_endpoint(
            verb="GET",
            endpoint=HELLO_WORLD_API_URL,
            expected_status_code=200,
            expected_response={"message": "hello user!"},
            headers={
                "Authorization": f"Bearer {self.oauth.access_token}",
                "NHSD-Session-URID": "ROLD-ID",
            },
        )

    @pytest.mark.apm_801
    @pytest.mark.happy_path
    @pytest.mark.usefixtures("set_refresh_token")
    async def test_refresh_token(self):
        resp = await self.oauth.get_token_response(
            grant_type="refresh_token", refresh_token=self.oauth.refresh_token
        )

        assert resp["status_code"] == 200
        assert sorted(list(resp["body"].keys())) == [
            "access_token",
            "expires_in",
            "refresh_count",
            "refresh_token",
            "refresh_token_expires_in",
            "token_type",
        ]

    @pytest.mark.apm_801
    @pytest.mark.errors
    @pytest.mark.parametrize(
        "token",
        [
            # Condition 1: Using an invalid token
            "ThisTokenIsInvalid",
            # Condition 2: Using an expired token
            "QjMGgujVxVbCV98omVaOlY1zR8aB",
            # Condition 3: Empty token
            "",
        ],
    )
    @pytest.mark.errors
    async def test_invalid_access_token(self, token: str, helper):
        assert helper.check_endpoint(
            verb="POST",
            endpoint=HELLO_WORLD_API_URL,
            expected_status_code=404,
            expected_response="""
            <!DOCTYPE html>
            <html lang="en">
            <head>
            <meta charset="utf-8">
            <title>Error</title>
            </head>
            <body>
            <pre>Cannot POST /hello/user</pre>
            </body>
            </html>
            """,
            headers={"Authorization": f"Bearer {token}", "NHSD-Session-URID": ""},
        )

    def test_missing_access_token(self, helper):
        assert helper.check_endpoint(
            verb="POST",
            endpoint=HELLO_WORLD_API_URL,
            expected_status_code=404,
            expected_response="""
            <!DOCTYPE html>
            <html lang="en">
            <head>
            <meta charset="utf-8">
            <title>Error</title>
            </head>
            <body>
            <pre>Cannot POST /hello/user</pre>
            </body>
            </html>
            """,
            headers={"NHSD-Session-URID": ""},
        )

    @pytest.mark.apm_801
    @pytest.mark.errors
    @pytest.mark.usefixtures("set_access_token")
    def test_access_token_does_expire(self, helper):
        # Set token fixture is executed
        # wait until token has expired
        sleep(5)

        # Check token still works after access token has expired
        assert helper.check_endpoint(
            verb="GET",
            endpoint=HELLO_WORLD_API_URL,
            expected_status_code=401,
            expected_response={
                "fault": {
                    "faultstring": "Access Token expired",
                    "detail": {
                        "errorcode": "keymanagement.service.access_token_expired"
                    },
                }
            },
            headers={
                "Authorization": f"Bearer {self.oauth.access_token}",
                "NHSD-Session-URID": "",
            },
        )

    @pytest.mark.apm_1618
    @pytest.mark.errors
    async def test_access_token_with_params(self):
        resp = await self.oauth.hit_oauth_endpoint(
            method="POST",
            endpoint="token",
            params={
                "client_id": self.oauth.client_id,
                "client_secret": self.oauth.client_secret,
                "grant_type": "authorization_code",
                "redirect_uri": self.oauth.redirect_uri,
                "code": await self.oauth.get_authenticated_with_simulated_auth(),
                "_access_token_expiry_ms": 5000,
            },
        )

        assert resp["status_code"] == 415
        assert resp["body"] == {
            "error": "invalid_request",
            "error_description": "Content-Type header must be application/x-www-urlencoded",
        }

    @pytest.mark.apm_1010
    @pytest.mark.errors
    @pytest.mark.usefixtures("set_refresh_token")
    async def test_refresh_token_does_expire(self):
        sleep(5)
        resp = await self.oauth.get_token_response(
            grant_type="refresh_token", refresh_token=self.oauth.refresh_token
        )

        assert resp["status_code"] == 401
        assert resp["body"] == {
            "error": "invalid_grant",
            "error_description": "refresh token refresh period has expired",
        }

    @pytest.mark.apm_1010
    @pytest.mark.errors
    @pytest.mark.usefixtures("set_refresh_token")
    async def test_refresh_tokens_validity_expires(self):
        # Set refresh token validity to 0
        resp = await self.oauth.get_token_response(
            grant_type="refresh_token",
            refresh_token=self.oauth.refresh_token,
            data={
                "client_id": self.oauth.client_id,
                "client_secret": self.oauth.client_secret,
                "grant_type": "refresh_token",
                "refresh_token": self.oauth.refresh_token,
                "_refresh_tokens_validity_ms": 0,
            },
        )

        assert resp["status_code"] == 401
        assert resp["body"] == {
            "error": "invalid_grant",
            "error_description": "refresh token refresh period has expired",
        }

    @pytest.mark.apm_1475
    @pytest.mark.errors
    @pytest.mark.usefixtures("set_refresh_token")
    async def test_re_use_of_refresh_token(self):
        resp = await self.oauth.get_token_response(
            grant_type="refresh_token", refresh_token=self.oauth.refresh_token
        )

        assert resp["status_code"] == 200
        assert sorted(list(resp["body"].keys())) == [
            "access_token",
            "expires_in",
            "refresh_count",
            "refresh_token",
            "refresh_token_expires_in",
            "token_type",
        ]

        # Sending another request with the same refresh token
        resp = await self.oauth.get_token_response(
            grant_type="refresh_token", refresh_token=self.oauth.refresh_token
        )

        assert resp["status_code"] == 401
        assert resp["body"] == {
            "error": "invalid_grant",
            "error_description": "refresh_token is invalid",
        }

    @pytest.mark.parametrize("auth_method", [("P0"), ("P5"), ("P9")])
    @pytest.mark.authorize_endpoint
    async def test_nhs_login_auth_code_flow_happy_path(
        self, helper, auth_code_nhs_login
    ):

        response = await auth_code_nhs_login.get_token(self.oauth)

        access_token = response["access_token"]

        assert helper.check_endpoint(
            verb="GET",
            endpoint=HELLO_WORLD_API_URL,
            expected_status_code=200,
            expected_response={"message": "hello user!"},
            headers={
                "Authorization": f"Bearer {access_token}",
                "NHSD-Session-URID": "ROLD-ID",
            },
        )


@pytest.mark.asyncio
class TestTokenExchangeTokens:
    """Test class to confirm token exchange logic is as expected """
    @pytest.mark.parametrize('scope', ['P9', 'P5', 'P0'])
    async def test_nhs_login_token_exchange_access_and_refresh_tokens_generated(self, scope):
        """
        Ensure access token and refresh token generated by nhs login token exchange
        """
        id_token_claims = {
            "aud": "tf_-APIM-1",
            "id_status": "verified",
            "token_use": "id",
            "auth_time": 1616600683,
            "iss": "https://internal-dev.api.service.nhs.uk",
            "vot": "P9.Cp.Cd",
            "exp": int(time()) + 600,
            "iat": int(time()) - 10,
            "vtm": "https://auth.sandpit.signin.nhs.uk/trustmark/auth.sandpit.signin.nhs.uk",
            "jti": str(uuid4()),
            "identity_proofing_level": scope,
            "nhs_number": "900000000001"
        }
        id_token_headers = {
            "sub": "49f470a1-cc52-49b7-beba-0f9cec937c46",
            "aud": "APIM-1",
            "kid": "nhs-login",
            "iss": "https://internal-dev.api.service.nhs.uk",
            "typ": "JWT",
            "exp": 1616604574,
            "iat": 1616600974,
            "alg": "RS512",
            "jti": str(uuid4()),
        }

        with open(ID_TOKEN_NHS_LOGIN_PRIVATE_KEY_ABSOLUTE_PATH, "r") as f:
            contents = f.read()

        client_assertion_jwt = self.oauth.create_jwt(kid="test-1")
        id_token_jwt = self.oauth.create_id_token_jwt(
            algorithm="RS512",
            claims=id_token_claims,
            headers=id_token_headers,
            signing_key=contents,
        )
        resp = await self.oauth.get_token_response(
            grant_type="token_exchange",
            _jwt=client_assertion_jwt,
            id_token_jwt=id_token_jwt,
        )
        access_token = resp['body']['access_token']
        refresh_token = resp['body']['refresh_token']

        assert bool(access_token) is True
        assert bool(refresh_token) is True
        assert resp['body']['expires_in'] == '599'
        assert resp['body']['refresh_token_expires_in'] == '3599'


    async def test_cis2_token_exchange_access_tokens_valid(self):
        """
        Using a refresh token that was generated via token exchange, fetch and use
        a new access token, refresh token pair.
        """
        # Generate access token using token-exchange
        id_token_jwt = self.oauth.create_id_token_jwt()
        client_assertion_jwt = self.oauth.create_jwt(kid='test-1')
        resp = await self.oauth.get_token_response(grant_type='token_exchange', _jwt=client_assertion_jwt,
                                                   id_token_jwt=id_token_jwt)

        access_token = resp['body']['access_token']
        refresh_token = resp['body']['refresh_token']

        assert bool(access_token) is True
        assert bool(refresh_token) is True
        assert resp['body']['expires_in'] == '599'
        assert resp['body']['refresh_token_expires_in'] == '3599'

        # Make request using access token to ensure valid
        req = requests.get(f"{HELLO_WORLD_API_URL}", headers={"Authorization": f"Bearer {access_token}"})
        assert req.status_code == 200

        # Get new access token using refresh token to ensure valid
        resp2 = await self.oauth.get_token_response(grant_type="refresh_token", refresh_token=refresh_token)
        access_token2 = resp2['body']['access_token']
        assert bool(access_token2) is True

        # Make request using new access token to ensure valid
        req2 = requests.get(f"{HELLO_WORLD_API_URL}", headers={"Authorization": f"Bearer {access_token2}"})
        assert req2.status_code == 200


    async def test_cis2_token_exchange_refresh_token_become_invalid(self):
        """
        Fetch a new access token, refresh token pair.
        Ensure the original refresh token becomes invalid
        """
        # Generate access token using token-exchange
        id_token_jwt = self.oauth.create_id_token_jwt()
        client_assertion_jwt = self.oauth.create_jwt(kid='test-1')
        resp = await self.oauth.get_token_response(grant_type='token_exchange', _jwt=client_assertion_jwt,
                                                   id_token_jwt=id_token_jwt)

        access_token = resp['body']['access_token']
        refresh_token = resp['body']['refresh_token']

        assert bool(access_token) is True
        assert bool(refresh_token) is True

        # Get new access token using refresh token
        resp2 = await self.oauth.get_token_response(grant_type="refresh_token", refresh_token=refresh_token)
        access_token2 = resp2['body']['access_token']
        assert bool(access_token2) is True

        # try to use the original refresh token to get another access token
        resp3 = await self.oauth.get_token_response(grant_type="refresh_token", refresh_token=refresh_token)
        assert resp3['status_code'] == 401


    async def test_token_by_password(self):
        """
        Test that request for token using password grant type is rejected.
        """
        form_data = {
            "client_id": self.oauth.client_id,
            "client_secret": self.oauth.client_secret,
            "grant_type": 'password',
            "username":'username',
            "password": "password"
        }
        resp = await self.oauth.get_token_response(grant_type='password', data=form_data)

        assert resp['status_code'] == 400