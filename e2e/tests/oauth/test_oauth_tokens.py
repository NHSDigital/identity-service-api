from uuid import uuid4
import pytest
from time import sleep, time
from e2e.scripts.config import HELLO_WORLD_API_URL, ID_TOKEN_NHS_LOGIN_PRIVATE_KEY_ABSOLUTE_PATH
import sys
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
        Use to fetch and a new access token, refresh token pair.
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

        assert access_token
        assert refresh_token
        assert resp['body']['expires_in'] == '599'
        assert resp['body']['refresh_token_expires_in'] == '3599'

        # Get new access token using refresh token to ensure valid
        resp2 = await self.oauth.get_token_response(grant_type="refresh_token", refresh_token=refresh_token)
        access_token2 = resp2['body']['access_token']
        refresh_token2 = resp2['body']['refresh_token']

        assert access_token2
        assert refresh_token2

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

        assert access_token
        assert refresh_token
        assert resp['body']['expires_in'] == '599'
        assert resp['body']['refresh_token_expires_in'] == '43199'

        # Make request using access token to ensure valid
        req = requests.get(f"{HELLO_WORLD_API_URL}", headers={"Authorization": f"Bearer {access_token}"})
        assert req.status_code == 200

        # Get new access token using refresh token to ensure valid
        resp2 = await self.oauth.get_token_response(grant_type="refresh_token", refresh_token=refresh_token)
        access_token2 = resp2['body']['access_token']
        refresh_token2 = resp2['body']['refresh_token']
        assert access_token2
        assert refresh_token2

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

        assert access_token
        assert refresh_token

        # Get new access token using refresh token
        resp2 = await self.oauth.get_token_response(grant_type="refresh_token", refresh_token=refresh_token)
        access_token2 = resp2['body']['access_token']
        assert access_token2

        # try to use the original refresh token to get another access token
        resp3 = await self.oauth.get_token_response(grant_type="refresh_token", refresh_token=refresh_token)
        assert resp3['status_code'] == 401

    async def test_rejects_token_request_by_password(self):
        """
        Test that request for token using password grant type is rejected.
        """
        form_data = {
            "client_id": self.oauth.client_id,
            "client_secret": self.oauth.client_secret,
            "grant_type": "password",
            "username": "username",
            "password": "password"
        }
        resp = await self.oauth.get_token_response(grant_type='password', data=form_data)

        assert resp['status_code'] == 400

    @pytest.mark.parametrize("token_expiry_ms, expected_time", [(100000, 100), (500000, 500),(700000, 600), (1000000, 600)])
    async def test_access_token_override_with_client_credentials(self, token_expiry_ms, expected_time):
        """
        Test client credential flow access token can be overridden with a time less than 10 min(600000ms or 600s) 
        and NOT be overridden with a time greater than 10 min(600000ms or 600s)  
        """
        form_data = {
            "client_assertion_type": "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
            "client_assertion": self.oauth.create_jwt('test-1'),
            "grant_type": 'client_credentials',
            "_access_token_expiry_ms": token_expiry_ms
        }
        
        resp = await self.oauth.get_token_response(grant_type='client_credentials', data=form_data)

        assert resp['status_code'] == 200
        # To make sure resp['body']['expires_in'] returns same value as token_expiry_s
        #assert token_expiry_s - 5 < int(resp['body']['expires_in']) <= token_expiry_s
        assert int(resp['body']['expires_in']) <= expected_time
    
    @pytest.mark.parametrize("token_expiry_ms, expected_time", [(100000, 100), (500000, 500),(700000, 600), (1000000, 600)])
    async def test_access_token_override_with_token_exchange(self, token_expiry_ms, expected_time):
        """
        Test token exchange flow access token can be overridden with a time less than 10 min(600000ms or 600s)
        and NOT be overridden with a time greater than 10 min(600000ms or 600s)
        """
        id_token_jwt = self.oauth.create_id_token_jwt()
        client_assertion_jwt = self.oauth.create_jwt(kid='test-1')
        form_data = {
            "grant_type": "urn:ietf:params:oauth:grant-type:token-exchange",
            "subject_token_type": "urn:ietf:params:oauth:token-type:id_token",
            "client_assertion_type": "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
            "subject_token": id_token_jwt,
            "client_assertion": client_assertion_jwt,
            "_access_token_expiry_ms": token_expiry_ms
        }
        
        resp = await self.oauth.hit_oauth_endpoint("post", "token", data=form_data)

        assert resp['status_code'] == 200
        # To make sure resp['body']['expires_in'] returns same value as token_expiry_s
        #assert token_expiry_s - 5 < int(resp['body']['expires_in']) <= token_expiry_s
        assert int(resp['body']['expires_in']) <= expected_time
    
    @pytest.mark.parametrize("token_expiry_ms, expected_time", [(100000, 100), (500000, 500),(700000, 600), (1000000, 600)])
    async def test_access_token_override_with_authorization_code(self, token_expiry_ms, expected_time):
        """
        Test authorization code flow access token can be overridden with a time less than 10 min(600000ms or 600s)
        and NOT be overridden with a time greater than 10 min(600000ms or 600s)
        """
        
        resp = await self.oauth.get_token_response(grant_type='authorization_code', timeout=token_expiry_ms)

        assert resp['status_code'] == 200
        assert int(resp['body']['expires_in']) <= expected_time
    
    @pytest.mark.usefixtures("set_refresh_token")
    @pytest.mark.parametrize("token_expiry_ms, expected_time", [(100000, 100), (500000, 500),(700000, 600), (1000000, 600)])
    async def test_access_token_override_with_refresh_token(self, token_expiry_ms, expected_time):
        """
        Test refresh token flow access token can be overridden with a time less than 10 min(600000ms or 600s)
        and  NOT be overridden with a time greater than 10 min(600000ms or 600s)
        """
        form_data = {
            "client_id": self.oauth.client_id,
            "client_secret": self.oauth.client_secret,
            "grant_type": "refresh_token",
            "refresh_token": self.oauth.refresh_token,
            "_refresh_tokens_validity_ms": 599,
            "_access_token_expiry_ms": token_expiry_ms
        }
        
        resp = await self.oauth.get_token_response(grant_type='refresh_token', data=form_data)
        
        assert resp['status_code'] == 200
        assert int(resp['body']['expires_in']) <= expected_time
    
@pytest.mark.asyncio
class TestTokenRefreshExpiry:
    """Test class to confirm refresh tokens expire after the expected amount of time
    for both separated and combined auth"""

    @pytest.mark.parametrize('scope', ['P9', 'P5', 'P0'])
    async def test_nhs_login_refresh_tokens_generated_with_expected_expiry_combined_auth(self, scope):
        """
        Test that refresh tokens generated via NHS Login have an expiry time of 1 hour for combined authentication.
        """

        form_data = {
            "client_id": self.oauth.client_id,
            "client_secret": self.oauth.client_secret,
            "grant_type": "authorization_code",
            "redirect_uri": self.oauth.redirect_uri,
            "_access_token_expiry_ms": 600000,
            "code": await self.oauth.get_authenticated_with_simulated_auth(auth_scope="nhs-login"),
        }
        params = {"scope": "nhs-login"}
        resp = await self.oauth.hit_oauth_endpoint("post", "token", data=form_data, params=params)

        access_token = resp['body']['access_token']
        refresh_token = resp['body']['refresh_token']

        assert access_token
        assert refresh_token
        assert resp['body']['expires_in'] == '599'
        assert resp['body']['refresh_token_expires_in'] == '3599'

    async def test_cis2_refresh_tokens_generated_with_expected_expiry_combined_auth(self):
        """
        Test that refresh tokens generated via CIS2 have an expiry time of 12 hours for combined authentication.
        """
        resp = await self.oauth.get_token_response(
            grant_type="authorization_code",
            timeout=600000,
        )

        access_token = resp['body']['access_token']
        refresh_token = resp['body']['refresh_token']

        assert access_token
        assert refresh_token
        assert resp['body']['expires_in'] == '599'
        assert resp['body']['refresh_token_expires_in'] == '43199'

    @pytest.mark.parametrize('scope', ['P9', 'P5', 'P0'])
    async def test_nhs_login_refresh_tokens_generated_with_expected_expiry_separated_auth(self, scope):
        """
        Test that refresh tokens generated via NHS Login have an expiry time of 1 hour for separated authentication.
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

        assert access_token
        assert refresh_token
        assert resp['body']['expires_in'] == '599'
        assert resp['body']['refresh_token_expires_in'] == '3599'

    async def test_cis2_refresh_tokens_generated_with_expected_expiry_separated_auth(self):
        """
        Test that refresh tokens generated via CIS2 have an expiry time of 12 hours for separated authentication.
        """
        # Generate access token using token-exchange
        id_token_jwt = self.oauth.create_id_token_jwt()
        client_assertion_jwt = self.oauth.create_jwt(kid='test-1')
        resp = await self.oauth.get_token_response(
            grant_type="token_exchange",
            _jwt=client_assertion_jwt,
            id_token_jwt=id_token_jwt
        )

        access_token = resp['body']['access_token']
        refresh_token = resp['body']['refresh_token']

        assert access_token
        assert refresh_token
        assert resp['body']['expires_in'] == '599'
        assert resp['body']['refresh_token_expires_in'] == '43199'

    @pytest.mark.skip(
        reason="It is not feasible to run this test each build due to the timeframe required, run manually if needed."
    )
    @pytest.mark.parametrize('scope', ['P9', 'P5', 'P0'])
    async def test_nhs_login_refresh_token_invalid_after_1_hour(self, scope):
        """
        Test that a refresh token received via a NHS Login is invalid after 1 hour (existing behaviour).
        Run pytest with the -s arg to display the stdout and show the wait time countdown.
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
        refresh_token = resp['body']['refresh_token']

        assert refresh_token
        assert resp['body']['expires_in'] == '599'
        assert resp['body']['refresh_token_expires_in'] == '3599'

        # Wait 1 hour (the previous refresh token expiry time) and check that the token is still valid
        for remaining in range(3600, 0, -1):
            mins, sec = divmod(remaining, 60)
            sys.stdout.write("\r")
            sys.stdout.write("{:2d} minutes {:2d} seconds remaining.".format(mins, sec))
            sleep(1)

        # Get new access token using refresh token
        resp2 = await self.oauth.get_token_response(grant_type="refresh_token", refresh_token=refresh_token)
        assert resp2['status_code'] == 401

    @pytest.mark.skip(
        reason="It is not feasible to run this test each build due to the timeframe required, run manually if needed."
    )
    async def test_cis2_refresh_token_valid_after_1_hour(self):
        """
        Test that a refresh token received via a CIS2 login is valid after 1 hour (the previous expiry time).
        Run pytest with the -s arg to display the stdout and show the wait time countdown.
        """
        # Generate access token using token-exchange
        id_token_jwt = self.oauth.create_id_token_jwt()
        client_assertion_jwt = self.oauth.create_jwt(kid='test-1')
        resp = await self.oauth.get_token_response(
            grant_type="token_exchange",
            _jwt=client_assertion_jwt,
            id_token_jwt=id_token_jwt
        )

        refresh_token = resp['body']['refresh_token']

        assert refresh_token
        assert resp['body']['expires_in'] == '599'
        assert resp['body']['refresh_token_expires_in'] == '43199'

        # Wait 1 hour (the previous refresh token expiry time) and check that the token is still valid
        for remaining in range(3600, 0, -1):
            mins, sec = divmod(remaining, 60)
            sys.stdout.write("\r")
            sys.stdout.write("{:2d} minutes {:2d} seconds remaining.".format(mins, sec))
            sleep(1)

        # Get new access token using refresh token
        resp2 = await self.oauth.get_token_response(grant_type="refresh_token", refresh_token=refresh_token)
        access_token2 = resp2['body']['access_token']
        assert access_token2

    @pytest.mark.skip(
        reason="It is not feasible to run this test each build due to the timeframe required, run manually if needed."
    )
    async def test_cis2_refresh_token_expires_after_12_hours(self):
        """
        Test that a refresh token received via a CIS2 login is valid for up to 12 hours.
        Run pytest with the -s arg to display the stdout and show the wait time countdown.
        """
        # Generate access token using token-exchange
        id_token_jwt = self.oauth.create_id_token_jwt()
        client_assertion_jwt = self.oauth.create_jwt(kid='test-1')
        resp = await self.oauth.get_token_response(
            grant_type="token_exchange",
            _jwt=client_assertion_jwt,
            id_token_jwt=id_token_jwt
        )

        refresh_token = resp['body']['refresh_token']

        assert refresh_token
        assert resp['body']['expires_in'] == '599'
        assert resp['body']['refresh_token_expires_in'] == '43199'

        # Wait 12 hours and check that the token has expired
        for remaining in range(43200, 0, -1):
            mins, sec = divmod(remaining, 60)
            hours, mins = divmod(mins, 60)
            sys.stdout.write("\r")
            sys.stdout.write("{:2d} hours {:2d} minutes {:2d} seconds remaining.".format(hours, mins, sec))
            sys.stdout.flush()
            sleep(1)

        # Try to use the now expired refresh token to get another access token
        resp2 = await self.oauth.get_token_response(grant_type="refresh_token", refresh_token=refresh_token)
        print(resp2)
        assert resp2['status_code'] == 401
