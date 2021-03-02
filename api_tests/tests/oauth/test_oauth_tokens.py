import pytest
from time import sleep
from api_tests.scripts.config import HELLO_WORLD_API_URL


@pytest.mark.asyncio
class TestOauthTokens:
    """ A test suite to confirm Oauth tokens error responses are as expected"""

    @pytest.mark.apm_801
    @pytest.mark.happy_path
    @pytest.mark.usefixtures('set_access_token')
    def test_access_token(self, helper):
        assert helper.check_endpoint(
            verb='GET',
            endpoint=HELLO_WORLD_API_URL,
            expected_status_code=200,
            expected_response={"message": "hello user!"},
            headers={
                'Authorization': f'Bearer {self.oauth.access_token}',
                'NHSD-Session-URID': 'ROLD-ID',
            }
        )

    @pytest.mark.apm_801
    @pytest.mark.happy_path
    @pytest.mark.usefixtures('set_refresh_token')
    async def test_refresh_token(self):
        resp = await self.oauth.get_token_response(grant_type="refresh_token", refresh_token=self.oauth.refresh_token)

        assert resp['status_code'] == 200
        assert sorted(list(resp['body'].keys())) == [
            'access_token',
            'expires_in',
            'refresh_count',
            'refresh_token',
            'refresh_token_expires_in',
            'token_type'
        ]

    @pytest.mark.apm_801
    @pytest.mark.errors
    @pytest.mark.parametrize('token', [
        # Condition 1: Using an invalid token
        "ThisTokenIsInvalid",

        # Condition 2: Using an expired token
        "QjMGgujVxVbCV98omVaOlY1zR8aB",

        # Condition 3: Empty token
        "",
    ])
    @pytest.mark.errors
    async def test_invalid_access_token(self, token: str, helper):
        assert helper.check_endpoint(
            verb='POST',
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
            headers={
                'Authorization': f'Bearer {token}',
                'NHSD-Session-URID': ''}
        )

    def test_missing_access_token(self, helper):
        assert helper.check_endpoint(
            verb='POST',
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
            headers={'NHSD-Session-URID': ''}
        )

    @pytest.mark.apm_801
    @pytest.mark.errors
    @pytest.mark.usefixtures('set_access_token')
    def test_access_token_does_expire(self, helper):
        # Set token fixture is executed
        # wait until token has expired
        sleep(5)

        # Check token still works after access token has expired
        assert helper.check_endpoint(
            verb='GET',
            endpoint=HELLO_WORLD_API_URL,
            expected_status_code=401,
            expected_response={
                'fault': {
                    'faultstring': 'Access Token expired', 'detail': {
                        'errorcode': 'keymanagement.service.access_token_expired'
                    }
                }
            },
            headers={
                'Authorization': f'Bearer {self.oauth.access_token}',
                'NHSD-Session-URID': '',
            }
        )

    @pytest.mark.apm_1618
    @pytest.mark.errors
    async def test_access_token_with_params(self):
        resp = await self.oauth.hit_oauth_endpoint(
            method="POST",
            endpoint="token",
            params={
                'client_id': self.oauth.client_id,
                'client_secret': self.oauth.client_secret,
                'grant_type': "authorization_code",
                'redirect_uri': self.oauth.redirect_uri,
                'code': await self.oauth.get_authenticated_with_simulated_auth(),
                '_access_token_expiry_ms': 5000
            }
        )

        assert resp['status_code'] == 400
        assert resp['body'] == {
            "error": "invalid_request",
            "error_description": "grant_type is missing"
        }

    @pytest.mark.apm_1010
    @pytest.mark.errors
    @pytest.mark.usefixtures('set_refresh_token')
    async def test_refresh_token_does_expire(self):
        sleep(5)
        resp = await self.oauth.get_token_response(
            grant_type="refresh_token",
            refresh_token=self.oauth.refresh_token
        )

        assert resp['status_code'] == 401
        assert resp['body'] == {
            "error": "invalid_grant",
            "error_description": "access token refresh period has expired",
        }

    @pytest.mark.apm_1010
    @pytest.mark.errors
    @pytest.mark.usefixtures('set_refresh_token')
    async def test_refresh_tokens_validity_expires(self):
        # Set refresh token validity to 0
        resp = await self.oauth.get_token_response(
            grant_type="refresh_token",
            refresh_token=self.oauth.refresh_token,
            data={
                'client_id': self.oauth.client_id,
                'client_secret': self.oauth.client_secret,
                'grant_type': 'refresh_token',
                'refresh_token': self.oauth.refresh_token,
                '_refresh_tokens_validity_ms': 0
            }
        )

        assert resp['status_code'] == 401
        assert resp['body'] == {
            "error": "invalid_grant",
            "error_description": "access token refresh period has expired"
        }

    @pytest.mark.apm_1475
    @pytest.mark.errors
    @pytest.mark.usefixtures('set_refresh_token')
    async def test_re_use_of_refresh_token(self):
        resp = await self.oauth.get_token_response(grant_type="refresh_token",
                                                   refresh_token=self.oauth.refresh_token)

        assert resp['status_code'] == 200
        assert sorted(list(resp['body'].keys())) == [
            'access_token',
            'expires_in',
            'refresh_count',
            'refresh_token',
            'refresh_token_expires_in',
            'token_type'
        ]

        # Sending another request with the same refresh token
        resp = await self.oauth.get_token_response(grant_type="refresh_token",
                                                   refresh_token=self.oauth.refresh_token)

        assert resp['status_code'] == 401
        assert resp['body'] == {
            "error": "invalid_grant",
            "error_description": "refresh_token is invalid"
        }
