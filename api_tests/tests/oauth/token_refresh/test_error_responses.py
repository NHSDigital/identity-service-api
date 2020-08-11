import pytest
from time import sleep

from api_tests.config_files import config


@pytest.mark.usefixtures("setup")
class TestOauthTokensSuite:
    """ A test suite to confirm Oauth tokens are behaving as expected"""

    @pytest.mark.apm_801
    @pytest.mark.errors
    @pytest.mark.usefixtures("update_token_in_parametrized_headers")
    @pytest.mark.parametrize('headers', [
        # Condition 1: Using an invalid token
        {
            'Authorization': 'Bearer ThisTokenIsInvalid',
            'NHSD-Session-URID': '',
        },

        # Condition 2: Using an Expired Token
        {
            'Authorization': 'Bearer QjMGgujVxVbCV98omVaOlY1zR8aB',  # This token has expired
            'NHSD-Session-URID': '',
        },

        # Condition 3: Missing token from header
        {
            'NHSD-Session-URID': '',
        },

        # Condition 4: Missing Role-ID
        {
            'Authorization': 'valid_token',  # This placeholder this will automatically  be replaced with a valid token
        },
    ])
    def test_invalid_token(self, headers: dict):
        assert self.test.check_endpoint(
            verb='POST',
            endpoint='api',
            expected_status_code=400,
            expected_response={},
            headers=headers
        )

    @pytest.mark.apm_801
    @pytest.mark.errors
    @pytest.mark.usefixtures('get_token')
    def test_token_does_expire(self):
        # Get token with a timeout set to 5 second &
        # wait until token has expired
        assert self.test.check_endpoint(
            verb='GET',
            endpoint='api',
            expected_status_code=200,
            expected_response={"message": "Hello User!"},
            headers={
                'Authorization': f'Bearer {self.token}',
                'NHSD-Session-URID': '',
            }
        )

        # Wait for token to expire
        sleep(5)

        # Check refresh token still works after access token has expired
        assert self.test.check_endpoint(
            verb='GET',
            endpoint='api',
            expected_status_code=401,
            expected_response={
                'fault': {
                    'faultstring': 'Access Token expired', 'detail': {
                        'errorcode': 'keymanagement.service.access_token_expired'
                    }
                }
            },
            headers={
                'Authorization': f'Bearer {self.token}',
                'NHSD-Session-URID': '',
            }
        )

    @pytest.mark.apm_1010
    @pytest.mark.errors
    @pytest.mark.usefixtures('get_refresh_token')
    def test_refresh_token_does_expire(self):
        sleep(5)
        assert self.test.check_endpoint(
            verb='POST',
            endpoint='token',
            expected_status_code=401,
            expected_response={
                "error": "invalid_request",
                "error_description": "Refresh Token expired"
            },
            headers={
                'NHSD-Session-URID': '',
            },
            data={
                'client_id': config.CLIENT_ID,
                'client_secret': config.CLIENT_SECRET,
                'grant_type': 'refresh_token',
                'refresh_token': self.refresh_token
            })
