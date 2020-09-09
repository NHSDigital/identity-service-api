import pytest
from api_tests.config_files import config


@pytest.mark.usefixtures("setup")
class TestOauthTokenSuite:
    """ A test suite to confirm Oauth tokens error responses are as expected"""

    @pytest.mark.apm_801
    @pytest.mark.happy_path
    @pytest.mark.usefixtures('get_token')
    def test_request_with_token(self):
        assert self.oauth.check_endpoint(
            verb='GET',
            endpoint='api',
            expected_status_code=200,
            expected_response={"message": "Hello User!"},
            headers={
                'Authorization': f'Bearer {self.token}',
                'NHSD-Session-URID': 'ROLD-ID',
            }
        )

    @pytest.mark.apm_801
    @pytest.mark.happy_path
    @pytest.mark.usefixtures('get_refresh_token')
    def test_refresh_token(self):
        assert self.oauth.check_endpoint(
            verb='POST',
            endpoint='token',
            expected_status_code=200,
            expected_response=[
                'access_token',
                'expires_in',
                'refresh_count',
                'refresh_token',
                'refresh_token_expires_in',
                'token_type'
            ],
            headers={
                'NHSD-Session-URID': '',
            },
            data={
                'client_id': config.CLIENT_ID,
                'client_secret': config.CLIENT_SECRET,
                'grant_type': 'refresh_token',
                'refresh_token': self.refresh_token,
            })
