import pytest
from time import sleep


@pytest.mark.usefixtures("setup")
class TestOauthTokenErrorConditionSuite:
    """ A test suite to confirm Oauth tokens error responses are as expected"""

    @pytest.mark.apm_801
    @pytest.mark.happy_path
    @pytest.mark.usefixtures('get_token')
    def test_request_with_token(self):
        assert self.test.check_endpoint(
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
    @pytest.mark.usefixtures('get_token')
    def test_refresh_token(self):
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
            expected_status_code=200,
            expected_response={"message": "Hello User!"},
            headers={
                'Authorization': f'Bearer {self.refresh_token}',
                'NHSD-Session-URID': '',
            }
        )
