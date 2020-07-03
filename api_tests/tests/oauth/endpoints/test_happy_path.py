from api_tests.config_files import config
from api_tests.scripts.response_bank import BANK
import pytest


@pytest.mark.usefixtures("setup")
class TestOauthEndpointSuite:
    """ A test suit to verify all the happy path oauth endpoints """

    @pytest.mark.apm_801
    @pytest.mark.happy_path
    @pytest.mark.authorize_endpoint
    def test_authorize_endpoint(self):
        # Test authorize endpoint is redirected and returns a 200
        assert self.test.check_endpoint(
            verb='GET',
            endpoint='authorize',
            expected_status_code=200,
            expected_response=BANK.get(self.name)['response'],
            params={
                'client_id': config.CLIENT_ID,
                'redirect_uri': config.REDIRECT_URI,
                'response_type': 'code',
            },
        )

        # Test the redirects are working as expected
        assert self.test.check_response_history(
            verb='GET',
            endpoint='authorize',
            expected_status_code=200,
            expected_redirects=BANK.get(self.name)['redirects'],
            params={
                'client_id': config.CLIENT_ID,
                'redirect_uri': config.REDIRECT_URI,
                'response_type': 'code',
            },
        )

    @pytest.mark.apm_801
    @pytest.mark.happy_path
    @pytest.mark.token_endpoint
    def test_token_endpoint(self):
        assert self.test.check_endpoint(
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
            data={
                'client_id': config.CLIENT_ID,
                'client_secret': config.CLIENT_SECRET,
                'redirect_uri': config.REDIRECT_URI,
                'grant_type': 'authorization_code',
                'code': self.test.get_authenticated(config.AUTHENTICATION_PROVIDER)
            },
        )
