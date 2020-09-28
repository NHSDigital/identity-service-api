from api_tests.config_files import config
from api_tests.scripts.response_bank import BANK
import pytest
import random


@pytest.mark.usefixtures("setup")
class TestOauthEndpointSuite:
    """ A test suit to verify all the happy path oauth endpoints """

    @pytest.mark.apm_801
    @pytest.mark.happy_path
    @pytest.mark.authorize_endpoint
    def test_authorize_endpoint(self):
        # Test authorize endpoint is redirected and returns a 200
        assert self.oauth.check_endpoint(
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
        assert self.oauth.check_response_history(
            verb='GET',
            endpoint='authorize',
            expected_redirects=BANK.get(self.name)['redirects'],
            params={
                'client_id': config.CLIENT_ID,
                'redirect_uri': f"{config.REDIRECT_URI}&prompt=login",
                'response_type': 'code',
            },
        )

    @pytest.mark.apm_801
    @pytest.mark.happy_path
    @pytest.mark.token_endpoint
    def test_token_endpoint(self):
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
            data={
                'client_id': config.CLIENT_ID,
                'client_secret': config.CLIENT_SECRET,
                'redirect_uri': config.REDIRECT_URI,
                'grant_type': 'authorization_code',
                'code': self.oauth.get_authenticated()
            },
        )

    @pytest.mark.apm_801
    @pytest.mark.apm_990
    @pytest.mark.errors
    @pytest.mark.authorize_endpoint
    @pytest.mark.parametrize('request_data', [
        # condition 1: invalid redirect uri
        {
            'expected_status_code': 400,
            'expected_response': {
                'error': 'invalid_request',
                'error_description': f'invalid redirection uri {config.REDIRECT_URI}/invalid'
            },
            'params': {
                'client_id': config.CLIENT_ID,
                'redirect_uri': f'{config.REDIRECT_URI}/invalid',  # invalid redirect uri
                'response_type': 'code',
                'state': random.getrandbits(32)
            },
        },

        # condition 2: missing redirect uri


        # condition 3: invalid client id


        # condition 4: missing client id


        # condition 5: invalid response type
        {
            'expected_status_code': 400,
            'expected_response': {
                'error': 'unsupported_response_type',
                'error_description': 'invalid response type: invalid'
            },
            'params': {
                'client_id': config.CLIENT_ID,
                'redirect_uri': config.REDIRECT_URI,
                'response_type': 'invalid',  # invalid response type
                'state': random.getrandbits(32)
            },
        },

        # condition 6: missing response type
    ])
    def test_authorization_error_conditions(self, request_data: dict):
        assert self.oauth.check_endpoint('GET', 'authorize', **request_data)

    @pytest.mark.apm_801
    @pytest.mark.errors
    @pytest.mark.token_endpoint
    @pytest.mark.parametrize('request_data', [
        # condition 1: invalid grant type
        {
            'expected_status_code': 400,
            'expected_response': {
                'error': 'invalid_request',
                'error_description': 'invalid grant_type'
            },
            'params': {
                'client_id': config.CLIENT_ID,
                'client_secret': config.CLIENT_SECRET,
                'redirect_uri': config.REDIRECT_URI,
                'grant_type': 'invalid',
            },
        },

        # condition 2: missing grant_type
        {
            'expected_status_code': 400,
            'expected_response': {
                'error': 'invalid_request',
                'error_description': 'The request is missing a required parameter : grant_type'
            },
            'params': {
                'client_id': config.CLIENT_ID,
                'client_secret': config.CLIENT_SECRET,
                'redirect_uri': config.REDIRECT_URI,
            },
        },

        # condition 3: invalid client id
        {
            'expected_status_code': 400,
            'expected_response': {
                'error': 'invalid_request',
                'error_description': 'invalid client_id'
            },
            'params': {
                'client_id': 'THISisANinvalidCLIENTid12345678',
                'client_secret': config.CLIENT_SECRET,
                'redirect_uri': config.REDIRECT_URI,
                'grant_type': 'authorization_code',
            },
        },

        # condition 4: missing client_id
        {
            'expected_status_code': 400,
            'expected_response': {
                'error': 'invalid_request',
                'error_description': 'The request is missing a required parameter : client_id'
            },
            'params': {
                'client_secret': config.CLIENT_SECRET,
                'redirect_uri': config.REDIRECT_URI,
                'grant_type': 'authorization_code',
            },
        },

        # condition 5: invalid redirect uri
        {
            'expected_status_code': 400,
            'expected_response': {
                'error': 'invalid_request',
                'error_description': 'invalid redirect_uri'
            },
            'params': {
                'client_id': config.CLIENT_ID,
                'client_secret': config.CLIENT_SECRET,
                'redirect_uri': f'{config.REDIRECT_URI}/invalid',
                'grant_type': 'authorization_code',
            },
        },

        # condition 6: missing redirect_uri
        {
            'expected_status_code': 400,
            'expected_response': {
                'error': 'invalid_request',
                'error_description': 'The request is missing a required parameter : redirect_uri'
            },
            'params': {
                'client_id': config.CLIENT_ID,
                'client_secret': config.CLIENT_SECRET,
                'grant_type': 'authorization_code',
            },
        },

        # condition 7: invalid client secret
        {
            'expected_status_code': 400,
            'expected_response': {
                'error': 'invalid_request',
                'error_description': 'invalid secret_id'
            },
            'params': {
                'client_id': config.CLIENT_ID,
                'client_secret': 'ThisSecretIsInvalid',
                'redirect_uri': config.REDIRECT_URI,
                'grant_type': 'authorization_code',
            },
        },

        # condition 8: missing client secret
        {
            'expected_status_code': 400,
            'expected_response': {
                'error': 'invalid_request',
                'error_description': 'The request is missing a required parameter : secret_id'
            },
            'params': {
                'client_id': config.CLIENT_ID,
                'redirect_uri': config.REDIRECT_URI,
                'grant_type': 'authorization_code',
            },
        },
    ])
    @pytest.mark.skip(reason="Not implemented")
    def test_token_error_conditions(self, request_data: dict):
        request_data['params']['code'] = self.oauth.get_authenticated()
        assert self.oauth.check_endpoint('POST', 'token', **request_data)

    @pytest.mark.errors
    @pytest.mark.parametrize('request_data', [
        # condition 1: invalid code
        {
            'expected_status_code': 400,
            'expected_response': {
                'error': 'invalid_request',
                'error_description': 'invalid code'
            },
            'params': {
                'client_id': config.CLIENT_ID,
                'client_secret': config.CLIENT_SECRET,
                'redirect_uri': config.REDIRECT_URI,
                'grant_type': 'authorization_code',
                'code': 'ThisIsAnInvalidCode'
            },
        },

        # condition 2: missing code
        {
            'expected_status_code': 400,
            'expected_response': {
                'error': 'invalid_request',
                'error_description': 'The request is missing a required parameter : code'
            },
            'params': {
                'client_id': config.CLIENT_ID,
                'client_secret': config.CLIENT_SECRET,
                'redirect_uri': config.REDIRECT_URI,
                'grant_type': 'authorization_code',
            },
        },
    ])
    @pytest.mark.skip(reason="Not implemented")
    def test_token_endpoint_with_invalid_authorization_code(self, request_data: dict):
        assert self.oauth.check_endpoint('POST', 'token', **request_data)
