from api_tests.config_files import config
from api_tests.scripts.response_bank import BANK
from api_tests.config_files.environments import ENV
import pytest
import random
import uuid


@pytest.mark.usefixtures("setup")
class TestOauthEndpointSuite:
    """ A test suit to verify all the happy path oauth endpoints """

    @staticmethod
    def switch_to_valid_asid_application():
        config.CLIENT_ID = ENV['oauth']['valid_asic_client_id']
        config.CLIENT_SECRET = ENV['oauth']['valid_asid_client_secret']
        config.REDIRECT_URI = "https://example.com/callback"

    @staticmethod
    def switch_to_application():
        config.CLIENT_ID = ENV['oauth']['client_id']
        config.CLIENT_SECRET = ENV['oauth']['client_secret']
        config.REDIRECT_URI = ENV['oauth']['redirect_uri']

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

    @pytest.mark.apm_1542
    @pytest.mark.happy_path
    @pytest.mark.authorize_endpoint
    def test_cache_scoping(self):
        """
        Test identity cache scoping:
            * Given i am authorizing
            * And sending two requests to the authorize endpoint
            * When using the same client_id
            * When requesting an auth code with the other state value
            * Then it should return 200
        """

        # Initialise authorize request number one
        request_1_state1 = str(uuid.uuid4())
        response = self.oauth.check_and_return_endpoint(
            verb='GET',
            endpoint='authorize',
            expected_status_code=302,
            expected_response="",
            params={
                'client_id': config.CLIENT_ID,
                'redirect_uri': config.REDIRECT_URI,
                'response_type': 'code',
                'state': request_1_state1
            },
            allow_redirects=False
        )
        response_1_state2 = self.oauth.get_param_from_url(url=response.headers["Location"], param="state")

        # Initialise authorize request number two
        request_2_state1 = str(uuid.uuid4())
        response = self.oauth.check_and_return_endpoint(
            verb='GET',
            endpoint='authorize',
            expected_status_code=302,
            expected_response="",
            params={
                'client_id': config.CLIENT_ID,
                'redirect_uri': config.REDIRECT_URI,
                'response_type': 'code',
                'state': request_2_state1
            },
            allow_redirects=False
        )
        response_2_state2 = self.oauth.get_param_from_url(url=response.headers["Location"], param="state")

        # Verify set states for state1 values are different
        assert request_1_state1 != request_2_state1
        # Verify returned state values are different
        assert response_1_state2 != response_2_state2

        # Use state from request 2 as first request
        response = self.oauth.check_and_return_endpoint(
            verb='POST',
            endpoint='sim_auth',
            expected_status_code=302,
            expected_response="",
            headers={"Content-Type": "application/x-www-form-urlencoded"},
            data={"state": response_2_state2},
            params={
                'client_id': config.CLIENT_ID,
                'redirect_uri': config.REDIRECT_URI,
                'scope': 'openid',
                'response_type': 'code',
                'state': response_2_state2
            },
            allow_redirects=False
        )
        auth_code = self.oauth.get_param_from_url(url=response.headers["Location"], param="code")

        # Make callback request from request 2 state
        response = self.oauth.check_and_return_endpoint(
            verb='GET',
            endpoint='callback',
            expected_status_code=302,
            expected_response="",
            params={
                'code': auth_code,
                'client_id': config.CLIENT_ID,
                'state': response_2_state2
            },
            allow_redirects=False
        )
        # Verify auth code is returned and state1 is returned
        response_params = self.oauth.get_params_from_url(response.headers["Location"])
        assert response_params["code"]
        assert response_params["state"] == request_2_state1

    @pytest.mark.apm_1542
    @pytest.mark.errors
    @pytest.mark.authorize_endpoint
    @pytest.mark.token_endpoint
    def test_cache_scoping_error_condition(self):
        """
        Test identity cache scoping:
            * Given i am authorizing
            * And sending two requests to the authorize endpoint
            * When using different client_ids
            * When requesting an access token with the other state value
            * Then it should return 401
        """

        # Initialise authorize request number one
        response = self.oauth.check_and_return_endpoint(
            verb='GET',
            endpoint='authorize',
            expected_status_code=302,
            expected_response="",
            params={
                'client_id': config.CLIENT_ID,
                'redirect_uri': config.REDIRECT_URI,
                'response_type': 'code',
                'state': '1234567890'
            },
            allow_redirects=False
        )
        request_1_state = self.oauth.get_param_from_url(url=response.headers["Location"], param="state")

        # Initialise authorize request number two as different application
        self.switch_to_valid_asid_application()
        response = self.oauth.check_and_return_endpoint(
            verb='GET',
            endpoint='authorize',
            expected_status_code=302,
            expected_response="",
            params={
                'client_id': config.CLIENT_ID,
                'redirect_uri': config.REDIRECT_URI,
                'response_type': 'code',
                'state': '1234567890'
            },
            allow_redirects=False
        )
        request_2_state = self.oauth.get_param_from_url(url=response.headers["Location"], param="state")

        # Verify state values are different
        assert request_1_state != request_2_state

        # Use state from request 2 as first request application
        self.switch_to_application()
        response = self.oauth.check_and_return_endpoint(
            verb='POST',
            endpoint='sim_auth',
            expected_status_code=302,
            expected_response="",
            headers={"Content-Type": "application/x-www-form-urlencoded"},
            data={"state": request_2_state},
            params={
                'client_id': config.CLIENT_ID,
                'redirect_uri': config.REDIRECT_URI,
                'scope': 'openid',
                'response_type': 'code',
                'state': request_2_state
            },
            allow_redirects=False
        )
        auth_code = self.oauth.get_param_from_url(url=response.headers["Location"], param="code")

        # Make callback request from request 2 state
        self.oauth.check_endpoint(
            verb='GET',
            endpoint='callback',
            expected_status_code=401,
            expected_response="",
            params={
                'code': auth_code,
                'client_id': config.CLIENT_ID,
                'state': request_2_state
            },
            allow_redirects=False
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

    @pytest.mark.apm_1064
    @pytest.mark.errors
    @pytest.mark.callback_endpoint
    @pytest.mark.parametrize('request_data', [
        # condition 1: invalid client id
        {
            'expected_status_code': 401,
            'expected_response': "",
            'params': {
                'code': "some-code",
                'client_id': 'invalid-client-id',
                'state': random.getrandbits(32)
            },
        },
    ])
    def test_callback_error_conditions(self, request_data: dict):
        assert self.oauth.check_endpoint('GET', 'callback', **request_data)
