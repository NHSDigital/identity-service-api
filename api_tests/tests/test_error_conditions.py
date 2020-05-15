from api_tests.config_files import config
import pytest


@pytest.mark.usefixtures("setup")
class TestOauthErrorConditionsSuite:
    """ A Simple test suit to generate error conditions and ensure the responses are as expected """
    @pytest.mark.errors
    @pytest.mark.authorize_endpoint
    @pytest.mark.parametrize('request_data', [
        # condition 1: invalid redirect uri
        {
            'expected_status_code': 400,
            'params': {
                'client_id': config.CLIENT_ID,
                'redirect_uri': f'{config.REDIRECT_URI}/invalid',  # invalid redirect uri
                'response_type': 'code',
                'state': '1234567890'
            },
            'expected_response': {
                'error': 'invalid_request',
                'error_description': f'Invalid redirection uri {config.REDIRECT_URI}/invalid'
            }
        },

        # condition 2: missing redirect uri
        {
            'expected_status_code': 400,
            'params': {
                'client_id': config.CLIENT_ID,
                'response_type': 'code',
                'state': '1234567890'
            },
            'expected_response': {
                'error': 'invalid_request',
                'error_description': 'Redirection uri is required'
            }
        },

        # condition 3: invalid client id
        {
            'expected_status_code': 401,
            'params': {
                'client_id': 'THISisANinvalidCLIENTid12345678',  # invalid client id
                'redirect_uri': config.REDIRECT_URI,
                'response_type': 'code',
                'state': '1234567890'
            },
            'expected_response': {
                'error': 'invalid_request',
                'error_description': "Invalid client id : THISisANinvalidCLIENTid12345678. clientId is invalid"
            }
        },

        # condition 4: missing client id
        {
            'expected_status_code': 400,
            'params': {
                'redirect_uri': config.REDIRECT_URI,
                'response_type': 'code',
                'state': '1234567890'
            },
            'expected_response': {
                'error': 'invalid_request',
                'error_description': 'The request is missing a required parameter : client_id'
            }
        },

        # condition 5: invalid response type
        {
            'expected_status_code': 400,
            'params': {
                'client_id': config.CLIENT_ID,
                'redirect_uri': config.REDIRECT_URI,
                'response_type': 'invalid',  # invalid response type
                'state': '1234567890'
            },
            'expected_response': {
                'ErrorCode': 'invalid_request',
                'Error': 'Response type must be code'
            }
        },

        # condition 6: missing response type
        {
            'expected_status_code': 400,
            'params': {
                'client_id': config.CLIENT_ID,
                'redirect_uri': config.REDIRECT_URI,
                'state': '1234567890'
            },
            'expected_response': {
                'ErrorCode': 'invalid_request',
                'Error': 'The request is missing a required parameter : response_type'
            }
        }
    ], ids=repr)
    def test_authorization_error_conditions(self, request_data: dict):
        assert self.test.check_endpoint('GET', 'authorize', **request_data)

    @pytest.mark.errors
    @pytest.mark.token_endpoint
    @pytest.mark.parametrize('request_data', [
        {
            'expected_status_code': 400,
            'params': {
                'client_id': config.CLIENT_ID,
                'client_secret': config.CLIENT_SECRET,
                'redirect_uri': config.REDIRECT_URI,
                'grant_type': 'invalid',  # invalid grant_type
            },
            'expected_response': {
                'error': 'invalid_request',
                'error_description':
                    'invalid grant_type'
            }
        },
    ], ids=repr)
    def test_token_error_conditions(self, request_data: dict):
        assert self.test.check_endpoint('POST', 'token', **request_data)
