import pytest
from api_tests.steps.check_oauth_endpoints import CheckOauthEndpoints


def _get_parametrized_values(request):
    for mark in request.node.own_markers:
        if mark.name == 'parametrize':
            # index 0 is the argument name while index 1 is the argument values,
            # here we are only interested in the values
            return mark.args[1]


@pytest.fixture()
def get_token(request):
    """Get the token and assign it to the test instance"""
    oauth_endpoints = CheckOauthEndpoints()
    token = oauth_endpoints.get_token_response()
    setattr(request.cls, 'token', token['access_token'])

    refresh_token = oauth_endpoints.get_token_response(grant_type='refresh_token', refresh_token=token['refresh_token'])
    setattr(request.cls, 'refresh_token', refresh_token['refresh_token'])


@pytest.fixture(scope='function')
def update_token_in_parametrized_headers(request):
    # Manually setting this fixture for session use because the pytest
    # session scope is called before any of the markers are set.
    if not hasattr(request.cls, 'setup_done'):
        token = CheckOauthEndpoints().get_token_response()
        for value in _get_parametrized_values(request):
            if value.get('Authorization', None) == 'valid_token':
                value['Authorization'] = f'Bearer {token["access_token"]}'

        # Make sure the token is not refreshed before every test
        setattr(request.cls, 'setup_done', True)


@pytest.fixture(scope='function')
def setup(request):
    """This function is called before each test is executed"""
    # Get the name of the current test and attach it the the test instance
    name = (request.node.name, request.node.originalname)[request.node.originalname is not None]
    setattr(request.cls, "name", name)

    test = CheckOauthEndpoints()
    setattr(request.cls, "test", test)

    yield  # Handover to test

    # Teardown
    try:
        # Close any lingering sessions
        request.cls.test.session.close()
    except AttributeError:
        # Probably failed during setup
        # so nothing to teardown
        pass
