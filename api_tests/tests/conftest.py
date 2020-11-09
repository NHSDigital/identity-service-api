import pytest
from api_tests.steps.check_oauth import CheckOauth
from api_tests.steps.check_pds import CheckPds


def _get_parametrized_values(request):
    for mark in request.node.own_markers:
        if mark.name == 'parametrize':
            # index 0 is the argument name while index 1 is the argument values,
            # here we are only interested in the values
            return mark.args[1]


@ pytest.fixture()
def get_token_using_jwt(request):
    """Get a token using a signed JWT and assign it to the test instance"""
    oauth_endpoints = CheckOauth()
    _jwt = oauth_endpoints.create_jwt(kid="test-1")
    response, _ = oauth_endpoints.get_jwt_token_response(_jwt)
    setattr(request.cls, 'jwt_response', response)
    setattr(request.cls, 'jwt_signed_token', response['access_token'])


@pytest.fixture()
def get_token(request):
    """Get the token and assign it to the test instance"""
    oauth_endpoints = CheckOauth()
    token = oauth_endpoints.get_token_response()
    setattr(request.cls, 'token', token['access_token'])
    setattr(request.cls, 'refresh', token['refresh_token'])  # This is required if you want to request a refresh token
    return oauth_endpoints


@pytest.fixture()
def get_refresh_token(request, get_token):
    """Get the refresh token and assign it to the test instance"""
    # Requesting a refresh token will expire the previous access token
    refresh_token = get_token.get_token_response(grant_type='refresh_token', refresh_token=request.cls.refresh)
    setattr(request.cls, 'refresh_token', refresh_token['refresh_token'])


@pytest.fixture()
def get_token_with_extra_long_expiry_time(request):
    """Useful for debugging and for tests that take longer and are require to reuse the token"""
    oauth_endpoints = CheckOauth()
    token = oauth_endpoints.get_token_response(timeout=500000)  # 5 minuets
    setattr(request.cls, 'token', token['access_token'])
    setattr(request.cls, 'refresh', token['refresh_token'])  # This is required if you want to request a refresh token
    return oauth_endpoints


@pytest.fixture(scope='function')
def update_token_in_parametrized_headers(request):
    # Manually setting this fixture for session use because the pytest
    # session scope is called before any of the markers are set.
    if not hasattr(request.cls, 'setup_done'):
        token = CheckOauth().get_token_response()
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

    oauth = CheckOauth()
    setattr(request.cls, "oauth", oauth)

    pds = CheckPds()
    setattr(request.cls, "pds", pds)

    yield  # Handover to test

    # Teardown
    try:
        # Close any lingering sessions
        request.cls.test.session.close()
    except AttributeError:
        # Probably failed during setup
        # so nothing to teardown
        pass
