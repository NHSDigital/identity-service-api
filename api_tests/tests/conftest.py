import pytest
from api_test_utils.oauth_helper import OauthHelper
from api_tests.config_files import config
from api_tests.scripts.generic_request import GenericRequest


def _get_parametrized_values(request):
    for mark in request.node.own_markers:
        if mark.name == 'parametrize':
            # index 0 is the argument name while index 1 is the argument values,
            # here we are only interested in the values
            return mark.args[1]


@pytest.fixture()
def get_token(request):
    """Get an access or refresh token
    some examples:
        1. access_token via simulated oauth (default)
            get_token()
        2. get access token with a specified timeout value (default is 5 seconds)
            get_token(timeout=500000)  # 5 minuets
        3. refresh_token via simulated oauth
            get_token(grant_type="refresh_token", refresh_token=<refresh_token>)
        4. access_token with JWT
            get_token(grant_type='client_credentials', _jwt=jwt)
    """

    async def _token(
        oauth: OauthHelper = request.cls.oauth,
        grant_type: str = "authorization_code",
        **kwargs
    ):
        resp = await oauth.get_token_response(grant_type=grant_type, **kwargs)

        if resp['status_code'] != 200:
            message = 'unable to get token'
            raise RuntimeError(f"\n{'*' * len(message)}\n"
                               f"MESSAGE: {message}\n"
                               f"URL: {resp.get('url')}\n"
                               f"STATUS CODE: {resp.get('status_code')}\n"
                               f"RESPONSE: {resp.get('body')}\n"
                               f"HEADERS: {resp.get('headers')}\n"
                               f"{'*' * len(message)}\n")
        return resp['body']
    return _token


@pytest.fixture()
async def set_access_token(request, get_token):
    token = await get_token()
    setattr(request.cls.oauth, "access_token", token['access_token'])
    setattr(request.cls.oauth, "refresh_token", token['refresh_token'])


@pytest.fixture()
async def set_refresh_token(request, get_token, set_access_token):
    refresh_token = await get_token(grant_type="refresh_token", refresh_token=request.cls.oauth.refresh_token)
    setattr(request.cls.oauth, "refresh_token", refresh_token['refresh_token'])


@pytest.fixture()
def helper():
    return GenericRequest()


@pytest.fixture(autouse=True)
def setup(request):
    """This function is called before each test is executed"""
    # Get the name of the current test and attach it the the test instance
    name = (request.node.name, request.node.originalname)[request.node.originalname is not None]
    setattr(request.cls, "name", name)

    oauth = OauthHelper(config.CLIENT_ID, config.CLIENT_SECRET, config.REDIRECT_URI)
    setattr(request.cls, "oauth", oauth)

    yield  # Handover to test

    # Teardown
    pass
