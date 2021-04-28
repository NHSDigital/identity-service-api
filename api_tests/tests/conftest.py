import pytest
import asyncio
from api_test_utils.oauth_helper import OauthHelper
from api_test_utils.apigee_api_apps import ApigeeApiDeveloperApps
from api_test_utils.apigee_api_products import ApigeeApiProducts
from api_tests.scripts.generic_request import GenericRequest


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
        5. access_token using a specific app
            get_token(app=<app>)
    """

    async def _token(
        grant_type: str = "authorization_code",
        test_app: ApigeeApiDeveloperApps = None,
        **kwargs
    ):
        if test_app:
            # Use provided test app
            oauth = OauthHelper(test_app.client_id, test_app.client_secret, test_app.callback_url)
            resp = await oauth.get_token_response(grant_type=grant_type, **kwargs)
        else:
            # Use default test app
            resp = await request.cls.oauth.get_token_response(grant_type=grant_type, **kwargs)

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


def _set_default_rate_limit(product: ApigeeApiProducts):
    product.update_ratelimits(quota=60000,
                              quota_interval="1",
                              quota_time_unit="minute",
                              rate_limit="1000ps")


@pytest.fixture()
async def test_product():
    """Create a test product which can be modified by the test"""
    product = ApigeeApiProducts()
    await product.create_new_product()
    _set_default_rate_limit(product)
    yield product
    await product.destroy_product()


@pytest.fixture()
def app():
    return ApigeeApiDeveloperApps()


@pytest.fixture()
async def test_app(app):
    """Create a test app which can be modified in the test"""
    await app.create_new_app()

    yield app
    await app.destroy_app()


async def _product_with_full_access():
    product = ApigeeApiProducts()
    await product.create_new_product()
    _set_default_rate_limit(product)
    product.update_scopes([
        "personal-demographics-service:USER-RESTRICTED",
        "urn:nhsd:apim:app:level3:",
        "urn:nhsd:apim:user-nhs-id:aal3:personal-demographics-service",
        "urn:nhsd:apim:user-nhs-login:P9:some-api"
    ])

    await product.update_paths(paths=["/", "/*"])
    return product


@pytest.fixture(scope="session", autouse=True)
def setup_session(request):
    """This fixture is automatically called once at the start of pytest execution.
    The default app created here should be modified by your tests.
    If your test requires specific app config then please create your own using
    the fixture test_app"""
    product = asyncio.run(_product_with_full_access())
    app = ApigeeApiDeveloperApps()

    print("\nCreating Default App..")
    asyncio.run(app.create_new_app(callback_url="https://nhsd-apim-testing-internal-dev.herokuapp.com/callback"))
    asyncio.run(app.add_api_product([product.name]))

    # Set default JWT Testing resource url
    asyncio.run(
        app.set_custom_attributes(
            {
                'jwks-resource-url': 'https://raw.githubusercontent.com/NHSDigital/'
                                     'identity-service-jwks/main/jwks/internal-dev/'
                                     '9baed6f4-1361-4a8e-8531-1f8426e3aba8.json'
            }
        )
    )

    oauth = OauthHelper(app.client_id, app.client_secret, app.callback_url)
    for item in request.node.items:
        setattr(item.cls, "oauth", oauth)

    yield

    # Teardown
    print("\nDestroying Default App..")
    asyncio.run(app.destroy_app())
    asyncio.run(product.destroy_product())


@pytest.fixture(scope="function", autouse=True)
def setup_function(request):
    """This function is called before each test is executed"""
    # Get the name of the current test and attach it the the test instance
    name = (request.node.name, request.node.originalname)[request.node.originalname is not None]
    setattr(request.cls, "name", name)
