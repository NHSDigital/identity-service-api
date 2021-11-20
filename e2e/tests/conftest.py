import json
import pytest
import asyncio
from api_test_utils.oauth_helper import OauthHelper
from api_test_utils.apigee_api_apps import ApigeeApiDeveloperApps
from api_test_utils.apigee_api_products import ApigeeApiProducts
from e2e.scripts.generic_request import GenericRequest
from time import time
from e2e.scripts import config
from api_test_utils.apigee_api_trace import ApigeeApiTraceDebug
import urllib.parse as urlparse
from urllib.parse import parse_qs
from e2e.scripts.config import (
    OAUTH_URL,
    ID_TOKEN_NHS_LOGIN_PRIVATE_KEY_ABSOLUTE_PATH,
    MOCK_IDP_BASE_URL
)

pytest_plugins = [
   "api_test_utils.fixtures",
]

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
        **kwargs,
    ):
        if test_app:
            # Use provided test app
            oauth = OauthHelper(
                test_app.client_id, test_app.client_secret, test_app.callback_url
            )
            print(oauth.base_uri)
            resp = await oauth.get_token_response(grant_type=grant_type, **kwargs)
        else:
            # Use default test app
            resp = await request.cls.oauth.get_token_response(
                grant_type=grant_type, **kwargs
            )

        if resp["status_code"] != 200:
            message = "unable to get token"
            raise RuntimeError(
                f"\n{'*' * len(message)}\n"
                f"MESSAGE: {message}\n"
                f"URL: {resp.get('url')}\n"
                f"STATUS CODE: {resp.get('status_code')}\n"
                f"RESPONSE: {resp.get('body')}\n"
                f"HEADERS: {resp.get('headers')}\n"
                f"{'*' * len(message)}\n"
            )
        return resp["body"]

    return _token


@pytest.fixture()
async def apigee_start_trace(expected_filtered_scopes):
    apigee_trace = ApigeeApiTraceDebug(proxy=config.SERVICE_NAME)
    await apigee_trace.start_trace()
    return apigee_trace


@pytest.fixture()
async def get_token_cis2_token_exchange(
    test_app_and_product, product_1_scopes, product_2_scopes
):
    """Call identity server to get an access token"""
    test_product, test_product2, test_app = test_app_and_product
    await test_product.update_scopes(product_1_scopes)
    await test_product2.update_scopes(product_2_scopes)

    oauth = OauthHelper(
        client_id=test_app.client_id,
        client_secret=test_app.client_secret,
        redirect_uri=test_app.callback_url,
    )

    claims = {
        "at_hash": "tf_-lqpq36lwO7WmSBIJ6Q",
        "sub": "787807429511",
        "auditTrackingId": "91f694e6-3749-42fd-90b0-c3134b0d98f6-1546391",
        "amr": ["N3_SMARTCARD"],
        "iss": "https://am.nhsint.auth-ptl.cis2.spineservices.nhs.uk:443/"
        "openam/oauth2/realms/root/realms/NHSIdentity/realms/Healthcare",
        "tokenName": "id_token",
        "aud": "969567331415.apps.national",
        "c_hash": "bc7zzGkClC3MEiFQ3YhPKg",
        "acr": "AAL3_ANY",
        "org.forgerock.openidconnect.ops": "-I45NjmMDdMa-aNF2sr9hC7qEGQ",
        "s_hash": "LPJNul-wow4m6Dsqxbning",
        "azp": "969567331415.apps.national",
        "auth_time": 1610559802,
        "realm": "/NHSIdentity/Healthcare",
        "exp": int(time()) + 6000,
        "tokenType": "JWTToken",
        "iat": int(time()) - 100,
    }

    with open(config.ID_TOKEN_PRIVATE_KEY_ABSOLUTE_PATH, "r") as f:
        contents = f.read()

    client_assertion_jwt = oauth.create_jwt(kid="test-1")
    id_token_jwt = oauth.create_id_token_jwt(
        kid="identity-service-tests-1", claims=claims, signing_key=contents
    )

    # When
    token_resp = await oauth.get_token_response(
        grant_type="token_exchange",
        data={
            "grant_type": "urn:ietf:params:oauth:grant-type:token-exchange",
            "subject_token_type": "urn:ietf:params:oauth:token-type:id_token",
            "client_assertion_type": "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
            "subject_token": id_token_jwt,
            "client_assertion": client_assertion_jwt,
        },
    )

    return token_resp


@pytest.fixture()
async def get_token_nhs_login_token_exchange(
    test_app_and_product, product_1_scopes, product_2_scopes
):
    """Call nhs login to get an access token"""
    test_product, test_product2, test_app = test_app_and_product
    await test_product.update_scopes(product_1_scopes)
    await test_product2.update_scopes(product_2_scopes)

    oauth = OauthHelper(
        client_id=test_app.client_id,
        client_secret=test_app.client_secret,
        redirect_uri=test_app.callback_url,
    )

    claims = {
        "sub": "8dc9fc1d-c3cb-48e1-ba62-b1532539ab6d",
        "birthdate": "1939-09-26",
        "nhs_number": "9482807146",
        "iss": "https://internal-dev.api.service.nhs.uk",
        "nonce": "randomnonce",
        "vtm": "https://auth.aos.signin.nhs.uk/trustmark/auth.aos.signin.nhs.uk",
        "aud": "java_test_client",
        "id_status": "verified",
        "token_use": "id",
        "surname": "CARTHY",
        "auth_time": 1617272144,
        "vot": "P9.Cp.Cd",
        "identity_proofing_level": "P9",
        "exp": int(time()) + 6000,
        "iat": int(time()) - 100,
        "family_name": "CARTHY",
        "jti": "b6d6a28e-b0bb-44e3-974f-bb245c0b688a",
    }

    with open(config.ID_TOKEN_NHS_LOGIN_PRIVATE_KEY_ABSOLUTE_PATH, "r") as f:
        contents = f.read()

    client_assertion_jwt = oauth.create_jwt(kid="test-1")
    id_token_jwt = oauth.create_id_token_jwt(
        kid="nhs-login", algorithm="RS512", claims=claims, signing_key=contents
    )

    # When
    token_resp = await oauth.get_token_response(
        grant_type="token_exchange",
        data={
            "grant_type": "urn:ietf:params:oauth:grant-type:token-exchange",
            "subject_token_type": "urn:ietf:params:oauth:token-type:id_token",
            "client_assertion_type": "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
            "subject_token": id_token_jwt,
            "client_assertion": client_assertion_jwt,
        },
    )

    return token_resp


@pytest.fixture()
async def set_access_token(request, get_token):
    token = await get_token()
    setattr(request.cls.oauth, "access_token", token["access_token"])
    setattr(request.cls.oauth, "refresh_token", token["refresh_token"])


@pytest.fixture()
async def set_refresh_token(request, get_token, set_access_token):
    refresh_token = await get_token(
        grant_type="refresh_token", refresh_token=request.cls.oauth.refresh_token
    )
    setattr(request.cls.oauth, "refresh_token", refresh_token["refresh_token"])


@pytest.fixture()
def helper():
    return GenericRequest()


async def _set_default_rate_limit(product: ApigeeApiProducts):
    await product.update_ratelimits(
        quota=60000, quota_interval="1", quota_time_unit="minute", rate_limit="1000ps"
    )


@pytest.fixture(scope="function")
async def test_product():
    """Create a test product which can be modified by the test"""
    product = ApigeeApiProducts()
    await product.create_new_product()
    await _set_default_rate_limit(product)
    yield product
    await product.destroy_product()


@pytest.fixture(scope="function")
def app():
    return ApigeeApiDeveloperApps()


@pytest.fixture(scope="function")
async def test_app(app):
    """Create a test app which can be modified in the test"""
    await app.create_new_app()
    # Sadly no way to do this in the constructor
    ratelimiting = {
        config.SERVICE_NAME: {
            "quota": {"enabled": False},
            "spikeArrest": {"enabled": False},
        }
    }
    await app.set_custom_attributes({"ratelimiting": json.dumps(ratelimiting)})
    yield app
    await app.destroy_app()


async def _product_with_full_access():
    product = ApigeeApiProducts()
    await product.create_new_product()
    await _set_default_rate_limit(product)
    await product.update_scopes(
        [
            "personal-demographics-service:USER-RESTRICTED",
            "urn:nhsd:apim:app:level3:",
            "urn:nhsd:apim:user-nhs-id:aal3:personal-demographics-service",
            "urn:nhsd:apim:user-nhs-login:P9:some-api",
            "urn:nhsd:apim:user-nhs-login:P5:some-api",
            "urn:nhsd:apim:user-nhs-login:P0:some-api",
        ]
    )

    await product.update_paths(paths=["/", "/*"])
    return product


@pytest.fixture(scope="session", autouse=True)
def setup_session(request):
    """This fixture is automatically called once at the start of pytest execution.
    The default app created here should be modified by your tests.
    If your test requires specific app config then please create your own using
    the fixture test_app"""
    async def _setup_session(request):
        product = await _product_with_full_access()
        app = ApigeeApiDeveloperApps()

        print("\nCreating Default App..")
        await app.create_new_app(
            callback_url="https://nhsd-apim-testing-internal-dev.herokuapp.com/callback"
        )
        await app.add_api_product([product.name])

        # Set default JWT Testing resource url
        await app.set_custom_attributes(
            {
                "jwks-resource-url": "https://raw.githubusercontent.com/NHSDigital/"
                "identity-service-jwks/main/jwks/internal-dev/"
                "9baed6f4-1361-4a8e-8531-1f8426e3aba8.json"
            }
        )

        oauth = OauthHelper(app.client_id, app.client_secret, app.callback_url)

        for item in request.node.items:
            setattr(item.cls, "oauth", oauth)

        return app, product

    async def _destroy_session(app, product):
        print("\nDestroying Default App..")
        await app.destroy_app()
        await product.destroy_product()

    app, product = asyncio.run(_setup_session(request))
    yield
    asyncio.run(_destroy_session(app, product))


@pytest.fixture(scope="function", autouse=True)
def setup_function(request):
    """This function is called before each test is executed"""
    # Get the name of the current test and attach it the the test instance
    name = (request.node.name, request.node.originalname)[
        request.node.originalname is not None
    ]
    setattr(request.cls, "name", name)

class AuthCredentialAndTokenClaim:
    def __init__(self, auth_method=None, scope=''):
        self.auth_method=auth_method
        self.scope=scope

    async def get_token(self, oauth):
        state = await self.get_state(oauth)
        auth_code = await self.make_auth_request(oauth, state)
        auth_code = await self.make_callback_request(oauth, state, auth_code)

        token_resp = await oauth.hit_oauth_endpoint(
            method="POST",
            endpoint="token",
            data={
                "grant_type": "authorization_code",
                "state": state,
                "code": auth_code,
                "redirect_uri": oauth.redirect_uri,
                "client_id": oauth.client_id,
                "client_secret": oauth.client_secret,
            },
            allow_redirects=False,
        )
        
        return token_resp["body"]

    async def get_state(self, oauth, test_app=None):

        self.client_id = oauth.client_id
        self.redirect_uri = oauth.redirect_uri
        if(test_app):
            self.client_id = test_app.client_id
            self.redirect_uri = await test_app.get_callback_url()

        response = await oauth.hit_oauth_endpoint(
            method="GET",
            endpoint="authorize",
            params={
                "client_id": self.client_id,
                "redirect_uri": self.redirect_uri,
                "response_type": "code",
                "state": "1234567890",
                "scope": self.scope,
            },
            allow_redirects=False,
        )
        self.response = response
        if("Location" in response["headers"]):
            location = response["headers"]["Location"]
            state = urlparse.urlparse(location)
            return parse_qs(state.query)["state"]


    async def make_auth_request(self, oauth, state):

        data={"state": state[0]}
        if(self.auth_method):
            data={"state": state[0], "auth_method": self.auth_method}

        # # Make simulated auth request to authenticate     

        response = await oauth.hit_oauth_endpoint(
            base_uri=MOCK_IDP_BASE_URL,
            method="POST",
            endpoint="simulated_auth",
            params={
                "response_type": "code",
                "client_id": self.client_id,
                "redirect_uri": self.redirect_uri,
                "scope": "openid",
                "state": state[0],
            },
            headers={"Content-Type": "application/x-www-form-urlencoded"},
            data=data,
            allow_redirects=False,
        )
        self.response = response
        if("Location" in response["headers"]):
            location = response["headers"]["Location"]
            auth_code = urlparse.urlparse(location)
            return parse_qs(auth_code.query)["code"]

    async def make_callback_request(self, oauth, state, auth_code):
        # # Make initial callback request

        response = await oauth.hit_oauth_endpoint(
            method="GET",
            endpoint="callback",
            params={"code": auth_code[0], "client_id": "some-client-id", "state": state[0]},
            allow_redirects=False,
        )
        self.response = response
        if("Location" in response["headers"]):
            location = response["headers"]["Location"]
            auth_code = urlparse.urlparse(location)
            return parse_qs(auth_code.query)["code"]

@pytest.fixture()
def auth_code_nhs_login(auth_method):
    return AuthCredentialAndTokenClaim(auth_method, "nhs-login")

@pytest.fixture()
def auth_code_nhs_cis2(auth_method):
    return AuthCredentialAndTokenClaim(auth_method)

async def _get_userinfo_nhs_login_exchanged_token(oauth):
    id_token_claims = {
            "aud": "tf_-APIM-1",
            "id_status": "verified",
            "token_use": "id",
            "auth_time": 1616600683,
            "iss": "https://internal-dev.api.service.nhs.uk",
            "vot": "P9.Cp.Cd",
            "exp": int(time()) + 600,
            "iat": int(time()) - 10,
            "vtm": "https://auth.sandpit.signin.nhs.uk/trustmark/auth.sandpit.signin.nhs.uk",
            "jti": "b68ddb28-e440-443d-8725-dfe0da330118",
            "identity_proofing_level": "P9"
        }
    id_token_headers = {
            "sub": "49f470a1-cc52-49b7-beba-0f9cec937c46",
            "aud": "APIM-1",
            "kid": "nhs-login",
            "iss": "https://internal-dev.api.service.nhs.uk",
            "typ": "JWT",
            "exp": 1616604574,
            "iat": 1616600974,
            "alg": "RS512",
            "jti": "b68ddb28-e440-443d-8725-dfe0da330118",
        }

    with open(ID_TOKEN_NHS_LOGIN_PRIVATE_KEY_ABSOLUTE_PATH, "r") as f:
        contents = f.read()

    client_assertion_jwt = oauth.create_jwt(kid="test-1")
    id_token_jwt = oauth.create_id_token_jwt(
        algorithm="RS512",
        claims=id_token_claims,
        headers=id_token_headers,
        signing_key=contents,
    )
    resp = await oauth.get_token_response(
        grant_type="token_exchange",
        _jwt=client_assertion_jwt,
        id_token_jwt=id_token_jwt,
    )
    return resp       

@pytest.fixture()
def get_exchange_code_nhs_login_token():
    return _get_userinfo_nhs_login_exchanged_token


