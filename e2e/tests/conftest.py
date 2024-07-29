import pytest
import random

from uuid import uuid4
from time import time
from pytest_nhsd_apim.apigee_apis import (
    ApigeeNonProdCredentials,
    ApigeeClient,
    AccessTokensAPI,
    ApiProductsAPI,
)

from e2e.tests.utils.config import (
    API_NAME,
    PROXY_NAME,
    ENVIRONMENT
)

# FIXTURES FOR USE IN SET UP OF pytest_nhsd_apim
@pytest.fixture(scope="session")
def nhsd_apim_api_name():
    return API_NAME


@pytest.fixture(scope="session")
def nhsd_apim_proxy_name():
    return PROXY_NAME


# TOKEN DATA
@pytest.fixture()
def token_data_authorization_code(_test_app_credentials, _test_app_callback_url):
    return {
        "client_id": _test_app_credentials["consumerKey"],
        "client_secret": _test_app_credentials["consumerSecret"],
        "redirect_uri": _test_app_callback_url,
        "grant_type": "authorization_code",
        "code": None,  # Should be updated in the test
    }


@pytest.fixture
def token_data_token_exchange():
    return {
        "subject_token_type": "urn:ietf:params:oauth:token-type:id_token",
        "client_assertion_type": "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
        "subject_token": None,  # Should be replaced in test
        "client_assertion": None,  # Should be replaced in test
        "grant_type": "urn:ietf:params:oauth:grant-type:token-exchange",
    }


@pytest.fixture
def token_data_client_credentials():
    return {
        "client_assertion_type": "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
        "client_assertion": None,  # Should be replace in test
        "grant_type": "client_credentials",
    }


@pytest.fixture()
def refresh_token_data(_test_app_credentials):
    return {
        "client_id": _test_app_credentials["consumerKey"],
        "client_secret": _test_app_credentials["consumerSecret"],
        "grant_type": "refresh_token",
        "refresh_token": None,  # Should be updated in the test
    }


# AUTH PARAMS AND CLAIMS
@pytest.fixture()
def authorize_params(_test_app_credentials, _test_app_callback_url):
    return {
        "client_id": _test_app_credentials["consumerKey"],
        "redirect_uri": _test_app_callback_url,
        "response_type": "code",
        "state": random.getrandbits(32),
    }


@pytest.fixture
def claims(_test_app_credentials, nhsd_apim_proxy_url):
    return {
        "sub": _test_app_credentials["consumerKey"],
        "iss": _test_app_credentials["consumerKey"],
        "jti": str(uuid4()),
        "aud": nhsd_apim_proxy_url + "/token",
        "exp": int(time()) + 300,  # 5 minutes in the future
    }


@pytest.fixture
def cis2_subject_token_claims():
    return {
        "at_hash": "tf_-lqpq36lwO7WmSBIJ6Q",
        "sub": "787807429511",
        "auditTrackingId": "91f694e6-3749-42fd-90b0-c3134b0d98f6-1546391",
        "amr": ["N3_SMARTCARD"],
        "iss": "https://identity.ptl.api.platform.nhs.uk/realms/Cis2-mock-internal-dev",
        "tokenName": "id_token",
        "aud": "969567331415.apps.national",
        "c_hash": "bc7zzGkClC3MEiFQ3YhPKg",
        "acr": "AAL2_OR_AAL3_ANY",
        "id_assurance_level": int(3),
        "org.forgerock.openidconnect.ops": "-I45NjmMDdMa-aNF2sr9hC7qEGQ",
        "s_hash": "LPJNul-wow4m6Dsqxbning",
        "azp": "969567331415.apps.national",
        "auth_time": 1610559802,
        "realm": "/NHSIdentity/Healthcare",
        "exp": int(time()) + 300,
        "tokenType": "JWTToken",
        "iat": int(time()) - 100,
    }


@pytest.fixture
def nhs_login_id_token():
    return {
        "headers": {
            "sub": "49f470a1-cc52-49b7-beba-0f9cec937c46",
            "aud": "APIM-1",
            "kid": "B86zGrfcoloO13rnjKYDyAJcqj2iZAMrS49jyleL0Fo",
            "iss": "https://internal-dev.api.service.nhs.uk",
            "typ": "JWT",
            "exp": int(time()) + 600,
            "iat": int(time()) - 10,
            "alg": "RS512",
            "jti": "b68ddb28-e440-443d-8725-dfe0da330118",
        },
        "claims": {
            "aud": "tf_-APIM-1",
            "id_status": "verified",
            "token_use": "id",
            "auth_time": int(time()),
            "iss": "https://identity.ptl.api.platform.nhs.uk/realms/NHS-Login-mock-internal-dev",
            "vot": "P9.Cp.Cd",
            "exp": int(time()) + 600,
            "iat": int(time()) - 10,
            "vtm": "https://auth.sandpit.signin.nhs.uk/trustmark/auth.sandpit.signin.nhs.uk",
            "jti": "b68ddb28-e440-443d-8725-dfe0da330118",
            "identity_proofing_level": "P9",
            "nhs_number": "9912003071",
        },
    }


# APIGEE API CLIENTS
@pytest.fixture(scope="session")
def access_token_api():
    """
    Authenitcated wrapper for Apigee's access token API
    """
    config = ApigeeNonProdCredentials()
    client = ApigeeClient(config=config)
    return AccessTokensAPI(client=client)


@pytest.fixture(scope="session")
def products_api():
    """
    Authenitcated wrapper for Apigee's access token API
    """
    config = ApigeeNonProdCredentials()
    client = ApigeeClient(config=config)
    return ApiProductsAPI(client=client)


# APIGEE RESOURCES FOR WHEN STANDARD TEST_APP FROM PACKAGE IS NOT APPLICABLE
@pytest.fixture(scope="function")
def test_app_and_products_for_scopes(
    nhsd_apim_test_app,
    products_api,
    _apigee_edge_session,
    _apigee_app_base_url,
    nhsd_apim_proxy_name,
    nhsd_apim_unsubscribe_test_app_from_all_products,
):
    nhsd_apim_unsubscribe_test_app_from_all_products()

    app = nhsd_apim_test_app()
    app_name = app["name"]

    product_names = [f"apim-auto-{uuid4()}", f"apim-auto-{uuid4()}"]
    products = [
        {
            "apiResources": ["/"],
            "approvalType": "auto",
            "attributes": [{"name": "access", "value": "public"}],
            "description": product_name,
            "displayName": product_name,
            "environments": [ENVIRONMENT],
            "name": product_name,
            "proxies": [nhsd_apim_proxy_name],
            "scopes": [],
        }
        for product_name in product_names
    ]

    for product in products:
        products_api.post_products(body=product)

    app["apiProducts"] = product_names
    add_products_to_app_resp = _apigee_edge_session.post(
        f"{_apigee_app_base_url}/{app_name}", json=app
    )
    assert add_products_to_app_resp.status_code == 200

    app = add_products_to_app_resp.json()

    yield app, products

    nhsd_apim_unsubscribe_test_app_from_all_products()

    for product in products:
        products_api.delete_product_by_name(product_name=product["name"])
