import asyncio
import aiohttp
import os
import pytest
from time import time
from typing import Dict
from uuid import uuid4
from api_test_utils.oauth_helper import OauthHelper
from api_test_utils.apigee_api_trace import ApigeeApiTraceDebug
from api_test_utils.apigee_api_apps import ApigeeApiDeveloperApps
from api_test_utils.apigee_api_products import ApigeeApiProducts
from e2e.scripts import config

def get_env(variable_name: str) -> str:
    """Returns a environment variable"""
    try:
        var = os.environ[variable_name]
        if not var:
            raise RuntimeError(f"Variable is null, Check {variable_name}.")
        return var
    except KeyError:
        raise RuntimeError(f"Variable is not set, Check {variable_name}.")


def nhs_login_subject_token(test_app: ApigeeApiDeveloperApps) -> Dict[str, str]:
    id_token_claims = {
        "aud": "tf_-APIM-1",
        "id_status": "verified",
        "token_use": "id",
        "auth_time": 1616600683,
        "iss": "https://internal-dev.api.service.nhs.uk",  # Points to internal dev -> testing JWKS
        "sub": "https://internal-dev.api.service.nhs.uk",
        "exp": int(time()) + 300,
        "iat": int(time()) - 10,
        "vtm": "https://auth.sandpit.signin.nhs.uk/trustmark/auth.sandpit.signin.nhs.uk",
        "jti": str(uuid4()),
        "sid": "08a5019c-17e1-4977-8f42-65a12843ea02"
    }

    id_token_headers = {
        "kid": "nhs-login",
        "typ": "JWT",
        "alg": "RS512",
    }
    
    # private key we retrieved from earlier
    nhs_login_id_token_private_key_path = get_env("ID_TOKEN_NHS_LOGIN_PRIVATE_KEY_ABSOLUTE_PATH")

    with open(nhs_login_id_token_private_key_path, "r") as f:
        contents = f.read()

    id_token_jwt = test_app.oauth.create_id_token_jwt(
        algorithm="RS512",
        claims=id_token_claims,
        headers=id_token_headers,
        signing_key=contents,
    )

    subject_token = {
        "id_token_jwt": id_token_jwt,
        "sid": "08a5019c-17e1-4977-8f42-65a12843ea02"
    }

    return subject_token


@pytest.fixture(scope="function")
async def test_app_and_product():
    apigee_product = ApigeeApiProducts()
    await apigee_product.create_new_product()
    await apigee_product.update_proxies([config.SERVICE_NAME])

    apigee_app = ApigeeApiDeveloperApps()
    # await apigee_app.create_new_app()

    # await apigee_app.add_api_product(
    #     api_products=[apigee_product.name]
    # )

    await apigee_product.update_ratelimits(
        quota=60000,
        quota_interval="1",
        quota_time_unit="minute",
        rate_limit="1000ps",
    )

    await apigee_app.setup_app(
        api_products=[apigee_product.name],
        custom_attributes={
            "jwks-resource-url": "https://raw.githubusercontent.com/NHSDigital/identity-service-jwks/main/jwks/internal-dev/9baed6f4-1361-4a8e-8531-1f8426e3aba8.json" # noqa
        },
    )

    apigee_app.oauth = OauthHelper(apigee_app.client_id, apigee_app.client_secret, apigee_app.callback_url)

    yield apigee_product, apigee_app

    await apigee_app.destroy_app()
    await apigee_product.destroy_product()

@pytest.mark.asyncio
class TestBackChannelLogout:
    """ A test suite for back-channel logout functionality"""

    @pytest.mark.asyncio
    async def test_back_channel_logout(self, test_app_and_product):
        test_product, test_app = test_app_and_product
        client_id = test_app.client_id
        client_secret = test_app.client_secret

        # Generate and sign subject access token
        subject_token = nhs_login_subject_token(test_app)

        # Create client assertion JWT
        client_assertion_jwt = test_app.oauth.create_jwt(kid="test-1")

        # Exchange above for access token
        token_resp = await test_app.oauth.get_token_response(
            grant_type="token_exchange",
            data={
                "grant_type": "urn:ietf:params:oauth:grant-type:token-exchange",
                "subject_token_type": "urn:ietf:params:oauth:token-type:id_token",
                "client_assertion_type": "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
                "subject_token": subject_token["id_token_jwt"],
                "client_assertion": client_assertion_jwt,
            },
        )
        print(token_resp)
        
        # Test access token
        assert token_resp["status_code"] == 200

        # Generate and sign logout token
        # Submit logout token to back-channel logout endpoint
        # Test access token has been revoked

