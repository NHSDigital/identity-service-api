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


def create_logout_token(test_app: ApigeeApiDeveloperApps) -> Dict[str, str]:
    logout_token_claims = {
        "aud": "9999999999",
        "iss": "https://am.nhsdev.auth-ptl.cis2.spineservices.nhs.uk:443/openam/oauth2/realms/root/realms/oidc",  # Points to internal dev -> testing JWKS
        "sub": "9999999999",
        "iat": int(time()) - 10,
        "jti": str(uuid4()),
        "sid": "08a5019c-17e1-4977-8f42-65a12843ea02",
        "events": { "http://schemas.openid.net/event/backchannel-logout": {} }
    }

    logout_token_headers = {
        "kid": "nhs-login",
        "typ": "JWT",
        "alg": "RS512",
    }
    
    # private key we retrieved from earlier
    id_token_private_key_path = get_env("ID_TOKEN_PRIVATE_KEY_ABSOLUTE_PATH")

    with open(id_token_private_key_path, "r") as f:
        contents = f.read()

    logout_token_jwt = test_app.oauth.create_id_token_jwt(
        algorithm="RS512",
        claims=logout_token_claims,
        headers=logout_token_headers,
        signing_key=contents,
    )

    return logout_token_jwt


@pytest.fixture(scope="function")
async def test_app():
    apigee_product = ApigeeApiProducts()
    await apigee_product.create_new_product()
    await apigee_product.update_proxies([config.SERVICE_NAME])

    apigee_app = ApigeeApiDeveloperApps()

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

    api_service_name = get_env("SERVICE_NAME")

    await apigee_product.update_scopes(
        [f"urn:nhsd:apim:user-nhs-login:P9:{api_service_name}"]
    )

    yield apigee_app

    await apigee_app.destroy_app()


@pytest.mark.asyncio
class TestBackChannelLogout:
    """ A test suite for back-channel logout functionality"""

    @pytest.mark.asyncio
    async def test_backchannel_logout_happy_path(self, test_app):
        token_resp = await self.oauth.hit_oauth_endpoint(
            method="POST",
            endpoint="token",
            data={
                'client_id': self.oauth.client_id,
                'client_secret': self.oauth.client_secret,
                'grant_type': "authorization_code",
                'redirect_uri': self.oauth.redirect_uri,
                'code': await self.oauth.get_authenticated_with_simulated_auth(),
                '_access_token_expiry_ms': 5000
            }
        )
        #<----
        # Test access token
        assert token_resp["status_code"] == 200

        access_token = token_resp["body"]["access_token"]

        user_info_resp = await test_app.oauth.hit_oauth_endpoint(
            method="GET",
            endpoint="userinfo",
            headers={"Authorization": f"Bearer {access_token}"}
        )

        assert user_info_resp["status_code"] == 200

        # TO DO - Generate and sign logout token
        logout_token = create_logout_token(test_app)

        # Submit logout token to back-channel logout endpoint
        back_channel_resp = await test_app.oauth.hit_oauth_endpoint(
            method="POST",
            endpoint="backchannel_logout",
            data={"logout_token": logout_token}
        )

        assert back_channel_resp["status_code"] == 200

        # Test access token has been revoked
        user_info_resp = await test_app.oauth.hit_oauth_endpoint(
            method="GET",
            endpoint="userinfo",
            headers={"Authorization": f"Bearer {access_token}"}
        )

        assert user_info_resp["status_code"] == 401

