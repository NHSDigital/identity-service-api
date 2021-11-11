import os
import urllib.parse
import pytest
from requests.exceptions import ConnectionError
from asyncio import sleep
from time import time
from typing import Dict, Optional
from uuid import uuid4
from selenium.webdriver.common.by import By
from selenium.webdriver.common.keys import Keys
from api_test_utils.oauth_helper2 import OAuthProviders, OauthHelper2
from api_test_utils.apigee_api_apps import ApigeeApiDeveloperApps
from api_test_utils.apigee_api_products import ApigeeApiProducts
from api_test_utils.fixtures import webdriver_session
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


def create_logout_token(
    test_app: ApigeeApiDeveloperApps,
    override_claims: Optional[Dict[str, str]] = None,
    override_kid: Optional[str] = None,
    override_sid: Optional[str] = None,
) -> Dict[str, str]:
    """Creates logout token. To be replaced with Mock OIDC"""
    logout_token_claims = {
        "aud": "9999999999",
        "iss": "https://am.nhsdev.auth-ptl.cis2.spineservices.nhs.uk:443/openam/oauth2/realms/root/realms/oidc",
        "sub": "9999999999",
        "iat": int(time()) - 10,
        "jti": str(uuid4()),
        "events": {"http://schemas.openid.net/event/backchannel-logout": {}}
    }

    if override_claims is not None:
        logout_token_claims = override_claims

    logout_token_kid = override_kid if override_kid is not None else "Xie81yxqBz-7MBOyykWmf-W1UwpsV16DJnQpxs_zixQ"
    logout_token_headers = {
        "kid": logout_token_kid,
        "typ": "JWT",
        "alg": "RS512",
    }

    if override_sid:
        logout_token_claims['sid'] = override_sid

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
async def test_app(webdriver_session):
    """Programatically create and destroy test app for each test"""
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
            "jwks-resource-url": "https://internal-dev.api.service.nhs.uk/mock-nhsid-jwks/identity-service/nhs-cis2-jwks"
        }
    )

    apigee_app.oauth = OauthHelper2(apigee_app.client_id, apigee_app.client_secret, apigee_app.callback_url,
                                    webdriver_session=webdriver_session, identity_provider=OAuthProviders.MOCK)

    api_service_name = get_env("SERVICE_NAME")

    await apigee_product.update_scopes(
        [f"urn:nhsd:apim:user-nhs-login:P9:{api_service_name}"]
    )

    yield apigee_app

    await apigee_app.destroy_app()


@pytest.mark.asyncio
class TestBackChannelLogout:
    """ A test suite for back-channel logout functionality"""
    async def get_access_token(self, driver, get_token_body: Optional[bool] = False):

        code = await self.oauth.get_authenticated("aal3")
        print(code)

        token_resp = await self.oauth.hit_oauth_endpoint(
            method="POST",
            endpoint="token",
            data={
                'client_id': self.oauth.client_id,
                'client_secret': self.oauth.client_secret,
                'grant_type': "authorization_code",
                'redirect_uri': self.oauth.redirect_uri,
                'code': code
            }
        )
        token = token_resp["body"] if get_token_body else token_resp["body"]["access_token"]

        return token, token_resp["body"].get("sid", None)

    async def call_user_info(self, app, access_token):
        user_info_resp = await app.oauth.hit_oauth_endpoint(
            method="GET",
            endpoint="userinfo",
            headers={"Authorization": f"Bearer {access_token}"}
        )

        return user_info_resp

    @pytest.mark.asyncio
    @pytest.mark.happy_path
    async def test_backchannel_logout_happy_path(self, test_app):
        access_token, sid = await self.get_access_token(test_app)
        assert sid

        # Test token can be used to access identity service
        userinfo_resp = await self.call_user_info(test_app, access_token)
        assert userinfo_resp['status_code'] == 200

        # Mock back channel logout notification and test succesful logout response
        logout_token = create_logout_token(test_app, override_sid=sid)

        back_channel_resp = await test_app.oauth.hit_oauth_endpoint(
            method="POST",
            endpoint="backchannel_logout",
            data={"logout_token": logout_token}
        )
        assert back_channel_resp['status_code'] == 200

        # Revoking a token seems to be eventually consistent?
        await sleep(2)

        # Test access token has been revoked
        userinfo_resp = await self.call_user_info(test_app, access_token)
        assert userinfo_resp['status_code'] == 401
    
    @pytest.mark.asyncio
    @pytest.mark.happy_path
    @pytest.mark.apm_2573
    async def test_backchannel_logout_user_refresh_token(self, test_app, our_webdriver):
        token, sid = await self.get_access_token(our_webdriver, get_token_body=True)
        assert sid

        # Test token can be used to access identity service
        userinfo_resp = await self.call_user_info(test_app, token['access_token'])
        assert userinfo_resp['status_code'] == 200

        # refresh token
        refresh_token_resp = await self.oauth.get_token_response(grant_type="refresh_token", refresh_token=token['refresh_token'])

        refresh_userinfo_resp = await self.call_user_info(test_app, refresh_token_resp['body']['access_token'])
        assert refresh_userinfo_resp['status_code'] == 200
        
        # Mock back channel logout notification and test succesful logout response
        logout_token = create_logout_token(test_app, override_sid=sid)

        back_channel_resp = await test_app.oauth.hit_oauth_endpoint(
            method="POST",
            endpoint="backchannel_logout",
            data={"logout_token": logout_token}
        )
        assert back_channel_resp['status_code'] == 200

        # Revoking a token seems to be eventually consistent?
        await sleep(2)

        # Test access token has been revoked
        post_userinfo_resp = await self.call_user_info(test_app, token['access_token'])
        assert post_userinfo_resp['status_code'] == 401

        post_refresh_userinfo_resp = await self.call_user_info(test_app, refresh_token_resp['body']['access_token'])
        assert post_refresh_userinfo_resp['status_code'] == 401

    # Request sends a JWT has missing or invalid claims of the following problems, returns a 400
    @pytest.mark.asyncio
    @pytest.mark.parametrize("claims,status_code,error_message", [
        (  # invalid aud claim
            {
                "aud": "invalid_aud_claim",
                "iss": "https://am.nhsdev.auth-ptl.cis2.spineservices.nhs.uk:443/openam/oauth2/realms/root/realms/oidc",
                "sub": "9999999999",
                "iat": int(time()) - 10,
                "jti": str(uuid4()),
                "sid": "08a5019c-17e1-4977-8f42-65a12843ea02",
                "events": {"http://schemas.openid.net/event/backchannel-logout": {}}
            },
            400,
            "Missing/invalid aud claim in JWT"
        ),
        (  # missing aud claim
            {
                "iss": "https://am.nhsdev.auth-ptl.cis2.spineservices.nhs.uk:443/openam/oauth2/realms/root/realms/oidc",
                "sub": "9999999999",
                "iat": int(time()) - 10,
                "jti": str(uuid4()),
                "sid": "08a5019c-17e1-4977-8f42-65a12843ea02",
                "events": {"http://schemas.openid.net/event/backchannel-logout": {}}
            },
            400,
            "Missing/invalid aud claim in JWT"
        ),
        (  # invalid iss claim
            {
                "aud": "9999999999",
                "iss": "invalid_iss_claim",
                "sub": "9999999999",
                "iat": int(time()) - 10,
                "jti": str(uuid4()),
                "sid": "08a5019c-17e1-4977-8f42-65a12843ea02",
                "events": {"http://schemas.openid.net/event/backchannel-logout": {}}
            },
            400,
            "Missing/invalid iss claim in JWT"
        ),
        (  # missing iss claim
            {
                "aud": "9999999999",
                "sub": "9999999999",
                "iat": int(time()) - 10,
                "jti": str(uuid4()),
                "sid": "08a5019c-17e1-4977-8f42-65a12843ea02",
                "events": {"http://schemas.openid.net/event/backchannel-logout": {}}
            },
            400,
            "Missing/invalid iss claim in JWT"
        ),
        (  # missing sid claim
            {
                "aud": "9999999999",
                "iss": "https://am.nhsdev.auth-ptl.cis2.spineservices.nhs.uk:443/openam/oauth2/realms/root/realms/oidc",
                "sub": "9999999999",
                "iat": int(time()) - 10,
                "jti": str(uuid4()),
                "events": {"http://schemas.openid.net/event/backchannel-logout": {}}
            },
            400,
            "Missing sid claim in JWT"
        ),
        (  # invalid events claim
            {
                "aud": "9999999999",
                "iss": "https://am.nhsdev.auth-ptl.cis2.spineservices.nhs.uk:443/openam/oauth2/realms/root/realms/oidc",
                "sub": "9999999999",
                "iat": int(time()) - 10,
                "jti": str(uuid4()),
                "sid": "08a5019c-17e1-4977-8f42-65a12843ea02",
                "events": {"invalid_event_url": {}}
            },
            400,
            "Missing/invalid events claim in JWT"
        ),
        (  # missing events claim
            {
                "aud": "9999999999",
                "iss": "https://am.nhsdev.auth-ptl.cis2.spineservices.nhs.uk:443/openam/oauth2/realms/root/realms/oidc",
                "sub": "9999999999",
                "iat": int(time()) - 10,
                "jti": str(uuid4()),
                "sid": "08a5019c-17e1-4977-8f42-65a12843ea02"
            },
            400,
            "Missing/invalid events claim in JWT"
        ),
        (  # present nonce claim
            {
                "aud": "9999999999",
                "iss": "https://am.nhsdev.auth-ptl.cis2.spineservices.nhs.uk:443/openam/oauth2/realms/root/realms/oidc",
                "sub": "9999999999",
                "iat": int(time()) - 10,
                "jti": str(uuid4()),
                "sid": "08a5019c-17e1-4977-8f42-65a12843ea02",
                "events": {"http://schemas.openid.net/event/backchannel-logout": {}},
                "nonce": "valid_nonce"
            },
            400,
            "Prohibited nonce claim in JWT"
        )
    ])
    async def test_claims(self, test_app, claims, status_code, error_message, webdriver_session):
        access_token, _sid = await self.get_access_token(webdriver_session)

        # Test token can be used to access identity service
        userinfo_resp = await self.call_user_info(test_app, access_token)
        assert userinfo_resp['status_code'] == 200

        # Mock back channel logout notification with overridden claims
        logout_token = create_logout_token(test_app, override_claims=claims)

        # Submit logout token to back-channel logout endpoint
        back_channel_resp = await test_app.oauth.hit_oauth_endpoint(
            method="POST",
            endpoint="backchannel_logout",
            data={"logout_token": logout_token}
        )

        assert back_channel_resp["status_code"] == status_code
        assert back_channel_resp["body"]["error_description"] == error_message

    # Request sends JWT that cannot be verified returns a  400
    @pytest.mark.asyncio
    async def test_invalid_jwt(self, test_app, webdriver_session):
        access_token, _sid = await self.get_access_token(webdriver_session)

        # Test token can be used to access identity service
        userinfo_resp = await self.call_user_info(test_app, access_token)
        assert userinfo_resp['status_code'] == 200

        # Mock back channel logout notification and test with invalid kid
        logout_token = create_logout_token(test_app, override_kid="invalid_kid",
                                           override_sid="5b8f2499-ad4a-4a7c-b0ac-aaada65bda2b")

        back_channel_resp = await test_app.oauth.hit_oauth_endpoint(
            method="POST",
            endpoint="backchannel_logout",
            data={"logout_token": logout_token}
        )

        assert back_channel_resp["status_code"] == 400
        assert back_channel_resp["body"]["error_description"] == "Unable to verify JWT"

    # Requests sends an logout token that does not exist in the session-id cache returns a 501
    @pytest.mark.asyncio
    async def test_sid_not_cached(self, test_app):
        logout_token = create_logout_token(test_app, override_sid="5b8f2499-ad4a-4a7c-b0ac-aaada65bda2b")

        back_channel_resp = await test_app.oauth.hit_oauth_endpoint(
            method="POST",
            endpoint="backchannel_logout",
            data={"logout_token": logout_token}
        )

        assert back_channel_resp["status_code"] == 501

    # Requests sends an logout token that does not match the session-id cache returns a 501
    @pytest.mark.asyncio
    async def test_cached_sid_does_not_match(self, test_app):
        claims_non_matching_sid = {
            "aud": "9999999999",
            "iss": "https://am.nhsdev.auth-ptl.cis2.spineservices.nhs.uk:443/openam/oauth2/realms/root/realms/oidc",
            "sub": "9999999999",
            "iat": int(time()) - 10,
            "jti": str(uuid4()),
            "sid": "12a5019c-17e1-4977-8f42-65a12843ea02",
            "events": {"http://schemas.openid.net/event/backchannel-logout": {}}
        }

        # Mock back channel logout notification and test with different sid
        logout_token = create_logout_token(test_app, override_claims=claims_non_matching_sid)

        back_channel_resp = await test_app.oauth.hit_oauth_endpoint(
            method="POST",
            endpoint="backchannel_logout",
            data={"logout_token": logout_token}
        )

        assert back_channel_resp["status_code"] == 501
