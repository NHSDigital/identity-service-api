import pytest
import requests
import jwt

from time import time, sleep
from typing import Dict, Optional
from uuid import uuid4

from e2e.tests.utils.config import JWT_PRIVATE_KEY_ABSOLUTE_PATH


class TestBackChannelLogout:
    """A test suite for back-channel logout functionality """

    def create_logout_token(
        self,
        override_claims: Optional[Dict[str, str]] = None,
        override_kid: Optional[str] = None,
        override_sid: Optional[str] = None,
    ) -> Dict[str, str]:
        """Creates logout token. To be replaced with Mock OIDC"""
        logout_token_claims = {
            "aud": "test-client-cis2",
            "iss": "https://identity.ptl.api.platform.nhs.uk/realms/Cis2-mock-internal-dev",
            "sub": "9999999999",
            "iat": int(time()) - 10,
            "jti": str(uuid4()),
            "events": {"http://schemas.openid.net/event/backchannel-logout": {}},
        }

        if override_claims is not None:
            logout_token_claims = override_claims

        logout_token_kid = (
            override_kid
            if override_kid is not None
            else "4A72Ed2asGJ0mdjHNTgo8HQJac7kIAKBTsb_sM1ikn8"
        )
        logout_token_headers = {
            "kid": logout_token_kid,
            "typ": "JWT",
            "alg": "RS512",
        }

        if override_sid:
            logout_token_claims["sid"] = override_sid

        id_token_private_key_path = JWT_PRIVATE_KEY_ABSOLUTE_PATH

        with open(id_token_private_key_path, "r") as f:
            contents = f.read()

        logout_token_jwt = jwt.encode(
            logout_token_claims,
            contents,
            algorithm="RS512",
            headers=logout_token_headers,
        )

        return logout_token_jwt

    @pytest.mark.happy_path
    @pytest.mark.nhsd_apim_authorization(
        access="healthcare_worker",
        level="aal3",
        login_form={"username": "656005750104"},
        force_new_token=True,
    )
    def test_backchannel_logout_happy_path(
        self, _nhsd_apim_auth_token_data, nhsd_apim_proxy_url
    ):
        access_token = _nhsd_apim_auth_token_data["access_token"]
        sid = _nhsd_apim_auth_token_data["sid"]
        assert sid

        # Test token can be used to access identity service
        userinfo_resp = requests.get(
            nhsd_apim_proxy_url + "/userinfo",
            headers={"Authorization": f"Bearer {access_token}"},
        )
        assert userinfo_resp.status_code == 200

        # Mock back channel logout notification and test succesful logout response
        logout_token = self.create_logout_token(override_sid=sid)

        back_channel_resp = requests.post(
            nhsd_apim_proxy_url + "/backchannel_logout",
            data={"logout_token": logout_token},
        )
        assert back_channel_resp.status_code == 200

        # Revoking a token seems to be eventually consistent?
        sleep(2)

        # Test access token has been revoked
        userinfo_resp = requests.get(
            nhsd_apim_proxy_url + "/userinfo",
            headers={"Authorization": f"Bearer {access_token}"},
        )
        assert userinfo_resp.status_code == 401

    @pytest.mark.happy_path
    @pytest.mark.nhsd_apim_authorization(
        access="healthcare_worker",
        level="aal3",
        login_form={"username": "656005750104"},
        force_new_token=True,
    )
    def test_backchannel_logout_user_refresh_token(
        self, _nhsd_apim_auth_token_data, nhsd_apim_proxy_url, _test_app_credentials
    ):
        access_token = _nhsd_apim_auth_token_data["access_token"]
        sid = _nhsd_apim_auth_token_data["sid"]
        assert sid

        # Test token can be used to access identity service
        userinfo_resp = requests.get(
            nhsd_apim_proxy_url + "/userinfo",
            headers={"Authorization": f"Bearer {access_token}"},
        )
        assert userinfo_resp.status_code == 200

        # refresh token
        refresh_token_resp = requests.post(
            nhsd_apim_proxy_url + "/token",
            data={
                "client_id": _test_app_credentials["consumerKey"],
                "client_secret": _test_app_credentials["consumerSecret"],
                "refresh_token": _nhsd_apim_auth_token_data["refresh_token"],
                "grant_type": "refresh_token",
            },
        )
        refreshed_access_token = refresh_token_resp.json()["access_token"]

        refresh_userinfo_resp = requests.get(
            nhsd_apim_proxy_url + "/userinfo",
            headers={"Authorization": f"Bearer {refreshed_access_token}"},
        )
        assert refresh_userinfo_resp.status_code == 200

        # Mock back channel logout notification and test succesful logout response
        logout_token = self.create_logout_token(override_sid=sid)

        back_channel_resp = requests.post(
            nhsd_apim_proxy_url + "/backchannel_logout",
            data={"logout_token": logout_token},
        )
        assert back_channel_resp.status_code == 200

        # Revoking a token seems to be eventually consistent?
        sleep(2)

        # Test access token has been revoked
        post_userinfo_resp = requests.get(
            nhsd_apim_proxy_url + "/userinfo",
            headers={"Authorization": f"Bearer {access_token}"},
        )
        assert post_userinfo_resp.status_code == 401

        post_refresh_userinfo_resp = requests.get(
            nhsd_apim_proxy_url + "/userinfo",
            headers={"Authorization": f"Bearer {refreshed_access_token}"},
        )
        assert post_refresh_userinfo_resp.status_code == 401

    # Request sends a JWT has missing or invalid claims of the following problems, returns a 400
    @pytest.mark.nhsd_apim_authorization(
        access="healthcare_worker",
        level="aal3",
        login_form={"username": "656005750104"},
        force_new_token=True,
    )
    @pytest.mark.parametrize(
        "claims,status_code,error_message",
        [
            (  # invalid aud claim
                {
                    "aud": "invalid_aud_claim",
                    "iss": "https://identity.ptl.api.platform.nhs.uk/realms/Cis2-mock-internal-dev",
                    "sub": "9999999999",
                    "iat": int(time()) - 10,
                    "jti": str(uuid4()),
                    "sid": "08a5019c-17e1-4977-8f42-65a12843ea02",
                    "events": {
                        "http://schemas.openid.net/event/backchannel-logout": {}
                    },
                },
                400,
                "Missing/invalid aud claim in JWT",
            ),
            (  # missing aud claim
                {
                    "iss": "https://identity.ptl.api.platform.nhs.uk/realms/Cis2-mock-internal-dev",
                    "sub": "9999999999",
                    "iat": int(time()) - 10,
                    "jti": str(uuid4()),
                    "sid": "08a5019c-17e1-4977-8f42-65a12843ea02",
                    "events": {
                        "http://schemas.openid.net/event/backchannel-logout": {}
                    },
                },
                400,
                "Missing/invalid aud claim in JWT",
            ),
            (  # invalid iss claim
                {
                    "aud": "test-client-cis2",
                    "iss": "invalid_iss_claim",
                    "sub": "9999999999",
                    "iat": int(time()) - 10,
                    "jti": str(uuid4()),
                    "sid": "08a5019c-17e1-4977-8f42-65a12843ea02",
                    "events": {
                        "http://schemas.openid.net/event/backchannel-logout": {}
                    },
                },
                400,
                "Missing/invalid iss claim in JWT",
            ),
            (  # missing iss claim
                {
                    "aud": "test-client-cis2",
                    "sub": "9999999999",
                    "iat": int(time()) - 10,
                    "jti": str(uuid4()),
                    "sid": "08a5019c-17e1-4977-8f42-65a12843ea02",
                    "events": {
                        "http://schemas.openid.net/event/backchannel-logout": {}
                    },
                },
                400,
                "Missing/invalid iss claim in JWT",
            ),
            (  # missing sid claim
                {
                    "aud": "test-client-cis2",
                    "iss": "https://identity.ptl.api.platform.nhs.uk/realms/Cis2-mock-internal-dev",
                    "sub": "9999999999",
                    "iat": int(time()) - 10,
                    "jti": str(uuid4()),
                    "events": {
                        "http://schemas.openid.net/event/backchannel-logout": {}
                    },
                },
                400,
                "Missing sid claim in JWT",
            ),
            (  # invalid events claim
                {
                    "aud": "test-client-cis2",
                    "iss": "https://identity.ptl.api.platform.nhs.uk/realms/Cis2-mock-internal-dev",
                    "sub": "9999999999",
                    "iat": int(time()) - 10,
                    "jti": str(uuid4()),
                    "sid": "08a5019c-17e1-4977-8f42-65a12843ea02",
                    "events": {"invalid_event_url": {}},
                },
                400,
                "Missing/invalid events claim in JWT",
            ),
            (  # missing events claim
                {
                    "aud": "test-client-cis2",
                    "iss": "https://identity.ptl.api.platform.nhs.uk/realms/Cis2-mock-internal-dev",
                    "sub": "9999999999",
                    "iat": int(time()) - 10,
                    "jti": str(uuid4()),
                    "sid": "08a5019c-17e1-4977-8f42-65a12843ea02",
                },
                400,
                "Missing/invalid events claim in JWT",
            ),
            (  # present nonce claim
                {
                    "aud": "test-client-cis2",
                    "iss": "https://identity.ptl.api.platform.nhs.uk/realms/Cis2-mock-internal-dev",
                    "sub": "9999999999",
                    "iat": int(time()) - 10,
                    "jti": str(uuid4()),
                    "sid": "08a5019c-17e1-4977-8f42-65a12843ea02",
                    "events": {
                        "http://schemas.openid.net/event/backchannel-logout": {}
                    },
                    "nonce": "valid_nonce",
                },
                400,
                "Prohibited nonce claim in JWT",
            ),
        ],
    )
    def test_claims(
        self,
        _nhsd_apim_auth_token_data,
        nhsd_apim_proxy_url,
        claims,
        status_code,
        error_message,
    ):
        access_token = _nhsd_apim_auth_token_data["access_token"]

        # Test token can be used to access identity service
        userinfo_resp = requests.get(
            nhsd_apim_proxy_url + "/userinfo",
            headers={"Authorization": f"Bearer {access_token}"},
        )
        assert userinfo_resp.status_code == 200

        # Mock back channel logout notification with overridden claims
        logout_token = self.create_logout_token(override_claims=claims)

        # Submit logout token to back-channel logout endpoint
        back_channel_resp = requests.post(
            nhsd_apim_proxy_url + "/backchannel_logout",
            data={"logout_token": logout_token},
        )

        assert back_channel_resp.status_code == status_code
        assert back_channel_resp.json()["error_description"] == error_message

    # Request sends JWT that cannot be verified returns a  400
    @pytest.mark.nhsd_apim_authorization(
        access="healthcare_worker",
        level="aal3",
        login_form={"username": "656005750104"},
        force_new_token=True,
    )
    def test_invalid_jwt(self, _nhsd_apim_auth_token_data, nhsd_apim_proxy_url):
        access_token = _nhsd_apim_auth_token_data["access_token"]

        # Test token can be used to access identity service
        userinfo_resp = requests.get(
            nhsd_apim_proxy_url + "/userinfo",
            headers={"Authorization": f"Bearer {access_token}"},
        )
        assert userinfo_resp.status_code == 200

        # Mock back channel logout notification and test with invalid kid
        logout_token = self.create_logout_token(
            override_kid="invalid_kid",
            override_sid="5b8f2499-ad4a-4a7c-b0ac-aaada65bda2b",
        )

        back_channel_resp = requests.post(
            nhsd_apim_proxy_url + "/backchannel_logout",
            data={"logout_token": logout_token},
        )

        assert back_channel_resp.status_code == 400
        assert back_channel_resp.json()["error_description"] == "Unable to verify JWT"

    # Requests sends an logout token that does not exist in the session-id cache returns a 501
    @pytest.mark.parametrize(
        "sid",
        [
            "5b8f2499-ad4a-4a7c-b0ac-aaada65bda2b",
            "12a5019c-17e1-4977-8f42-65a12843ea02",
        ],
    )
    def test_sid_not_cached(self, nhsd_apim_proxy_url, sid):
        logout_token = self.create_logout_token(override_sid=sid)

        back_channel_resp = requests.post(
            nhsd_apim_proxy_url + "/backchannel_logout",
            data={"logout_token": logout_token},
        )

        assert back_channel_resp.status_code == 501
