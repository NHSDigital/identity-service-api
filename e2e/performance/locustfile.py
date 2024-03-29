import os
import json
import jwt  # pyjwt
from uuid import uuid4
from time import time
import urllib.parse as urlparse
from urllib.parse import parse_qs
from locust import HttpUser, task, between, tag


class IdentityServiceUser(HttpUser):
    """Configuration for performance testing identity service"""
    wait_time = between(2, 5)

    def on_start(self):
        self.base_url = os.environ["LOCUST_HOST"]
        self.identity_proxy = self._identity_proxy_name()
        self.client_id = os.environ["CLIENT_ID"]
        self.client_secret = os.environ["CLIENT_SECRET"]
        self.callback_url = os.environ["CALLBACK_URL"]
        self.jwt_app_key = os.environ["JWT_APP_KEY"]
        self.kid = os.environ["JWT_KID"]
        self.signing_key = os.environ["JWT_SIGNING_KEY"]

    def _identity_proxy_name(self):
        try:
            namespace = os.environ["NAMESPACE"]
            return f"oauth2-{namespace}"
        except KeyError:
            return "oauth2"

    @task
    @tag("user_restricted")
    def user_restricated_auth(self):
        state = self._get_state()
        redirect_uri = self._get_redirect_callback(state)
        auth_code = self._get_auth_code(redirect_uri)
        credentials = self._get_access_token(auth_code)
        self._refresh_token(credentials)

    def _get_state(self):
        params = {
            "client_id": self.client_id,
            "redirect_uri": self.callback_url,
            "response_type": "code",
            "state": "1234567890",
        }
        with self.client.get(
            f"/{self.identity_proxy}/authorize", params=params, catch_response=True
        ) as response:
            parsed = urlparse.urlparse(response.url)
            return parse_qs(parsed.query)["state"][0]

    def _get_redirect_callback(self, state):
        if state is None:
            return
        url = f"/{self.identity_proxy}/simulated_auth"
        params = {
            "response_type": "code",
            "client_id": "some-client-id",
            "redirect_uri": f"{self.base_url}/callback",
            "scope": "openid",
            "state": state,
        }
        headers = {
            "Accept": "*/*",
            "Accept-Encoding": "gzip,deflate",
            "Cache-Control": "no-cache",
            "Content-Type": "application/x-www-form-urlencoded",
        }
        payload = {"state": state}
        with self.client.post(
            url,
            params=params,
            data=payload,
            headers=headers,
            allow_redirects=False,
            catch_response=True,
        ) as response:
            redirect_uri = response.headers["Location"]
            redirect_uri = redirect_uri.replace("oauth2", self.identity_proxy)
            return redirect_uri

    def _get_auth_code(self, redirect_uri):
        if redirect_uri is None:
            return
        with self.client.get(
            redirect_uri, allow_redirects=False, catch_response=True
        ) as response:
            parsed = urlparse.urlparse(response.headers["Location"])
            return parse_qs(parsed.query)["code"][0]

    def _get_access_token(self, auth_code):
        if auth_code is None:
            return
        url = f"/{self.identity_proxy}/token"
        headers = {
            "Accept": "*/*",
            "connection": "keep-alive",
            "Content-Type": "application/x-www-form-urlencoded",
        }
        payload = {
            "grant_type": "authorization_code",
            "code": auth_code,
            "redirect_uri": self.callback_url,
            "client_id": self.client_id,
            "client_secret": self.client_secret,
        }
        with self.client.post(
            url, data=payload, headers=headers, catch_response=True
        ) as response:
            credentials = json.loads(response.text)
            return credentials

    def _refresh_token(self, credentials):
        if credentials is None:
            return
        headers = {"Content-Type": "application/x-www-form-urlencoded"}
        payload = {
            "grant_type": "refresh_token",
            "client_id": self.client_id,
            "client_secret": self.client_secret,
            "refresh_token": credentials["refresh_token"],
        }
        self.client.post(f"/{self.identity_proxy}/token", headers=headers, data=payload)

    @task
    @tag("app_restricted")
    def app_restricted_auth(self):
        jwt = self.create_jwt()

        form_data = {
            "client_assertion_type": "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
            "client_assertion": jwt,
            "grant_type": "client_credentials",
        }

        with self.client.post(
            f"/{self.identity_proxy}/token", data=form_data
        ) as response:
            print(response)

    def create_jwt(self):
        claims = {
            "sub": self.jwt_app_key,
            "iss": self.jwt_app_key,
            "jti": str(uuid4()),
            "aud": f"{self.base_url}/{self.identity_proxy}/token",
            "exp": int(time()) + 5,
        }

        headers = {"kid": self.kid}

        with open(self.signing_key, "r") as f:
            private_key = f.read()

        return jwt.encode(
            payload=claims, key=private_key, headers=headers, algorithm="RS512"
        )
