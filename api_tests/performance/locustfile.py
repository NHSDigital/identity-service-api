import os
import json
import urllib.parse as urlparse
from urllib.parse import parse_qs
from locust import HttpUser, TaskSet, task, between

class IdentityServiceUser(HttpUser):
    wait_time = between(2, 5)

    def on_start(self):
        self.base_url = os.environ["LOCUST_HOST"]
        self.client_id = os.environ["CLIENT_ID"]
        self.client_secret = os.environ["CLIENT_SECRET"]
        self.callback_url = os.environ["CALLBACK_URL"]
    
    @task
    def authenticate(self):
        state = self.get_state()
        redirect_uri = self.get_redirect_callback(state)
        auth_code = self.get_auth_code(redirect_uri)
        self.get_access_token(auth_code)

    def get_state(self):
        with self.client.get(f"/oauth2/authorize?client_id={self.client_id}&redirect_uri={self.callback_url}&response_type=code&state=1234567890") as response:
            parsed = urlparse.urlparse(response.url)
            return parse_qs(parsed.query)['state'][0]

    def get_redirect_callback(self, state):
        url = f"/oauth2/simulated_auth?response_type=code&client_id=some-client-id&redirect_uri={self.base_url}/callback&scope=openid&state={state}"
        headers = {
            "Accept": "*/*",
            "Accept-Encoding": "gzip,deflate",
            "Cache-Control": "no-cache",
            "Content-Type": "application/x-www-form-urlencoded"
        }
        payload = {
            "state": state
        }
        with self.client.post(url, data=payload, headers=headers, allow_redirects=False) as response:
            redirect_uri = response.headers['Location']
            return redirect_uri

    def get_auth_code(self, redirect_uri):
        with self.client.get(redirect_uri, allow_redirects=False) as response:
            parsed = urlparse.urlparse(response.headers['Location'])
            return parse_qs(parsed.query)["code"][0]
    
    def get_access_token(self, auth_code):
        url = "/oauth2/token"
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
            "client_secret": self.client_secret
        }
        with self.client.post(url, data=payload, headers=headers) as response:
            credentials = json.loads(response.text)