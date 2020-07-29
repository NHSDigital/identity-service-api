import os
from locust import HttpUser, TaskSet, task, between

class IdentityServiceUser(HttpUser):
    wait_time = between(2, 5)

    def on_start(self):
        self.identity_proxy = self._identity_proxy_name()
        self.client_id = os.environ["CLIENT_ID"]
        self.callback_url = os.environ["CALLBACK_URL"]

    def _identity_proxy_name(self):
        try: 
            namespace = os.environ["NAMESPACE"]
            return f"oauth2-{namespace}"
        except:
            return "oauth2"

    @task
    def authorize_endpoint(self):
        self.client.get(f"/{self.identity_proxy}/authorize?client_id={self.client_id}&redirect_uri={self.callback_url}&response_type=code&state=1234567890")