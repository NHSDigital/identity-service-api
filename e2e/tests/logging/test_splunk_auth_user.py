import base64
import hashlib
import hmac
import pytest
import requests
from api_test_utils.apigee_api_trace import ApigeeApiTraceDebug
from api_test_utils.oauth_helper import OauthHelper
from urllib.parse import urlparse, urlencode, parse_qsl
from uuid import uuid4

from e2e.scripts.config import OAUTH_URL, SERVICE_NAME, ACCESS_TOKEN_SECRET


class Authentication:
    def __init__(self, auth_base_url: str, client_id: str, client_secret: str, redirect_uri: str, simulated_auth_url):
        self.__auth_base_url = auth_base_url
        self.__client_id = client_id
        self.__client_secret = client_secret
        self.__redirect_uri = redirect_uri
        self.__simulated_auth_url = simulated_auth_url

    def authorization_code_cis2(self):
        # Authorize
        uri = self.__create_authorize_url(response_type="code", state=uuid4())
        res = requests.get(uri, allow_redirects=False)
        parsed_location_url = urlparse(res.headers['Location'])
        queries = dict(parse_qsl(parsed_location_url.query))
        queries['redirect_uri'] = f"{self.__auth_base_url}/callback"
        state = queries['state']
        client_id = queries["client_id"]
        url = f"{self.__simulated_auth_url}/simulated_auth?{urlencode(queries)}"
        requests.get(url)

        queries = {"redirect_uri": self.__redirect_uri, "state": state, "client_id": self.__client_id,
                   "scope": "openid", "response_type": "code"}
        url = f"{self.__simulated_auth_url}/simulated_auth?{urlencode(queries)}"
        res = requests.post(url, data={"state": state}, allow_redirects=False)
        redirect_uri = self.__change_pr_redirect(res.headers["Location"], "callback")
        res = requests.get(redirect_uri, allow_redirects=False)
        parsed = urlparse(res.headers["Location"])
        code = dict(parse_qsl(parsed.query))["code"]

        data = {
            "client_id": self.__client_id,
            "client_secret": self.__client_secret,
            "grant_type": "authorization_code",
            "redirect_uri": self.__redirect_uri,
            "code": code,
            "access_token_expiry_ms": 5000
        }
        res = requests.post(f"{self.__auth_base_url}/token", data=data)

        print(res.status_code)
        print(res.json())

    def __create_authorize_url(self, response_type, state):
        return f"{self.__auth_base_url}/authorize?" \
               f"response_type={response_type}&" \
               f"client_id={self.__client_id}" \
               f"&redirect_uri={self.__redirect_uri}" \
               f"&state={state}"

    def __create_callback_url(self, queries):
        queries['redirect_uri'] = f"{self.__auth_base_url}/callback"
        return f"{self.__auth_base_url}/callback?{urlencode(queries)}"

    def __change_pr_redirect(self, location, path):
        parsed_location_url = urlparse(location)
        queries = dict(parse_qsl(parsed_location_url.query))
        return f"{self.__auth_base_url}/{path}?{urlencode(queries)}"


def auth():
    auth = Authentication(auth_base_url="https://internal-dev.api.service.nhs.uk/oauth2-pr-233",
                          client_id="Too5BdPayTQACdw1AJK1rD4nKUD0Ag7J",
                          client_secret="wi7sCuFSgQg34ZWO",
                          redirect_uri="https://nhsd-apim-testing-internal-dev.herokuapp.com/callback",
                          simulated_auth_url="https://internal-dev.api.service.nhs.uk/mock-nhsid-jwks")

    auth.authorization_code_cis2()


def calculate_hmac_sha512(content: str, key: str) -> str:
    binary_content = bytes(content, 'utf-8')
    hmac_key = bytes(key, 'utf-8')
    signature = hmac.new(hmac_key, binary_content, hashlib.sha512)

    return base64.b64encode(signature.digest())


@pytest.mark.asyncio
class TestSplunkUserAuthLogging:
    @pytest.mark.happy_path
    @pytest.mark.logging
    @pytest.mark.debug2
    async def test_populate_hashed_access_token_using_auth_code_cis2(self, test_app_and_product, helper):
        # Given
        p1, p2, test_app = test_app_and_product
        await p1.update_scopes(['urn:nhsd:apim:user-nhs-id:aal3:personal-demographics-service'])
        await p2.update_scopes([])

        callback_url = await test_app.get_callback_url()
        oauth = OauthHelper(test_app.client_id, test_app.client_secret, callback_url)

        apigee_trace = ApigeeApiTraceDebug(proxy=SERVICE_NAME)

        # When
        await apigee_trace.start_trace()
        res = helper.send_request(
            verb="POST",
            endpoint=f"{OAUTH_URL}/token",
            data={
                "client_id": test_app.get_client_id(),
                "client_secret": test_app.get_client_secret(),
                "redirect_uri": callback_url,
                "grant_type": "authorization_code",
                "code": await oauth.get_authenticated_with_simulated_auth(),
            },
        )
        access_token = res.json()["access_token"]

        # Then
        expected_access_token_hashed = calculate_hmac_sha512(access_token, ACCESS_TOKEN_SECRET).decode('utf-8')
        actual_access_token_hashed = await apigee_trace.get_apigee_variable_from_trace(name='auth.access_token_hash')
        assert expected_access_token_hashed == actual_access_token_hashed
