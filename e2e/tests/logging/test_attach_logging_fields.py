import pytest
import requests

from pytest_nhsd_apim.apigee_apis import (
    ApigeeNonProdCredentials,
    ApigeeClient,
    AccessTokensAPI
)
# from e2e.scripts.config import OAUTH_URL, CANARY_API_URL, ENVIRONMENT, ID_TOKEN_NHS_LOGIN_PRIVATE_KEY_ABSOLUTE_PATH, MOCK_IDP_BASE_URL


# Helpers
def get_token_details(token_data):
    token_attributes = {}
    for attribute in token_data["attributes"]:
        token_attributes[attribute["name"]] = attribute["value"]
    return token_attributes


# Fixtures
@pytest.fixture()
def access_token_api():
    """
    Authenitcated wrapper for Apigee's access token API
    """
    config = ApigeeNonProdCredentials()
    client = ApigeeClient(config=config)
    return AccessTokensAPI(client=client)


class TestAttachLoggingFields:
    @pytest.mark.happy_path
    @pytest.mark.logging
    @pytest.mark.parametrize(
        ("expected_token_attributes"),
        [
            # User-restricted CIS2 combined aal3
            pytest.param(
                {
                    "auth_type": "user",
                    "auth_grant_type": "authorization_code",
                    "auth_level": "aal3",
                    "auth_provider": "nhs-cis2",
                    "auth_user_id": "656005750104"
                },
                marks=pytest.mark.nhsd_apim_authorization(
                    access="healthcare_worker",
                    level="aal3",
                    login_form={"username": "656005750104"},
                    force_new_token=True
                ),
            ),
            # User-restricted NHS-login combined P0
            pytest.param(
                {
                    "auth_type": "user",
                    "auth_grant_type": "authorization_code",
                    "auth_level": "p0",
                    "auth_provider": "nhs-login",
                    "auth_user_id": "9912003073"
                },
                marks=pytest.mark.nhsd_apim_authorization(
                    access="patient",
                    level="P0",
                    login_form={"username": "9912003073"},
                    force_new_token=True
                ),
            ),
        ]
    )
    def test_access_token_fields_for_logging_cis2_combined(
        self,
        _nhsd_apim_auth_token_data,
        access_token_api,
        expected_token_attributes
    ):
        access_token = _nhsd_apim_auth_token_data["access_token"]
        token_data = access_token_api.get_token_details(access_token)
        token_attributes = get_token_details(token_data)

        for attribute, _ in expected_token_attributes.items():
            assert token_attributes[attribute] == expected_token_attributes[attribute]

#     @pytest.mark.simulated_auth
#     @pytest.mark.happy_path
#     @pytest.mark.logging
#     @pytest.mark.parametrize('scope', ['P9', 'P5', 'P0'])
#     async def test_access_token_fields_for_logging_when_using_authorization_code_nhs_login(self, scope, helper):
#         # Given
#         apigee_trace = ApigeeApiTraceDebug(proxy=f"canary-api-{ENVIRONMENT}")

#         # Make authorize request to retrieve state2
#         response = await self.oauth.hit_oauth_endpoint(
#             method="GET",
#             endpoint="authorize",
#             params={
#                 "client_id": self.oauth.client_id,
#                 "redirect_uri": self.oauth.redirect_uri,
#                 "response_type": "code",
#                 "state": "1234567890",
#                 "scope": "nhs-login"
#             },
#             allow_redirects=False,
#         )

#         state = helper.get_param_from_url(
#             url=response["headers"]["Location"], param="state"
#         )
#         # Make simulated auth request to authenticate
#         response = await self.oauth.hit_oauth_endpoint(
#             base_uri=MOCK_IDP_BASE_URL,
#             method="POST",
#             endpoint="nhs_login_simulated_auth",
#             params={
#                 "response_type": "code",
#                 "client_id": self.oauth.client_id,
#                 "redirect_uri": self.oauth.redirect_uri,
#                 "scope": "openid",
#                 "state": state,
#             },
#             headers={"Content-Type": "application/x-www-form-urlencoded"},
#             data={
#                 "state": state,
#                 "auth_method": scope
#             },
#             allow_redirects=False,
#         )

#         # Make initial callback request
#         auth_code = helper.get_param_from_url(
#             url=response["headers"]["Location"], param="code"
#         )

#         response = await self.oauth.hit_oauth_endpoint(
#             method="GET",
#             endpoint="callback",
#             params={"code": auth_code, "client_id": "some-client-id", "state": state},
#             allow_redirects=False,
#         )

#         auth_code = helper.get_param_from_url(
#             url=response["headers"]["Location"], param="code"
#         )

#         response = await self.oauth.hit_oauth_endpoint(
#             method="POST",
#             endpoint="token",
#             data={
#                 "grant_type": "authorization_code",
#                 "state": state,
#                 "code": auth_code,
#                 "redirect_uri": self.oauth.redirect_uri,
#                 "client_id": self.oauth.client_id,
#                 "client_secret": self.oauth.client_secret
#             },
#             allow_redirects=False,
#         )

#         access_token = response['body']['access_token']
#         # When
#         await apigee_trace.start_trace()
#         requests.get(f"{CANARY_API_URL}", headers={"Authorization": f"Bearer {access_token}"})

#         # Then
#         auth_type = await apigee_trace.get_apigee_variable_from_trace(name='accesstoken.auth_type')
#         auth_grant_type = await apigee_trace.get_apigee_variable_from_trace(name='accesstoken.auth_grant_type')
#         auth_level = await apigee_trace.get_apigee_variable_from_trace(name='accesstoken.auth_level')
#         auth_provider = await apigee_trace.get_apigee_variable_from_trace(name='accesstoken.auth_provider')
#         auth_user_id = await apigee_trace.get_apigee_variable_from_trace(name='accesstoken.auth_user_id')

#         assert auth_type == 'user'
#         assert auth_grant_type == 'authorization_code'
#         assert auth_level == scope.lower()
#         assert auth_provider == 'apim-mock-nhs-login'
#         assert auth_user_id == '9912003071'

#     @pytest.mark.happy_path
#     @pytest.mark.logging
#     async def test_access_token_fields_for_logging_when_using_client_credentials(self):
#         # Given
#         apigee_trace = ApigeeApiTraceDebug(proxy=f"canary-api-{ENVIRONMENT}")
#         jwt_claims = {
#             'kid': 'test-1',
#             'claims': {
#                 "sub": self.oauth.client_id,
#                 "iss": self.oauth.client_id,
#                 "jti": str(uuid4()),
#                 "aud": f"{OAUTH_URL}/token",
#                 "exp": int(time()) + 300,
#             }
#         }
#         jwt = self.oauth.create_jwt(**jwt_claims)
#         resp = await self.oauth.get_token_response(grant_type='client_credentials', _jwt=jwt)
#         access_token = resp['body']['access_token']

#         # When
#         await apigee_trace.start_trace()
#         requests.get(f"{CANARY_API_URL}", headers={"Authorization": f"Bearer {access_token}"})

#         # Then
#         auth_type = await apigee_trace.get_apigee_variable_from_trace(name='accesstoken.auth_type')
#         auth_grant_type = await apigee_trace.get_apigee_variable_from_trace(name='accesstoken.auth_grant_type')
#         auth_level = await apigee_trace.get_apigee_variable_from_trace(name='accesstoken.auth_level')
#         auth_provider = await apigee_trace.get_apigee_variable_from_trace(name='accesstoken.auth_provider')
#         auth_user_id = await apigee_trace.get_apigee_variable_from_trace(name='accesstoken.auth_user_id')

#         assert auth_type == 'app'
#         assert auth_grant_type == 'client_credentials'
#         assert auth_level == 'level3'
#         assert auth_provider == 'apim'
#         assert auth_user_id == ''

#     @pytest.mark.simulated_auth
#     @pytest.mark.happy_path
#     @pytest.mark.logging
#     async def test_access_token_fields_for_logging_when_using_token_exchange_cis2(self):
#         # Given
#         apigee_trace = ApigeeApiTraceDebug(proxy=f"canary-api-{ENVIRONMENT}")

#         id_token_jwt = self.oauth.create_id_token_jwt()
#         client_assertion_jwt = self.oauth.create_jwt(kid='test-1')
#         resp = await self.oauth.get_token_response(grant_type='token_exchange', _jwt=client_assertion_jwt,
#                                                    id_token_jwt=id_token_jwt)
#         access_token = resp['body']['access_token']

#         # When
#         await apigee_trace.start_trace()
#         requests.get(f"{CANARY_API_URL}", headers={"Authorization": f"Bearer {access_token}"})

#         # Then
#         auth_type = await apigee_trace.get_apigee_variable_from_trace(name='accesstoken.auth_type')
#         auth_grant_type = await apigee_trace.get_apigee_variable_from_trace(name='accesstoken.auth_grant_type')
#         auth_provider = await apigee_trace.get_apigee_variable_from_trace(name='accesstoken.auth_provider')
#         auth_level = await apigee_trace.get_apigee_variable_from_trace(name='accesstoken.auth_level')
#         auth_user_id = await apigee_trace.get_apigee_variable_from_trace(name='accesstoken.auth_user_id')

#         assert auth_type == 'user'
#         assert auth_grant_type == 'token_exchange'
#         assert auth_provider == 'nhs-cis2'
#         assert auth_level == 'aal3'
#         assert auth_user_id == '787807429511'

#     @pytest.mark.simulated_auth
#     @pytest.mark.happy_path
#     @pytest.mark.logging
#     @pytest.mark.parametrize('scope', ['P9', 'P5', 'P0'])
#     async def test_access_token_fields_for_logging_when_using_token_exchange_nhs_login(self, scope):
#         # Given
#         apigee_trace = ApigeeApiTraceDebug(proxy=f"canary-api-{ENVIRONMENT}")

#         id_token_claims = {
#             "aud": "tf_-APIM-1",
#             "id_status": "verified",
#             "token_use": "id",
#             "auth_time": 1616600683,
#             "iss": "https://internal-dev.api.service.nhs.uk",
#             "vot": "P9.Cp.Cd",
#             "exp": int(time()) + 600,
#             "iat": int(time()) - 10,
#             "vtm": "https://auth.sandpit.signin.nhs.uk/trustmark/auth.sandpit.signin.nhs.uk",
#             "jti": str(uuid4()),
#             "identity_proofing_level": scope,
#             "nhs_number": "900000000001"
#         }
#         id_token_headers = {
#             "sub": "49f470a1-cc52-49b7-beba-0f9cec937c46",
#             "aud": "APIM-1",
#             "kid": "nhs-login",
#             "iss": "https://internal-dev.api.service.nhs.uk",
#             "typ": "JWT",
#             "exp": 1616604574,
#             "iat": 1616600974,
#             "alg": "RS512",
#             "jti": str(uuid4()),
#         }

#         with open(ID_TOKEN_NHS_LOGIN_PRIVATE_KEY_ABSOLUTE_PATH, "r") as f:
#             contents = f.read()

#         client_assertion_jwt = self.oauth.create_jwt(kid="test-1")
#         id_token_jwt = self.oauth.create_id_token_jwt(
#             algorithm="RS512",
#             claims=id_token_claims,
#             headers=id_token_headers,
#             signing_key=contents,
#         )
#         resp = await self.oauth.get_token_response(
#             grant_type="token_exchange",
#             _jwt=client_assertion_jwt,
#             id_token_jwt=id_token_jwt,
#         )
#         access_token = resp['body']['access_token']

#         # When
#         await apigee_trace.start_trace()
#         requests.get(f"{CANARY_API_URL}", headers={"Authorization": f"Bearer {access_token}"})

#         # Then
#         auth_type = await apigee_trace.get_apigee_variable_from_trace(name='accesstoken.auth_type')
#         auth_grant_type = await apigee_trace.get_apigee_variable_from_trace(name='accesstoken.auth_grant_type')
#         auth_provider = await apigee_trace.get_apigee_variable_from_trace(name='accesstoken.auth_provider')
#         auth_level = await apigee_trace.get_apigee_variable_from_trace(name='accesstoken.auth_level')
#         auth_user_id = await apigee_trace.get_apigee_variable_from_trace(name='accesstoken.auth_user_id')

#         assert auth_type == 'user'
#         assert auth_grant_type == 'token_exchange'
#         assert auth_provider == 'apim-mock-nhs-login'
#         assert auth_level == scope.lower()
#         assert auth_user_id == '900000000001'
