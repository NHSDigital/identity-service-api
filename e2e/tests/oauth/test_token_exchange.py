from e2e.scripts.config import (
    ID_TOKEN_NHS_LOGIN_PRIVATE_KEY_ABSOLUTE_PATH,
    CANARY_API_URL
)
import pytest
from uuid import uuid4
from time import time, sleep
import requests
import sys
import jwt
from e2e.scripts import config


@pytest.fixture
@pytest.mark.nhsd_apim_authorization(
    {
        "access": "healthcare_worker",
        "level": "aal3",
        "login_form": {"username": "aal3"},
        "authentication": "separate",
    }
)
def claims(_test_app_credentials, nhsd_apim_proxy_url):
    claims = {
        "sub": _test_app_credentials["consumerKey"],
        "iss": _test_app_credentials["consumerKey"],
        "jti": str(uuid4()),
        "aud": nhsd_apim_proxy_url + "/token",
        "exp": int(time()) + 300,  # 5 minutes in the future
    }
    return claims


@pytest.fixture
def cis_2_claims():
    cis2_claims = {
        "at_hash": "tf_-lqpq36lwO7WmSBIJ6Q",
        "sub": "787807429511",
        "auditTrackingId": "91f694e6-3749-42fd-90b0-c3134b0d98f6-1546391",
        "amr": ["N3_SMARTCARD"],
        "iss": "https://am.nhsint.auth-ptl.cis2.spineservices.nhs.uk:443/openam/oauth2/realms/root/realms"
               "/NHSIdentity/realms/Healthcare",
        "tokenName": "id_token",
        "aud": "969567331415.apps.national",
        "c_hash": "bc7zzGkClC3MEiFQ3YhPKg",
        "acr": "AAL3_ANY",
        "org.forgerock.openidconnect.ops": "-I45NjmMDdMa-aNF2sr9hC7qEGQ",
        "s_hash": "LPJNul-wow4m6Dsqxbning",
        "azp": "969567331415.apps.national",
        "auth_time": 1610559802,
        "realm": "/NHSIdentity/Healthcare",
        "exp": int(time()) + 300,
        "tokenType": "JWTToken",
        "iat": int(time()) - 100}
    return cis2_claims


@pytest.fixture
@pytest.mark.nhsd_apim_authorization({"access": "patient",
                                      "level": "P0",
                                      "login_form": {"auth_method": "P0"},
                                      "authentication": "separate"})
def claims_nhsd_login(_test_app_credentials, nhsd_apim_proxy_url):
    claims = {
        "sub": _test_app_credentials["consumerKey"],
        "iss": _test_app_credentials["consumerKey"],
        "jti": str(uuid4()),
        "aud": nhsd_apim_proxy_url + "/token",
        "exp": int(time()) + 300,  # 5 minutes in the future
    }
    return claims


@pytest.mark.asyncio
class TestTokenExchange:
    """ A test suit to test the token exchange flow """

    # ############# JWT ###############
    @pytest.mark.simulated_auth
    @pytest.mark.token_exchange
    @pytest.mark.nhsd_apim_authorization(
        {
            "access": "healthcare_worker",
            "level": "aal3",
            "login_form": {"username": "aal3"},
            "authentication": "separate",
        }
    )
    def test_healthcare_work_user_token_exchange_happy_path(self, nhsd_apim_proxy_url, _nhsd_apim_auth_token_data):
        assert "access_token" in _nhsd_apim_auth_token_data.keys()
        assert "issued_at" in _nhsd_apim_auth_token_data.keys()
        assert _nhsd_apim_auth_token_data["expires_in"] == "599"
        assert _nhsd_apim_auth_token_data["token_type"] == "Bearer"

    @pytest.mark.errors
    @pytest.mark.token_exchange
    async def test_token_exchange_invalid_client_assertion_type(self, claims, _jwt_keys, nhsd_apim_proxy_url,
                                                                cis_2_claims):
        # Given
        expected_status_code = 400
        expected_error = 'invalid_request'
        expected_error_description = "Missing or invalid client_assertion_type - " \
                                     "must be 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer"

        with open(config.ID_TOKEN_PRIVATE_KEY_ABSOLUTE_PATH, "r") as f:
            id_token_private_key = f.read()

        additional_headers = {"kid": "test-1"}
        client_assertion = jwt.encode(claims, _jwt_keys["private_key_pem"],
                                      algorithm="RS512",
                                      headers=additional_headers)

        kid = "identity-service-tests-1"
        headers = ({}, {"kid": kid})[kid is not None]
        id_token_jwt = jwt.encode(cis_2_claims, id_token_private_key, algorithm="RS512", headers=headers)

        # When
        response = requests.post(
            nhsd_apim_proxy_url + "/token",
            data={"subject_token_type": "urn:ietf:params:oauth:token-type:id_token",
                  "client_assertion_type": "jwt-bearer",
                  "subject_token": id_token_jwt,
                  "client_assertion": client_assertion,
                  "grant_type": "urn:ietf:params:oauth:grant-type:token-exchange"})
        resp = response.json()

        # Then
        assert expected_status_code == response.status_code
        assert expected_error == resp['error']
        assert expected_error_description == resp['error_description']

    @pytest.mark.errors
    @pytest.mark.token_exchange
    async def test_token_exchange_invalid_subject_token_type(self, claims, _jwt_keys, nhsd_apim_proxy_url,
                                                             cis_2_claims):
        # Given
        expected_status_code = 400
        expected_error = 'invalid_request'
        expected_error_description = "missing or invalid subject_token_type - " \
                                     "must be 'urn:ietf:params:oauth:token-type:id_token'"

        with open(config.ID_TOKEN_PRIVATE_KEY_ABSOLUTE_PATH, "r") as f:
            id_token_private_key = f.read()

        additional_headers = {"kid": "test-1"}
        client_assertion = jwt.encode(claims, _jwt_keys["private_key_pem"],
                                      algorithm="RS512",
                                      headers=additional_headers)

        kid = "identity-service-tests-1"
        headers = ({}, {"kid": kid})[kid is not None]
        id_token_jwt = jwt.encode(cis_2_claims, id_token_private_key, algorithm="RS512", headers=headers)

        # When
        response = requests.post(
            nhsd_apim_proxy_url + "/token",
            data={"subject_token_type": "id_token",
                  "client_assertion_type": "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
                  "subject_token": id_token_jwt,
                  "client_assertion": client_assertion,
                  "grant_type": "urn:ietf:params:oauth:grant-type:token-exchange"})
        resp = response.json()

        # Then
        assert expected_status_code == response.status_code
        assert expected_error == resp['error']
        assert expected_error_description == resp['error_description']

    @pytest.mark.errors
    @pytest.mark.token_exchange
    async def test_token_exchange_claims_assertion_invalid_kid(self, claims, _jwt_keys, nhsd_apim_proxy_url,
                                                               cis_2_claims):
        # Given
        expected_status_code = 400
        expected_error = 'invalid_request'
        expected_error_description = "Missing 'kid' header in JWT"

        with open(config.ID_TOKEN_PRIVATE_KEY_ABSOLUTE_PATH, "r") as f:
            id_token_private_key = f.read()

        additional_headers = {"kid": ''}
        client_assertion = jwt.encode(claims, _jwt_keys["private_key_pem"],
                                      algorithm="RS512",
                                      headers=additional_headers)

        kid = "identity-service-tests-1"
        headers = ({}, {"kid": kid})[kid is not None]
        id_token_jwt = jwt.encode(cis_2_claims, id_token_private_key, algorithm="RS512", headers=headers)

        # When
        response = requests.post(
            nhsd_apim_proxy_url + "/token",
            data={"subject_token_type": "urn:ietf:params:oauth:token-type:id_token",
                  "client_assertion_type": "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
                  "subject_token": id_token_jwt,
                  "client_assertion": client_assertion,
                  "grant_type": "urn:ietf:params:oauth:grant-type:token-exchange"})
        resp = response.json()

        # Then
        assert expected_status_code == response.status_code
        assert expected_error == resp['error']
        assert expected_error_description == resp['error_description']

    @pytest.mark.errors
    @pytest.mark.token_exchange
    async def test_token_exchange_claims_assertion_invalid_typ_header(self, claims, _jwt_keys, nhsd_apim_proxy_url,
                                                                      cis_2_claims):
        # Given
        expected_status_code = 400
        expected_error = 'invalid_request'
        expected_error_description = "Invalid 'typ' header in JWT - must be 'JWT'"

        with open(config.ID_TOKEN_PRIVATE_KEY_ABSOLUTE_PATH, "r") as f:
            id_token_private_key = f.read()

        additional_headers = {'kid': 'test-1', 'typ': 'invalid'}
        client_assertion = jwt.encode(claims, _jwt_keys["private_key_pem"],
                                      algorithm="RS512",
                                      headers=additional_headers)

        kid = "identity-service-tests-1"
        headers = ({}, {"kid": kid})[kid is not None]
        id_token_jwt = jwt.encode(cis_2_claims, id_token_private_key, algorithm="RS512", headers=headers)

        # When
        response = requests.post(
            nhsd_apim_proxy_url + "/token",
            data={"subject_token_type": "urn:ietf:params:oauth:token-type:id_token",
                  "client_assertion_type": "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
                  "subject_token": id_token_jwt,
                  "client_assertion": client_assertion,
                  "grant_type": "urn:ietf:params:oauth:grant-type:token-exchange"})
        resp = response.json()

        # Then
        assert expected_status_code == response.status_code
        assert expected_error == resp['error']
        assert expected_error_description == resp['error_description']

    @pytest.mark.errors
    @pytest.mark.token_exchange
    async def test_token_exchange_claims_assertion_invalid_iss_claim(self, _jwt_keys, nhsd_apim_proxy_url,
                                                                     cis_2_claims):
        # Given
        expected_status_code = 400
        expected_error = 'invalid_request'
        expected_error_description = "Missing or non-matching iss/sub claims in JWT"

        claims = {"sub": '',
                  "jti": str(uuid4()),
                  "aud": f"{nhsd_apim_proxy_url}/token",
                  "exp": int(time()) + 5}

        with open(config.ID_TOKEN_PRIVATE_KEY_ABSOLUTE_PATH, "r") as f:
            id_token_private_key = f.read()

        additional_headers = {'kid': 'test-1'}
        client_assertion = jwt.encode(claims, _jwt_keys["private_key_pem"],
                                      algorithm="RS512",
                                      headers=additional_headers)

        kid = "identity-service-tests-1"
        headers = ({}, {"kid": kid})[kid is not None]
        id_token_jwt = jwt.encode(cis_2_claims, id_token_private_key, algorithm="RS512", headers=headers)

        # When
        response = requests.post(
            nhsd_apim_proxy_url + "/token",
            data={"subject_token_type": "urn:ietf:params:oauth:token-type:id_token",
                  "client_assertion_type": "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
                  "subject_token": id_token_jwt,
                  "client_assertion": client_assertion,
                  "grant_type": "urn:ietf:params:oauth:grant-type:token-exchange"})
        resp = response.json()

        # Then
        assert expected_status_code == response.status_code
        assert expected_error == resp['error']
        assert expected_error_description == resp['error_description']

    @pytest.mark.errors
    @pytest.mark.token_exchange
    async def test_token_exchange_claims_assertion_missing_jti_claim(self, _test_app_credentials, _jwt_keys,
                                                                     nhsd_apim_proxy_url, cis_2_claims):
        # Given
        expected_status_code = 400
        expected_error = 'invalid_request'
        expected_error_description = "Missing jti claim in JWT"

        claims = {"sub": _test_app_credentials["consumerKey"],
                  "iss": _test_app_credentials["consumerKey"],
                  "jti": '',
                  "aud": f"{nhsd_apim_proxy_url}/token",
                  "exp": int(time()) + 5}

        with open(config.ID_TOKEN_PRIVATE_KEY_ABSOLUTE_PATH, "r") as f:
            id_token_private_key = f.read()

        additional_headers = {'kid': 'test-1'}
        client_assertion = jwt.encode(claims, _jwt_keys["private_key_pem"],
                                      algorithm="RS512",
                                      headers=additional_headers)

        kid = "identity-service-tests-1"
        headers = ({}, {"kid": kid})[kid is not None]
        id_token_jwt = jwt.encode(cis_2_claims, id_token_private_key, algorithm="RS512", headers=headers)

        # When
        response = requests.post(
            nhsd_apim_proxy_url + "/token",
            data={"subject_token_type": "urn:ietf:params:oauth:token-type:id_token",
                  "client_assertion_type": "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
                  "subject_token": id_token_jwt,
                  "client_assertion": client_assertion,
                  "grant_type": "urn:ietf:params:oauth:grant-type:token-exchange"})
        resp = response.json()

        # Then
        assert expected_status_code == response.status_code
        assert expected_error == resp['error']
        assert expected_error_description == resp['error_description']

    @pytest.mark.errors
    @pytest.mark.token_exchange
    async def test_token_exchange_claims_assertion_missing_exp_claim(self, _test_app_credentials, _jwt_keys,
                                                                     nhsd_apim_proxy_url, cis_2_claims):
        # Given
        expected_status_code = 400
        expected_error = 'invalid_request'
        expected_error_description = "Missing exp claim in JWT"

        claims = {"sub": _test_app_credentials["consumerKey"],
                  "iss": _test_app_credentials["consumerKey"],
                  "jti": str(uuid4()),
                  "aud": f"{nhsd_apim_proxy_url}/token"}

        with open(config.ID_TOKEN_PRIVATE_KEY_ABSOLUTE_PATH, "r") as f:
            id_token_private_key = f.read()

        additional_headers = {'kid': 'test-1'}
        client_assertion = jwt.encode(claims, _jwt_keys["private_key_pem"],
                                      algorithm="RS512",
                                      headers=additional_headers)

        kid = "identity-service-tests-1"
        headers = ({}, {"kid": kid})[kid is not None]
        id_token_jwt = jwt.encode(cis_2_claims, id_token_private_key, algorithm="RS512", headers=headers)

        # When
        response = requests.post(
            nhsd_apim_proxy_url + "/token",
            data={"subject_token_type": "urn:ietf:params:oauth:token-type:id_token",
                  "client_assertion_type": "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
                  "subject_token": id_token_jwt,
                  "client_assertion": client_assertion,
                  "grant_type": "urn:ietf:params:oauth:grant-type:token-exchange"})
        resp = response.json()

        # Then
        assert expected_status_code == response.status_code
        assert expected_error == resp['error']
        assert expected_error_description == resp['error_description']

    @pytest.mark.errors
    @pytest.mark.token_exchange
    async def test_token_exchange_claims_assertion_invalid_exp_claim(self, _test_app_credentials, _jwt_keys,
                                                                     nhsd_apim_proxy_url, cis_2_claims):
        # Given
        expected_status_code = 400
        expected_error = 'invalid_request'
        expected_error_description = "Invalid exp claim in JWT - more than 5 minutes in future"

        claims = {"sub": _test_app_credentials["consumerKey"],
                  "iss": _test_app_credentials["consumerKey"],
                  "jti": str(uuid4()),
                  "aud": f"{nhsd_apim_proxy_url}/token",
                  "exp": int(time()) + 50000}

        with open(config.ID_TOKEN_PRIVATE_KEY_ABSOLUTE_PATH, "r") as f:
            id_token_private_key = f.read()

        additional_headers = {'kid': 'test-1'}
        client_assertion = jwt.encode(claims, _jwt_keys["private_key_pem"],
                                      algorithm="RS512",
                                      headers=additional_headers)

        kid = "identity-service-tests-1"
        headers = ({}, {"kid": kid})[kid is not None]
        id_token_jwt = jwt.encode(cis_2_claims, id_token_private_key, algorithm="RS512", headers=headers)

        # When
        response = requests.post(
            nhsd_apim_proxy_url + "/token",
            data={"subject_token_type": "urn:ietf:params:oauth:token-type:id_token",
                  "client_assertion_type": "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
                  "subject_token": id_token_jwt,
                  "client_assertion": client_assertion,
                  "grant_type": "urn:ietf:params:oauth:grant-type:token-exchange"})
        resp = response.json()

        # Then
        assert expected_status_code == response.status_code
        assert expected_error == resp['error']
        assert expected_error_description == resp['error_description']

    @pytest.mark.errors
    @pytest.mark.token_exchange
    async def test_token_exchange_claims_assertion_invalid_jti_claim(self, _test_app_credentials, _jwt_keys,
                                                                     nhsd_apim_proxy_url, cis_2_claims, claims):
        # Given
        expected_status_code = 400
        expected_error = 'invalid_request'
        expected_error_description = "Non-unique jti claim in JWT"

        additional_headers = {'kid': 'test-1'}
        client_assertion = jwt.encode(claims, _jwt_keys["private_key_pem"],
                                      algorithm="RS512",
                                      headers=additional_headers)

        with open(config.ID_TOKEN_PRIVATE_KEY_ABSOLUTE_PATH, "r") as f:
            id_token_private_key = f.read()

        kid = "identity-service-tests-1"
        headers = ({}, {"kid": kid})[kid is not None]
        id_token_jwt = jwt.encode(cis_2_claims, id_token_private_key, algorithm="RS512", headers=headers)

        # When
        response = requests.post(
            nhsd_apim_proxy_url + "/token",
            data={"subject_token_type": "urn:ietf:params:oauth:token-type:id_token",
                  "client_assertion_type": "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
                  "subject_token": id_token_jwt,
                  "client_assertion": client_assertion,
                  "grant_type": "urn:ietf:params:oauth:grant-type:token-exchange"})
        resp = response.json()

        assert 200 == response.status_code
        assert 'access_token' in resp['issued_token_type']

        response = requests.post(
            nhsd_apim_proxy_url + "/token",
            data={"subject_token_type": "urn:ietf:params:oauth:token-type:id_token",
                  "client_assertion_type": "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
                  "subject_token": id_token_jwt,
                  "client_assertion": client_assertion,
                  "grant_type": "urn:ietf:params:oauth:grant-type:token-exchange"})
        resp = response.json()

        # Then
        assert expected_status_code == response.status_code
        assert expected_error == resp['error']
        assert expected_error_description == resp['error_description']

    @pytest.mark.errors
    @pytest.mark.token_exchange
    async def test_token_exchange_subject_token_missing_iss_or_sub_claim(self, _test_app_credentials, _jwt_keys,
                                                                         nhsd_apim_proxy_url, cis_2_claims, claims):
        # Given
        expected_status_code = 400
        expected_error = 'invalid_request'
        expected_error_description = "Missing or non-matching iss/sub claims in JWT"

        additional_headers = {'kid': 'test-1'}
        client_assertion = jwt.encode(cis_2_claims, _jwt_keys["private_key_pem"],
                                      algorithm="RS512",
                                      headers=additional_headers)

        with open(config.ID_TOKEN_PRIVATE_KEY_ABSOLUTE_PATH, "r") as f:
            id_token_private_key = f.read()

        kid = "identity-service-tests-1"
        headers = ({}, {"kid": kid})[kid is not None]
        id_token_jwt = jwt.encode(cis_2_claims, id_token_private_key, algorithm="RS512", headers=headers)

        # When
        response = requests.post(
            nhsd_apim_proxy_url + "/token",
            data={"subject_token_type": "urn:ietf:params:oauth:token-type:id_token",
                  "client_assertion_type": "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
                  "subject_token": id_token_jwt,
                  "client_assertion": client_assertion,
                  "grant_type": "urn:ietf:params:oauth:grant-type:token-exchange"})
        resp = response.json()

        # Then
        assert expected_status_code == response.status_code
        assert expected_error == resp['error']
        assert expected_error_description == resp['error_description']

    @pytest.mark.simulated_auth
    @pytest.mark.errors
    @pytest.mark.token_exchange
    async def test_token_exchange_subject_token_missing_aud_claim(self, _test_app_credentials, _jwt_keys,
                                                                  nhsd_apim_proxy_url, claims):
        # Given
        expected_status_code = 400
        expected_error = 'invalid_request'
        expected_error_description = "Missing aud claim in JWT"

        id_token_claims = {
            'at_hash': 'tf_-lqpq36lwO7WmSBIJ6Q',
            'sub': '787807429511',
            'auditTrackingId': '91f694e6-3749-42fd-90b0-c3134b0d98f6-1546391',
            'iss': 'https://am.nhsint.auth-ptl.cis2.spineservices.nhs.uk:443'
                   '/openam/oauth2/realms/root/realms/NHSIdentity/realms/Healthcare',
            'amr': ['N3_SMARTCARD'],
            'tokenName': 'id_token',
            'c_hash': 'bc7zzGkClC3MEiFQ3YhPKg',
            'acr': 'AAL3_ANY',
            'org.forgerock.openidconnect.ops': '-I45NjmMDdMa-aNF2sr9hC7qEGQ',
            's_hash': 'LPJNul-wow4m6Dsqxbning',
            'azp': '969567331415.apps.national',
            'auth_time': 1610559802,
            'realm': '/NHSIdentity/Healthcare',
            'exp': int(time()) + 600,
            'tokenType': 'JWTToken',
            'iat': int(time()) - 10
        }

        additional_headers = {'kid': 'test-1'}
        client_assertion = jwt.encode(claims, _jwt_keys["private_key_pem"],
                                      algorithm="RS512",
                                      headers=additional_headers)

        with open(config.ID_TOKEN_PRIVATE_KEY_ABSOLUTE_PATH, "r") as f:
            id_token_private_key = f.read()

        kid = "identity-service-tests-1"
        headers = ({}, {"kid": kid})[kid is not None]
        id_token_jwt = jwt.encode(id_token_claims, id_token_private_key, algorithm="RS512", headers=headers)

        # When
        response = requests.post(
            nhsd_apim_proxy_url + "/token",
            data={"subject_token_type": "urn:ietf:params:oauth:token-type:id_token",
                  "client_assertion_type": "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
                  "subject_token": id_token_jwt,
                  "client_assertion": client_assertion,
                  "grant_type": "urn:ietf:params:oauth:grant-type:token-exchange"})
        resp = response.json()

        # Then
        assert expected_status_code == response.status_code
        assert expected_error == resp['error']
        assert expected_error_description == resp['error_description']

    @pytest.mark.errors
    @pytest.mark.token_exchange
    async def test_token_exchange_subject_token_missing_exp_claim(self, _jwt_keys, nhsd_apim_proxy_url, claims):
        # Given
        expected_status_code = 400
        expected_error = 'invalid_request'
        expected_error_description = "Missing exp claim in JWT"

        id_token_claims = {
            'at_hash': 'tf_-lqpq36lwO7WmSBIJ6Q',
            'sub': '787807429511',
            'auditTrackingId': '91f694e6-3749-42fd-90b0-c3134b0d98f6-1546391',
            'amr': ['N3_SMARTCARD'],
            'iss': 'https://am.nhsint.auth-ptl.cis2.spineservices.nhs.uk:443'
                   '/openam/oauth2/realms/root/realms/NHSIdentity/realms/Healthcare',
            'tokenName': 'id_token',
            'aud': '969567331415.apps.national',
            'c_hash': 'bc7zzGkClC3MEiFQ3YhPKg',
            'acr': 'AAL3_ANY',
            'org.forgerock.openidconnect.ops': '-I45NjmMDdMa-aNF2sr9hC7qEGQ',
            's_hash': 'LPJNul-wow4m6Dsqxbning',
            'azp': '969567331415.apps.national',
            'auth_time': 1610559802,
            'realm': '/NHSIdentity/Healthcare',
            'tokenType': 'JWTToken',
            'iat': int(time()) - 10
        }

        additional_headers = {'kid': 'test-1'}
        client_assertion = jwt.encode(claims, _jwt_keys["private_key_pem"],
                                      algorithm="RS512",
                                      headers=additional_headers)

        with open(config.ID_TOKEN_PRIVATE_KEY_ABSOLUTE_PATH, "r") as f:
            id_token_private_key = f.read()

        kid = "identity-service-tests-1"
        headers = ({}, {"kid": kid})[kid is not None]
        id_token_jwt = jwt.encode(id_token_claims, id_token_private_key, algorithm="RS512", headers=headers)

        # When
        response = requests.post(
            nhsd_apim_proxy_url + "/token",
            data={"subject_token_type": "urn:ietf:params:oauth:token-type:id_token",
                  "client_assertion_type": "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
                  "subject_token": id_token_jwt,
                  "client_assertion": client_assertion,
                  "grant_type": "urn:ietf:params:oauth:grant-type:token-exchange"})
        resp = response.json()

        # Then
        assert expected_status_code == response.status_code
        assert expected_error == resp['error']
        assert expected_error_description == resp['error_description']

    @pytest.mark.simulated_auth
    @pytest.mark.errors
    @pytest.mark.token_exchange
    @pytest.mark.skip(reason="Skipped for now. Needs further investigation.")
    async def test_nhs_login_happy_path(self, _nhsd_apim_auth_token_data, _jwt_keys, nhsd_apim_proxy_url):
        # Given
        assert "access_token" in _nhsd_apim_auth_token_data.keys()
        assert "issued_at" in _nhsd_apim_auth_token_data.keys()
        assert _nhsd_apim_auth_token_data["expires_in"] == "599"
        assert _nhsd_apim_auth_token_data["token_type"] == "Bearer"
        expected_status_code = 200
        expected_expires_in = '599'
        expected_token_type = 'Bearer'
        expected_issued_token_type = 'urn:ietf:params:oauth:token-type:access_token'

        id_token_claims = {
            'aud': 'tf_-APIM-1',
            'id_status': 'verified',
            'token_use': 'id',
            'auth_time': 1616600683,
            'iss': 'https://internal-dev.api.service.nhs.uk',
            'vot': 'P9.Cp.Cd',
            'exp': int(time()) + 600,
            'iat': int(time()) - 10,
            'vtm': 'https://auth.sandpit.signin.nhs.uk/trustmark/auth.sandpit.signin.nhs.uk',
            'jti': 'b68ddb28-e440-443d-8725-dfe0da330118',
            "identity_proofing_level": "P9"
        }
        id_token_headers = {
            "sub": "49f470a1-cc52-49b7-beba-0f9cec937c46",
            "aud": "APIM-1",
            "kid": "nhs-login",
            "iss": "https://internal-dev.api.service.nhs.uk",
            "typ": "JWT",
            "exp": 1616604574,
            "iat": 1616600974,
            "alg": "RS512",
            "jti": "b68ddb28-e440-443d-8725-dfe0da330118"
        }

        additional_headers = {'kid': 'test-1'}
        client_assertion = jwt.encode(claims, _jwt_keys["private_key_pem"],
                                      algorithm="RS512",
                                      headers=additional_headers)

        with open(ID_TOKEN_NHS_LOGIN_PRIVATE_KEY_ABSOLUTE_PATH, "r") as f:
            id_token_nhs_login = f.read()

        id_token_jwt = jwt.encode(payload=id_token_claims,
                                  key=id_token_nhs_login,
                                  algorithm="RS512",
                                  headers=id_token_headers)

        # When
        response = requests.post(
            nhsd_apim_proxy_url + "/token",
            data={"subject_token_type": "urn:ietf:params:oauth:token-type:id_token",
                  "client_assertion_type": "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
                  "subject_token": id_token_jwt,
                  "client_assertion": client_assertion,
                  "grant_type": "urn:ietf:params:oauth:grant-type:token-exchange"})
        resp = response.json()
        print(resp)
        #     # Then
        assert expected_status_code == response.status_code
        assert 'access_token' in resp['body']
        assert expected_expires_in == resp['body']['expires_in']
        assert expected_token_type == resp['body']['token_type']
        assert expected_issued_token_type == resp['body']['issued_token_type']

    @pytest.mark.errors
    @pytest.mark.token_exchange
    async def test_token_exchange_subject_token_nhs_login_missing_iss_claim(self, _jwt_keys, nhsd_apim_proxy_url,
                                                                            claims):
        # Given
        expected_status_code = 400
        expected_error = 'invalid_request'
        expected_error_description = "Missing or non-matching iss/sub claims in JWT"

        id_token_claims = {
            'aud': 'tf_-APIM-1',
            'id_status': 'verified',
            'token_use': 'id',
            'auth_time': 1616600683,
            'vot': 'P9.Cp.Cd',
            'exp': int(time()) + 600,
            'iat': int(time()) - 10,
            'vtm': 'https://auth.sandpit.signin.nhs.uk/trustmark/auth.sandpit.signin.nhs.uk',
            'jti': 'b68ddb28-e440-443d-8725-dfe0da330118'
        }
        id_token_headers = {
            "sub": "49f470a1-cc52-49b7-beba-0f9cec937c46",
            "aud": "APIM-1",
            "kid": "nhs-login",
            "iss": "https://internal-dev.api.service.nhs.uk",
            "typ": "JWT",
            "exp": 1616604574,
            "iat": 1616600974,
            "alg": "RS512",
            "jti": "b68ddb28-e440-443d-8725-dfe0da330118"
        }

        additional_headers = {'kid': 'test-1'}
        client_assertion = jwt.encode(claims, _jwt_keys["private_key_pem"],
                                      algorithm="RS512",
                                      headers=additional_headers)

        with open(ID_TOKEN_NHS_LOGIN_PRIVATE_KEY_ABSOLUTE_PATH, "r") as f:
            id_token_nhs_login = f.read()

        id_token_jwt = jwt.encode(payload=id_token_claims,
                                  key=id_token_nhs_login,
                                  algorithm="RS512",
                                  headers=id_token_headers)

        # When
        response = requests.post(
            nhsd_apim_proxy_url + "/token",
            data={"subject_token_type": "urn:ietf:params:oauth:token-type:id_token",
                  "client_assertion_type": "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
                  "subject_token": id_token_jwt,
                  "client_assertion": client_assertion,
                  "grant_type": "urn:ietf:params:oauth:grant-type:token-exchange"})
        resp = response.json()

        # Then
        assert expected_status_code == response.status_code
        assert expected_error == resp['error']
        assert expected_error_description == resp['error_description']

    @pytest.mark.simulated_auth
    @pytest.mark.errors
    @pytest.mark.token_exchange
    async def test_token_exchange_subject_token_nhs_login_missing_aud_claim(self, _jwt_keys, nhsd_apim_proxy_url,
                                                                            claims):
        # Given
        expected_status_code = 400
        expected_error = 'invalid_request'
        expected_error_description = "Missing aud claim in JWT"

        id_token_claims = {
            'id_status': 'verified',
            'token_use': 'id',
            'auth_time': 1616600683,
            'iss': 'https://internal-dev.api.service.nhs.uk',
            'vot': 'P9.Cp.Cd',
            'exp': int(time()) + 600,
            'iat': int(time()) - 10,
            'vtm': 'https://auth.sandpit.signin.nhs.uk/trustmark/auth.sandpit.signin.nhs.uk',
            'jti': 'b68ddb28-e440-443d-8725-dfe0da330118'
        }
        id_token_headers = {
            "sub": "49f470a1-cc52-49b7-beba-0f9cec937c46",
            "aud": "APIM-1",
            "kid": "nhs-login",
            "iss": "https://internal-dev.api.service.nhs.uk",
            "typ": "JWT",
            "exp": 1616604574,
            "iat": 1616600974,
            "alg": "RS512",
            "jti": "b68ddb28-e440-443d-8725-dfe0da330118"
        }

        additional_headers = {'kid': 'test-1'}
        client_assertion = jwt.encode(claims, _jwt_keys["private_key_pem"],
                                      algorithm="RS512",
                                      headers=additional_headers)

        with open(ID_TOKEN_NHS_LOGIN_PRIVATE_KEY_ABSOLUTE_PATH, "r") as f:
            id_token_nhs_login = f.read()

        id_token_jwt = jwt.encode(payload=id_token_claims,
                                  key=id_token_nhs_login,
                                  algorithm="RS512",
                                  headers=id_token_headers)

        # When
        response = requests.post(
            nhsd_apim_proxy_url + "/token",
            data={"subject_token_type": "urn:ietf:params:oauth:token-type:id_token",
                  "client_assertion_type": "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
                  "subject_token": id_token_jwt,
                  "client_assertion": client_assertion,
                  "grant_type": "urn:ietf:params:oauth:grant-type:token-exchange"})
        resp = response.json()

        # Then
        assert expected_status_code == response.status_code
        assert expected_error == resp['error']
        assert expected_error_description == resp['error_description']

    @pytest.mark.errors
    @pytest.mark.token_exchange
    async def test_token_exchange_subject_token_nhs_login_missing_exp_claim(self, _jwt_keys, nhsd_apim_proxy_url,
                                                                            claims):
        # Given
        expected_status_code = 400
        expected_error = 'invalid_request'
        expected_error_description = "Missing exp claim in JWT"

        id_token_claims = {
            'aud': 'tf_-APIM-1',
            'id_status': 'verified',
            'token_use': 'id',
            'auth_time': 1616600683,
            'iss': 'https://internal-dev.api.service.nhs.uk',
            'vot': 'P9.Cp.Cd',
            'iat': int(time()) - 10,
            'vtm': 'https://auth.sandpit.signin.nhs.uk/trustmark/auth.sandpit.signin.nhs.uk',
            'jti': 'b68ddb28-e440-443d-8725-dfe0da330118'
        }
        id_token_headers = {
            "sub": "49f470a1-cc52-49b7-beba-0f9cec937c46",
            "aud": "APIM-1",
            "kid": "nhs-login",
            "iss": "https://internal-dev.api.service.nhs.uk",
            "typ": "JWT",
            "exp": 1616604574,
            "iat": 1616600974,
            "alg": "RS512",
            "jti": "b68ddb28-e440-443d-8725-dfe0da330118"
        }

        additional_headers = {'kid': 'test-1'}
        client_assertion = jwt.encode(claims, _jwt_keys["private_key_pem"],
                                      algorithm="RS512",
                                      headers=additional_headers)

        with open(ID_TOKEN_NHS_LOGIN_PRIVATE_KEY_ABSOLUTE_PATH, "r") as f:
            id_token_nhs_login = f.read()

        id_token_jwt = jwt.encode(payload=id_token_claims,
                                  key=id_token_nhs_login,
                                  algorithm="RS512",
                                  headers=id_token_headers)

        # When
        response = requests.post(
            nhsd_apim_proxy_url + "/token",
            data={"subject_token_type": "urn:ietf:params:oauth:token-type:id_token",
                  "client_assertion_type": "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
                  "subject_token": id_token_jwt,
                  "client_assertion": client_assertion,
                  "grant_type": "urn:ietf:params:oauth:grant-type:token-exchange"})
        resp = response.json()

        # Then
        assert expected_status_code == response.status_code
        assert expected_error == resp['error']
        assert expected_error_description == resp['error_description']

    @pytest.mark.errors
    @pytest.mark.token_exchange
    async def test_token_exchange_subject_token_nhs_login_invalid_iss_claim(self, _jwt_keys, nhsd_apim_proxy_url,
                                                                            claims):
        # Given
        expected_status_code = 400
        expected_error = 'invalid_request'
        expected_error_description = "Missing or non-matching iss/sub claims in JWT"

        id_token_claims = {
            'aud': 'tf_-APIM-1',
            'id_status': 'verified',
            'token_use': 'id',
            'auth_time': 1616600683,
            'iss': 'invalidIss',
            'vot': 'P9.Cp.Cd',
            'exp': int(time()) + 600,
            'iat': int(time()) - 10,
            'vtm': 'https://auth.sandpit.signin.nhs.uk/trustmark/auth.sandpit.signin.nhs.uk',
            'jti': 'b68ddb28-e440-443d-8725-dfe0da330118'
        }
        id_token_headers = {
            "sub": "49f470a1-cc52-49b7-beba-0f9cec937c46",
            "aud": "APIM-1",
            "kid": "nhs-login",
            "iss": "InvalidIss",
            "typ": "JWT",
            "exp": 1616604574,
            "iat": 1616600974,
            "alg": "RS512",
            "jti": "b68ddb28-e440-443d-8725-dfe0da330118"
        }

        additional_headers = {'kid': 'test-1'}
        client_assertion = jwt.encode(claims, _jwt_keys["private_key_pem"],
                                      algorithm="RS512",
                                      headers=additional_headers)

        with open(ID_TOKEN_NHS_LOGIN_PRIVATE_KEY_ABSOLUTE_PATH, "r") as f:
            id_token_nhs_login = f.read()

        id_token_jwt = jwt.encode(payload=id_token_claims,
                                  key=id_token_nhs_login,
                                  algorithm="RS512",
                                  headers=id_token_headers)

        # When
        response = requests.post(
            nhsd_apim_proxy_url + "/token",
            data={"subject_token_type": "urn:ietf:params:oauth:token-type:id_token",
                  "client_assertion_type": "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
                  "subject_token": id_token_jwt,
                  "client_assertion": client_assertion,
                  "grant_type": "urn:ietf:params:oauth:grant-type:token-exchange"})
        resp = response.json()

        # Then
        assert expected_status_code == response.status_code
        assert expected_error == resp['error']
        assert expected_error_description == resp['error_description']

    @pytest.mark.errors
    @pytest.mark.token_exchange
    @pytest.mark.skip(reason="Skipped for now. Needs further investigation.")
    async def test_token_exchange_invalid_jwks_resource_url(self, test_product, test_application):
        # Given
        expected_status_code = 403
        expected_error = 'public_key error'
        expected_error_description = "The JWKS endpoint, for your client_assertion can't be reached"

        id_token_jwt = self.oauth.create_id_token_jwt()

        await test_application.add_api_product([test_product.name])
        await test_application.set_custom_attributes(attributes={"jwks-resource-url": "http://invalid_url"})

        client_assertion_jwt = self.oauth.create_jwt(kid='test-1', client_id=test_application.client_id)

        # When
        resp = await self.oauth.get_token_response(
            grant_type="token_exchange",
            _jwt=client_assertion_jwt,
            id_token_jwt=id_token_jwt
        )

        # Then
        assert expected_status_code == resp['status_code'], resp['body']
        assert expected_error == resp['body']['error']
        assert expected_error_description == resp['body']['error_description']

    @pytest.mark.errors
    @pytest.mark.token_exchange
    @pytest.mark.skip(reason="Skipped for now. Needs further investigation.")
    async def test_token_exchange_no_jwks_resource_url_set(self, test_product, test_application):
        # Given
        expected_status_code = 403
        expected_error = 'public_key error'
        expected_error_description = "You need to register a public key to use this authentication method " \
                                     "- please contact support to configure"

        id_token_jwt = self.oauth.create_id_token_jwt()

        await test_application.add_api_product([test_product.name])
        client_assertion_jwt = self.oauth.create_jwt(kid='test-1', client_id=test_application.client_id)

        # When
        resp = await self.oauth.get_token_response(
            grant_type="token_exchange",
            _jwt=client_assertion_jwt,
            id_token_jwt=id_token_jwt
        )

        # Then
        assert expected_status_code == resp['status_code'], resp['body']
        assert expected_error == resp['body']['error']
        assert expected_error_description == resp['body']['error_description']

    # ############ OAUTH ENDPOINTS ###########

    @pytest.mark.simulated_auth
    async def test_userinfo_nhs_login_exchanged_token(self, _jwt_keys, nhsd_apim_proxy_url, claims):
        # Given
        expected_status_code = 400
        expected_error = 'invalid_request'
        expected_error_description = 'The Userinfo endpoint is only supported for Combined Auth integrations. ' \
                                     'Currently this is only for NHS CIS2 authentications - for more guidance see ' \
                                     'https://digital.nhs.uk/developer/guides-and-documentation/security-and' \
                                     '-authorisation/user-restricted-restful-apis-nhs-cis2-combined-authentication' \
                                     '-and-authorisation'

        # When
        id_token_claims = {"at_hash": "tf_-lqpq36lwO7WmSBIJ6Q",
                           "sub": "787807429511",
                           "auditTrackingId": "91f694e6-3749-42fd-90b0-c3134b0d98f6-1546391",
                           "amr": ["N3_SMARTCARD"],
                           "iss": "https://am.nhsint.auth-ptl.cis2.spineservices.nhs.uk:443/openam/oauth2/realms/root"
                                  "/realms"
                                  "/NHSIdentity/realms/Healthcare",
                           "tokenName": "id_token",
                           "aud": "969567331415.apps.national",
                           "c_hash": "bc7zzGkClC3MEiFQ3YhPKg",
                           "acr": "AAL3_ANY",
                           "org.forgerock.openidconnect.ops": "-I45NjmMDdMa-aNF2sr9hC7qEGQ",
                           "s_hash": "LPJNul-wow4m6Dsqxbning",
                           "azp": "969567331415.apps.national",
                           "auth_time": 1610559802,
                           "realm": "/NHSIdentity/Healthcare",
                           "exp": int(time()) + 300,
                           "tokenType": "JWTToken",
                           "iat": int(time()) - 100}

        additional_headers = {'kid': 'test-1'}
        client_assertion = jwt.encode(claims, _jwt_keys["private_key_pem"],
                                      algorithm="RS512",
                                      headers=additional_headers)

        with open(config.ID_TOKEN_PRIVATE_KEY_ABSOLUTE_PATH, "r") as f:
            id_token_private_key = f.read()

        kid = "identity-service-tests-1"
        headers = ({}, {"kid": kid})[kid is not None]
        id_token_jwt = jwt.encode(id_token_claims, id_token_private_key, algorithm="RS512", headers=headers)

        # When
        response = requests.post(
            nhsd_apim_proxy_url + "/token",
            data={"subject_token_type": "urn:ietf:params:oauth:token-type:id_token",
                  "client_assertion_type": "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
                  "subject_token": id_token_jwt,
                  "client_assertion": client_assertion,
                  "grant_type": "urn:ietf:params:oauth:grant-type:token-exchange"})
        resp = response.json()

        # Then
        token = resp["access_token"]
        resp = requests.get(nhsd_apim_proxy_url + '/userinfo',
                            headers={"Authorization": f"Bearer {token}"})
        assert expected_status_code == resp.status_code

        resp = resp.json()
        assert expected_error_description in resp['error_description']
        assert expected_error in resp['error']

    # ############# OAUTH TOKENS ###############

    # @pytest.mark.simulated_auth
    # @pytest.mark.parametrize("auth_method", ["P0"])
    # @pytest.mark.parametrize("auth_method", ["P0", "P5", "P9"])
    # @pytest.mark.authorize_endpoint
    # @pytest.mark.skip(reason="Skipped for now. Needs further investigation.")
    # async def test_nhs_login_auth_code_flow_happy_path(self, nhsd_apim_proxy_url, auth_code_nhs_login):
    #     response = requests.get(CANARY_API_URL,
    #                             headers={"Authorization": f"Bearer {access_token}",
    #                                      "NHSD-Session-URID": "ROLD-ID"})
    #     assert 'Hello user!' == response.text
    #     assert 200 == response.status_code
    @pytest.mark.skip(reason="Skipped for now. Needs further investigation.")
    @pytest.mark.parametrize(
        ("expected_status_code", "test_path"),
        [pytest.param(
            200,
            "/test-auth/nhs-login/P9",
            marks=pytest.mark.nhsd_apim_authorization(
                access="patient",
                level="P9",
                login_form={"auth_method": "P9"},
            ))])
    def test_nhs_login_auth_code_flow_happy_path(self, nhsd_apim_proxy_url, expected_status_code, test_path,
                                                 nhsd_apim_auth_headers):
        # additional_headers = {'kid': 'test-1'}
        #         client_assertion = jwt.encode(claims, _jwt_keys["private_key_pem"],
        #                                       algorithm="RS512",
        #                                       headers=additional_headers)
        #
        #         with open(config.ID_TOKEN_PRIVATE_KEY_ABSOLUTE_PATH, "r") as f:
        #             id_token_private_key = f.read()
        #
        #         kid = "identity-service-tests-1"
        #         headers = ({}, {"kid": kid})[kid is not None]
        #         id_token_jwt = jwt.encode(id_token_claims, id_token_private_key, algorithm="RS512", headers=headers)
        #
        #         # When
        #         response = requests.post(
        #             nhsd_apim_proxy_url + "/token",
        #             data={"subject_token_type": "urn:ietf:params:oauth:token-type:id_token",
        #                   "client_assertion_type": "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
        #                   "subject_token": id_token_jwt,
        #                   "client_assertion": client_assertion,
        #                   "grant_type": "urn:ietf:params:oauth:grant-type:token-exchange"})
        #         resp = response.json()
        #
        # response = requests.get(CANARY_API_URL,
        #                         headers={"Authorization": f"Bearer {access_token}",
        #                                  "NHSD-Session-URID": "ROLD-ID"})
        # assert 'Hello user!' == response.text
        # assert 200 == response.status_code
        resp = requests.get(nhsd_apim_proxy_url + test_path, headers=nhsd_apim_auth_headers)
        assert resp.status_code == expected_status_code

    @pytest.mark.simulated_auth
    @pytest.mark.parametrize('scope', ['P5'])
    # @pytest.mark.skip(reason="Skipped for now. Needs further investigation.")
    async def test_nhs_login_token_exchange_access_and_refresh_tokens_generated(self, scope, claims, _jwt_keys,
                                                                                nhsd_apim_proxy_url):
        """
        Ensure access token and refresh token generated by nhs login token exchange
        Use to fetch and a new access token, refresh token pair.
        """
        id_token_claims = {
            "aud": "tf_-APIM-1",
            "id_status": "verified",
            "token_use": "id",
            "auth_time": 1616600683,
            "iss": "https://internal-dev.api.service.nhs.uk",
            "vot": "P9.Cp.Cd",
            "exp": int(time()) + 600,
            "iat": int(time()) - 10,
            "vtm": "https://auth.sandpit.signin.nhs.uk/trustmark/auth.sandpit.signin.nhs.uk",
            "jti": "b68ddb28-e440-443d-8725-dfe0da330118",
            "identity_proofing_level": scope,
            "nhs_number": "9482807146",
            "nonce": "randomnonce",
            "family_name": "CARTHY",

        }

        id_token_headers = {
            "sub": "49f470a1-cc52-49b7-beba-0f9cec937c46",
            "aud": "APIM-1",
            "kid": "nhs-login",
            "iss": "https://internal-dev.api.service.nhs.uk",
            "typ": "JWT",
            "exp": 1616604574,
            "iat": 1616600974,
            "alg": "RS512",
            "jti": "b68ddb28-e440-443d-8725-dfe0da330118",
        }
        id_token_nhs_login_claims = {
            "sub": "8dc9fc1d-c3cb-48e1-ba62-b1532539ab6d",
            "birthdate": "1939-09-26",
            "nhs_number": "9482807146",
            "iss": "https://internal-dev.api.service.nhs.uk",
            "nonce": "randomnonce",
            "vtm": "https://auth.aos.signin.nhs.uk/trustmark/auth.aos.signin.nhs.uk",
            "aud": "java_test_client",
            "id_status": "verified",
            "token_use": "id",
            "surname": "CARTHY",
            "auth_time": 1617272144,
            "vot": "P9.Cp.Cd",
            "identity_proofing_level": "P9",
            "exp": int(time()) + 6000,
            "iat": int(time()) - 100,
            "family_name": "CARTHY",
            "jti": "b6d6a28e-b0bb-44e3-974f-bb245c0b688a",
        }
        client_assertion = jwt.encode(claims, _jwt_keys["private_key_pem"],
                                      algorithm="RS512",
                                      headers={'kid': 'test-1'})

        with open(ID_TOKEN_NHS_LOGIN_PRIVATE_KEY_ABSOLUTE_PATH, "r") as f:
            id_token_nhs_login = f.read()

        id_token_jwt = jwt.encode(payload=id_token_claims,
                                  key=id_token_nhs_login,
                                  algorithm="RS512",
                                  headers={'kid': 'nhs-login'})

        # When
        response = requests.post(
            nhsd_apim_proxy_url + "/token",
            data={"subject_token_type": "urn:ietf:params:oauth:token-type:id_token",
                  "client_assertion_type": "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
                  "subject_token": id_token_jwt,
                  "client_assertion": client_assertion,
                  "grant_type": "urn:ietf:params:oauth:grant-type:token-exchange"})
        resp = response.json()
        print(resp)
        # make test fail after this line
        access_token = response['body']['access_token']
        refresh_token = response['body']['refresh_token']

        assert access_token
        assert refresh_token
        assert resp['body']['expires_in'] == '599'
        assert resp['body']['refresh_token_expires_in'] == '3599'

        # Get new access token using refresh token to ensure valid
        resp2 = await self.oauth.get_token_response(grant_type="refresh_token", refresh_token=refresh_token)
        access_token2 = resp2['body']['access_token']
        refresh_token2 = resp2['body']['refresh_token']

        assert access_token2
        assert refresh_token2

        # # Then
        # assert expected_status_code == response.status_code
        # assert expected_error == resp['error']
        # assert expected_error_description == resp['error_description']

    @pytest.mark.simulated_auth
    @pytest.mark.skip(reason="Skipped for now. Needs further investigation.")
    async def test_cis2_token_exchange_access_tokens_valid(self):
        """
        Using a refresh token that was generated via token exchange, fetch and use
        a new access token, refresh token pair.
        """
        # Generate access token using token-exchange
        id_token_jwt = self.oauth.create_id_token_jwt()
        client_assertion_jwt = self.oauth.create_jwt(kid='test-1')
        resp = await self.oauth.get_token_response(grant_type='token_exchange', _jwt=client_assertion_jwt,
                                                   id_token_jwt=id_token_jwt)

        access_token = resp['body']['access_token']
        refresh_token = resp['body']['refresh_token']

        assert access_token
        assert refresh_token
        assert resp['body']['expires_in'] == '599'
        assert resp['body']['refresh_token_expires_in'] == '43199'

        # Make request using access token to ensure valid
        req = requests.get(f"{CANARY_API_URL}", headers={"Authorization": f"Bearer {access_token}"})
        assert req.status_code == 200

        # Get new access token using refresh token to ensure valid
        resp2 = await self.oauth.get_token_response(grant_type="refresh_token", refresh_token=refresh_token)
        access_token2 = resp2['body']['access_token']
        refresh_token2 = resp2['body']['refresh_token']
        assert access_token2
        assert refresh_token2

        # Make request using new access token to ensure valid
        req2 = requests.get(f"{CANARY_API_URL}", headers={"Authorization": f"Bearer {access_token2}"})
        assert req2.status_code == 200

    @pytest.mark.simulated_auth
    @pytest.mark.skip(reason="Skipped for now. Needs further investigation.")
    async def test_cis2_token_exchange_refresh_token_become_invalid(self):
        """
        Fetch a new access token, refresh token pair.
        Ensure the original refresh token becomes invalid
        """
        # Generate access token using token-exchange
        id_token_jwt = self.oauth.create_id_token_jwt()
        client_assertion_jwt = self.oauth.create_jwt(kid='test-1')
        resp = await self.oauth.get_token_response(grant_type='token_exchange', _jwt=client_assertion_jwt,
                                                   id_token_jwt=id_token_jwt)

        access_token = resp['body']['access_token']
        refresh_token = resp['body']['refresh_token']

        assert access_token
        assert refresh_token

        # Get new access token using refresh token
        resp2 = await self.oauth.get_token_response(grant_type="refresh_token", refresh_token=refresh_token)
        access_token2 = resp2['body']['access_token']
        assert access_token2

        # try to use the original refresh token to get another access token
        resp3 = await self.oauth.get_token_response(grant_type="refresh_token", refresh_token=refresh_token)
        assert resp3['status_code'] == 401

    async def test_rejects_token_request_by_password(self):
        """
        Test that request for token using password grant type is rejected.
        """
        form_data = {
            "client_id": self.oauth.client_id,
            "client_secret": self.oauth.client_secret,
            "grant_type": "password",
            "username": "username",
            "password": "password"
        }
        resp = await self.oauth.get_token_response(grant_type='password', data=form_data)

        assert resp['status_code'] == 400

    @pytest.mark.parametrize("token_expiry_ms, expected_time",
                             [(100000, 100), (500000, 500), (700000, 600), (1000000, 600)])
    @pytest.mark.skip(reason="Skipped for now. Needs further investigation.")
    async def test_access_token_override_with_client_credentials(self, token_expiry_ms, expected_time):
        """
        Test client credential flow access token can be overridden with a time less than 10 min(600000ms or 600s)
        and NOT be overridden with a time greater than 10 min(600000ms or 600s)
        """
        form_data = {
            "client_assertion_type": "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
            "client_assertion": self.oauth.create_jwt('test-1'),
            "grant_type": 'client_credentials',
            "_access_token_expiry_ms": token_expiry_ms
        }

        resp = await self.oauth.get_token_response(grant_type='client_credentials', data=form_data)

        assert resp['status_code'] == 200
        assert int(resp['body']['expires_in']) <= expected_time

    @pytest.mark.simulated_auth
    @pytest.mark.parametrize("token_expiry_ms, expected_time",
                             [(100000, 100), (500000, 500), (700000, 600), (1000000, 600)])
    @pytest.mark.skip(reason="Skipped for now. Needs further investigation.")
    async def test_access_token_override_with_token_exchange(self, token_expiry_ms, expected_time):
        """
        Test token exchange flow access token can be overridden with a time less than 10 min(600000ms or 600s)
        and NOT be overridden with a time greater than 10 min(600000ms or 600s)
        """
        id_token_jwt = self.oauth.create_id_token_jwt()
        client_assertion_jwt = self.oauth.create_jwt(kid='test-1')
        form_data = {
            "grant_type": "urn:ietf:params:oauth:grant-type:token-exchange",
            "subject_token_type": "urn:ietf:params:oauth:token-type:id_token",
            "client_assertion_type": "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
            "subject_token": id_token_jwt,
            "client_assertion": client_assertion_jwt,
            "_access_token_expiry_ms": token_expiry_ms
        }

        resp = await self.oauth.hit_oauth_endpoint("post", "token", data=form_data)

        assert resp['status_code'] == 200
        assert int(resp['body']['expires_in']) <= expected_time

    @pytest.mark.skip(reason="It is not feasible to run this test each build due to the timeframe required, "
                             "run manually if needed.")
    @pytest.mark.parametrize('scope', ['P9', 'P5', 'P0'])
    async def test_nhs_login_refresh_token_invalid_after_1_hour(self, scope):
        """
        Test that a refresh token received via a NHS Login is invalid after 1 hour (existing behaviour).
        Run pytest with the -s arg to display the stdout and show the wait time countdown.
        """
        id_token_claims = {
            "aud": "tf_-APIM-1",
            "id_status": "verified",
            "token_use": "id",
            "auth_time": 1616600683,
            "iss": "https://internal-dev.api.service.nhs.uk",
            "vot": "P9.Cp.Cd",
            "exp": int(time()) + 600,
            "iat": int(time()) - 10,
            "vtm": "https://auth.sandpit.signin.nhs.uk/trustmark/auth.sandpit.signin.nhs.uk",
            "jti": str(uuid4()),
            "identity_proofing_level": scope,
            "nhs_number": "900000000001"
        }
        id_token_headers = {
            "sub": "49f470a1-cc52-49b7-beba-0f9cec937c46",
            "aud": "APIM-1",
            "kid": "nhs-login",
            "iss": "https://internal-dev.api.service.nhs.uk",
            "typ": "JWT",
            "exp": 1616604574,
            "iat": 1616600974,
            "alg": "RS512",
            "jti": str(uuid4()),
        }

        with open(ID_TOKEN_NHS_LOGIN_PRIVATE_KEY_ABSOLUTE_PATH, "r") as f:
            contents = f.read()

        client_assertion_jwt = self.oauth.create_jwt(kid="test-1")
        id_token_jwt = self.oauth.create_id_token_jwt(
            algorithm="RS512",
            claims=id_token_claims,
            headers=id_token_headers,
            signing_key=contents,
        )
        resp = await self.oauth.get_token_response(
            grant_type="token_exchange",
            _jwt=client_assertion_jwt,
            id_token_jwt=id_token_jwt,
        )
        refresh_token = resp['body']['refresh_token']

        assert refresh_token
        assert resp['body']['expires_in'] == '599'
        assert resp['body']['refresh_token_expires_in'] == '3599'

        # Wait 1 hour (the previous refresh token expiry time) and check that the token is still valid
        for remaining in range(3600, 0, -1):
            mins, sec = divmod(remaining, 60)
            sys.stdout.write("\r")
            sys.stdout.write("{:2d} minutes {:2d} seconds remaining.".format(mins, sec))
            sleep(1)

        # Get new access token using refresh token
        resp2 = await self.oauth.get_token_response(grant_type="refresh_token", refresh_token=refresh_token)
        assert resp2['status_code'] == 401

    @pytest.mark.simulated_auth
    @pytest.mark.parametrize("token_expiry_ms, expected_time",
                             [(100000, 100), (500000, 500), (700000, 600), (1000000, 600)])
    @pytest.mark.skip(reason="Skipped for now. Needs further investigation.")
    async def test_access_token_override_with_authorization_code(self, token_expiry_ms, expected_time):
        """
        Test authorization code flow access token can be overridden with a time less than 10 min(600000ms or 600s)
        and NOT be overridden with a time greater than 10 min(600000ms or 600s)
        """

        resp = await self.oauth.get_token_response(grant_type='authorization_code', timeout=token_expiry_ms)

        assert resp['status_code'] == 200
        assert int(resp['body']['expires_in']) <= expected_time

    @pytest.mark.simulated_auth
    @pytest.mark.usefixtures("set_refresh_token")
    @pytest.mark.parametrize("token_expiry_ms, expected_time",
                             [(100000, 100), (500000, 500), (700000, 600), (1000000, 600)])
    @pytest.mark.skip(reason="Skipped for now. Needs further investigation.")
    async def test_access_token_override_with_refresh_token(self, token_expiry_ms, expected_time):
        """
        Test refresh token flow access token can be overridden with a time less than 10 min(600000ms or 600s)
        and  NOT be overridden with a time greater than 10 min(600000ms or 600s)
        """
        form_data = {
            "client_id": self.oauth.client_id,
            "client_secret": self.oauth.client_secret,
            "grant_type": "refresh_token",
            "refresh_token": self.oauth.refresh_token,
            "_refresh_tokens_validity_ms": 599,
            "_access_token_expiry_ms": token_expiry_ms
        }

        resp = await self.oauth.get_token_response(grant_type='refresh_token', data=form_data)

        assert resp['status_code'] == 200
        assert int(resp['body']['expires_in']) <= expected_time

    @pytest.mark.skip(reason="It is not feasible to run this test each build due to the timeframe required, "
                             "run manually if needed.")
    async def test_cis2_refresh_token_expires_after_12_hours(self):
        """
        Test that a refresh token received via a CIS2 login is valid for up to 12 hours.
        Run pytest with the -s arg to display the stdout and show the wait time countdown.
        """
        # Generate access token using token-exchange
        id_token_jwt = self.oauth.create_id_token_jwt()
        client_assertion_jwt = self.oauth.create_jwt(kid='test-1')
        resp = await self.oauth.get_token_response(
            grant_type="token_exchange",
            _jwt=client_assertion_jwt,
            id_token_jwt=id_token_jwt
        )

        refresh_token = resp['body']['refresh_token']

        assert refresh_token
        assert resp['body']['expires_in'] == '599'
        assert resp['body']['refresh_token_expires_in'] == '43199'

        # Wait 12 hours and check that the token has expired
        for remaining in range(43200, 0, -1):
            mins, sec = divmod(remaining, 60)
            hours, mins = divmod(mins, 60)
            sys.stdout.write("\r")
            sys.stdout.write("{:2d} hours {:2d} minutes {:2d} seconds remaining.".format(hours, mins, sec))
            sys.stdout.flush()
            sleep(1)

        # Try to use the now expired refresh token to get another access token
        resp2 = await self.oauth.get_token_response(grant_type="refresh_token", refresh_token=refresh_token)
        print(resp2)
        assert resp2['status_code'] == 401

    @pytest.mark.simulated_auth
    @pytest.mark.parametrize('scope', ['P9', 'P5', 'P0'])
    @pytest.mark.skip(reason="Skipped for now. Needs further investigation.")
    async def test_nhs_login_refresh_tokens_generated_with_expected_expiry_separated_auth(self, scope):
        """
        Test that refresh tokens generated via NHS Login have an expiry time of 1 hour for separated authentication.
        """
        id_token_claims = {
            "aud": "tf_-APIM-1",
            "id_status": "verified",
            "token_use": "id",
            "auth_time": 1616600683,
            "iss": "https://internal-dev.api.service.nhs.uk",
            "vot": "P9.Cp.Cd",
            "exp": int(time()) + 600,
            "iat": int(time()) - 10,
            "vtm": "https://auth.sandpit.signin.nhs.uk/trustmark/auth.sandpit.signin.nhs.uk",
            "jti": str(uuid4()),
            "identity_proofing_level": scope,
            "nhs_number": "900000000001"
        }
        id_token_headers = {
            "sub": "49f470a1-cc52-49b7-beba-0f9cec937c46",
            "aud": "APIM-1",
            "kid": "nhs-login",
            "iss": "https://internal-dev.api.service.nhs.uk",
            "typ": "JWT",
            "exp": 1616604574,
            "iat": 1616600974,
            "alg": "RS512",
            "jti": str(uuid4()),
        }

        with open(ID_TOKEN_NHS_LOGIN_PRIVATE_KEY_ABSOLUTE_PATH, "r") as f:
            contents = f.read()

        client_assertion_jwt = self.oauth.create_jwt(kid="test-1")
        id_token_jwt = self.oauth.create_id_token_jwt(
            algorithm="RS512",
            claims=id_token_claims,
            headers=id_token_headers,
            signing_key=contents,
        )
        resp = await self.oauth.get_token_response(
            grant_type="token_exchange",
            _jwt=client_assertion_jwt,
            id_token_jwt=id_token_jwt,
        )
        access_token = resp['body']['access_token']
        refresh_token = resp['body']['refresh_token']

        assert access_token
        assert refresh_token
        assert resp['body']['expires_in'] == '599'
        assert resp['body']['refresh_token_expires_in'] == '3599'

    @pytest.mark.simulated_auth
    @pytest.mark.skip(reason="Skipped for now. Needs further investigation.")
    async def test_cis2_refresh_tokens_generated_with_expected_expiry_separated_auth(self):
        """
        Test that refresh tokens generated via CIS2 have an expiry time of 12 hours for separated authentication.
        """
        # Generate access token using token-exchange
        id_token_jwt = self.oauth.create_id_token_jwt()
        client_assertion_jwt = self.oauth.create_jwt(kid='test-1')
        resp = await self.oauth.get_token_response(
            grant_type="token_exchange",
            _jwt=client_assertion_jwt,
            id_token_jwt=id_token_jwt
        )

        access_token = resp['body']['access_token']
        refresh_token = resp['body']['refresh_token']

        assert access_token
        assert refresh_token
        assert resp['body']['expires_in'] == '599'
        assert resp['body']['refresh_token_expires_in'] == '43199'
