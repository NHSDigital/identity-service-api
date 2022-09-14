import pytest
import requests
import jwt
from uuid import uuid4
from time import time
from e2e.scripts import config
from e2e.scripts.config import (
    ID_TOKEN_PRIVATE_KEY_ABSOLUTE_PATH,
    ID_TOKEN_NHS_LOGIN_PRIVATE_KEY_ABSOLUTE_PATH,
    CANARY_API_URL,
    CANARY_PRODUCT_NAME
)
from e2e.tests.oauth.utils.helpers import (
    remove_keys,
    replace_keys,
    subscribe_app_to_products
)


def create_client_assertion(claims, private_key, additional_headers={"kid": "test-1"}):
    return jwt.encode(
        claims,
        private_key,
        algorithm="RS512",
        headers=additional_headers
    )


def create_subject_token(claims, kid="identity-service-tests-1"):
    with open(ID_TOKEN_PRIVATE_KEY_ABSOLUTE_PATH, "r") as f:
        id_token_private_key = f.read()

    headers = ({}, {"kid": kid})[kid is not None]
    return jwt.encode(claims, id_token_private_key, algorithm="RS512", headers=headers)


def create_nhs_login_subject_token(claims, headers):
    with open(ID_TOKEN_NHS_LOGIN_PRIVATE_KEY_ABSOLUTE_PATH, "r") as f:
        id_token_nhs_login = f.read()

    return jwt.encode(
        payload=claims,
        key=id_token_nhs_login,
        algorithm="RS512",
        headers=headers
    )


@pytest.fixture
def claims(_test_app_credentials, nhsd_apim_proxy_url):
    return {
        "sub": _test_app_credentials["consumerKey"],
        "iss": _test_app_credentials["consumerKey"],
        "jti": str(uuid4()),
        "aud": nhsd_apim_proxy_url + "/token",
        "exp": int(time()) + 300,  # 5 minutes in the future
    }


@pytest.fixture
def cis2_subject_token_claims():
    return {
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


@pytest.fixture
def nhs_login_id_token():
    return {
        "headers": {
            "sub": "49f470a1-cc52-49b7-beba-0f9cec937c46",
            "aud": "APIM-1",
            "kid": "nhs-login",
            "iss": "https://internal-dev.api.service.nhs.uk",
            "typ": "JWT",
            "exp": 1616604574,
            "iat": 1616600974,
            "alg": "RS512",
            "jti": "b68ddb28-e440-443d-8725-dfe0da330118"
        },
        "claims": {
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
    }


@pytest.fixture
def token_data():
    return {
        "subject_token_type": "urn:ietf:params:oauth:token-type:id_token",
        "client_assertion_type": "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
        "subject_token": None,  # Should be replaced in test
        "client_assertion": None,  # Should be replaced in test
        "grant_type": "urn:ietf:params:oauth:grant-type:token-exchange"
    }


class TestTokenExchange:
    """ A test suit to test the token exchange flow """

    @pytest.mark.happy_path
    @pytest.mark.nhsd_apim_authorization(
        access="healthcare_worker",
        level="aal3",
        login_form={"username": "aal3"},
        authentication="separate",
        force_new_token=True
    )
    def test_cis2_token_exchange_happy_path(self, _nhsd_apim_auth_token_data):
        assert _nhsd_apim_auth_token_data["expires_in"] == "599"
        assert _nhsd_apim_auth_token_data["token_type"] == "Bearer"
        assert _nhsd_apim_auth_token_data["refresh_count"] == "0"
        assert _nhsd_apim_auth_token_data["issued_token_type"] == "urn:ietf:params:oauth:token-type:access_token"
        assert set(_nhsd_apim_auth_token_data.keys()) == {
            "access_token",
            "expires_in",
            "refresh_count",
            "refresh_token",
            "refresh_token_expires_in",
            "token_type",
            "issued_token_type",
            "issued_at"  # Added by pytest_nhsd_apim
        }

    @pytest.mark.simulated_auth
    @pytest.mark.token_exchange
    @pytest.mark.nhsd_apim_authorization(
        access="healthcare_worker",
        level="aal3",
        login_form={"username": "aal3"},
        authentication="separate",
        force_new_token=True
    )
    def test_cis2_token_exchange_refresh_token(
        self,
        _nhsd_apim_auth_token_data,
        nhsd_apim_proxy_url,
        _test_app_credentials
    ):
        resp = requests.post(
            nhsd_apim_proxy_url + "/token",
            data={
                "client_id": _test_app_credentials["consumerKey"],
                "client_secret": _test_app_credentials["consumerSecret"],
                "grant_type":  "refresh_token",
                "refresh_token": _nhsd_apim_auth_token_data["refresh_token"]
            },
            headers={"Content-Type": "application/x-www-form-urlencoded"}
        )
        refresh_resp = resp.json()

        assert resp.status_code == 200
        assert refresh_resp["expires_in"] == "599"
        assert refresh_resp["token_type"] == "Bearer"
        assert refresh_resp["refresh_count"] == "1"
        assert set(refresh_resp.keys()) == {
            "access_token",
            "expires_in",
            "refresh_count",
            "refresh_token",
            "refresh_token_expires_in",
            "token_type"
        }

    @pytest.mark.errors
    @pytest.mark.parametrize(
        "expected_response,expected_status_code,missing_or_invalid,update_data",
        [
            (  # Test invalid client_assertion_type
                {
                    "error": "invalid_request",
                    "error_description": "Missing or invalid client_assertion_type - " \
                                         "must be 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer"
                },
                400,
                "invalid",
                {"client_assertion_type": "invalid"}
            ),
            (  # Test missing client_assertion_type
                {
                    "error": "invalid_request",
                    "error_description": "Missing or invalid client_assertion_type - " \
                                         "must be 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer"
                },
                400,
                "missing",
                {"client_assertion_type"}
            ),
            (  # Test invalid subject_token_type
                {
                    "error": "invalid_request",
                    "error_description": "missing or invalid subject_token_type - " \
                                         "must be 'urn:ietf:params:oauth:token-type:id_token'"
                },
                400,
                "invalid",
                {"subject_token_type": "invalid"}
            ),
            (  # Test missing subject_token_type
                {
                    "error": "invalid_request",
                    "error_description": "missing or invalid subject_token_type - " \
                                         "must be 'urn:ietf:params:oauth:token-type:id_token'"
                },
                400,
                "missing",
                {"subject_token_type"}
            ),
            (  # Test invalid grant_type
                {
                    "error": "invalid_request",
                    "error_description": "grant_type is invalid"
                },
                400,
                "invalid",
                {"grant_type": "invalid"}
            ),
            (  # Test missing grant_type
                {
                    "error": "invalid_request",
                    "error_description": "grant_type is invalid"
                },
                400,
                "missing",
                {"grant_type"}
            ),
            (  # Test invalid subject_token - TO DO - REFACTOR when completing APM-3323
                {
                    "error": "invalid_request",
                    "error_description": "Malformed JWT in client_assertion"
                },
                400,
                "invalid",
                {"subject_token": "invalid"}
            ),
            (  # Test missing subject_token - TO DO - REFACTOR when completing APM-3323
                {
                    "error": "invalid_request",
                    "error_description": "Missing client_assertion"
                },
                400,
                "missing",
                {"subject_token"}
            ),
            (  # Test invalid client_assertion
                {
                    "error": "invalid_request",
                    "error_description": "Malformed JWT in client_assertion"
                },
                400,
                "invalid",
                {"client_assertion": "invalid"}
            ),
            (  # Test missing client_assertion
                {
                    "error": "invalid_request",
                    "error_description": "Missing client_assertion"
                },
                400,
                "missing",
                {"client_assertion"}
            ),
        ]
    )
    def test_token_exchange_form_param_errors(
        self,
        expected_response,
        expected_status_code,
        missing_or_invalid,
        update_data,
        claims,
        _jwt_keys,
        nhsd_apim_proxy_url,
        cis2_subject_token_claims,
        token_data
    ):
        token_data["client_assertion"] = create_client_assertion(claims, _jwt_keys["private_key_pem"])
        token_data["subject_token"] = create_subject_token(cis2_subject_token_claims)

        if missing_or_invalid == "missing":
            token_data = remove_keys(token_data, update_data)
        if missing_or_invalid == "invalid":
            token_data = replace_keys(token_data, update_data)

        # When
        resp = requests.post(
            nhsd_apim_proxy_url + "/token",
            data=token_data
        )

        # Then
        body = resp.json()
        assert resp.status_code == expected_status_code
        assert (
            "message_id" in body.keys()
        )  # We assert the key but not he value for message_id
        del body["message_id"]
        assert body == expected_response

    @pytest.mark.errors
    @pytest.mark.parametrize(
        "expected_response,expected_status_code,missing_or_invalid,update_headers",
        [
            (  # Test missing kid
                {
                    "error": "invalid_request",
                    "error_description": "Missing 'kid' header in JWT"
                },
                400,
                "missing",
                {"kid"}
            ),
            (  # Test invalid kid
                {
                    "error": "invalid_request",
                    "error_description": "Invalid 'kid' header in JWT - no matching public key"
                },
                401,
                "invalid",
                {"kid": "invalid"}
            ),
            (  # Test invalid typ
                {
                    "error": "invalid_request",
                    "error_description": "Invalid 'typ' header in JWT - must be 'JWT'"
                },
                400,
                "invalid",
                {"typ": "invalid"}
            ),
            (  # Test None typ
                {
                    "error": "invalid_request",
                    "error_description": "Invalid 'typ' header in JWT - must be 'JWT'"
                },
                400,
                "invalid",
                {"typ": None}
            ),
        ]
    )
    def test_token_exchange_client_assertion_header_errors(
        self,
        expected_response,
        expected_status_code,
        missing_or_invalid,
        update_headers,
        claims,
        _jwt_keys,
        nhsd_apim_proxy_url,
        cis2_subject_token_claims,
        token_data
    ):
        additional_headers = {"kid": "test-1"}

        if missing_or_invalid == "missing":
            additional_headers = remove_keys(additional_headers, update_headers)
        if missing_or_invalid == "invalid":
            additional_headers = replace_keys(additional_headers, update_headers)

        token_data["client_assertion"] = create_client_assertion(
            claims,
            _jwt_keys["private_key_pem"],
            additional_headers=additional_headers
        )
        token_data["subject_token"] = create_subject_token(cis2_subject_token_claims)

        # When
        resp = requests.post(
            nhsd_apim_proxy_url + "/token",
            data=token_data
        )

        # Then
        body = resp.json()
        assert resp.status_code == expected_status_code
        assert (
            "message_id" in body.keys()
        )  # We assert the key but not he value for message_id
        del body["message_id"]
        assert body == expected_response

    @pytest.mark.errors
    @pytest.mark.parametrize(
        "expected_response,expected_status_code,missing_or_invalid,update_claims",
        [
            (  # Test invalid iss
                {
                    "error": "invalid_request",
                    "error_description": "Missing or non-matching iss/sub claims in JWT"
                },
                400,
                "invalid",
                {"iss": "invalid"}
            ),
            (  # Test missing iss
                {
                    "error": "invalid_request",
                    "error_description": "Missing or non-matching iss/sub claims in JWT"
                },
                400,
                "missing",
                {"iss"}
            ),
            (  # Test invalid sub
                {
                    "error": "invalid_request",
                    "error_description": "Missing or non-matching iss/sub claims in JWT"
                },
                400,
                "invalid",
                {"sub": "invalid"}
            ),
            (  # Test missing sub
                {
                    "error": "invalid_request",
                    "error_description": "Missing or non-matching iss/sub claims in JWT"
                },
                400,
                "missing",
                {"sub"}
            ),
            (  # Test missing jti
                {
                    "error": "invalid_request",
                    "error_description": "Missing jti claim in JWT"
                },
                400,
                "missing",
                {"jti"}
            ),
            (  # Test missing exp
                {
                    "error": "invalid_request",
                    "error_description": "Missing exp claim in JWT"
                },
                400,
                "missing",
                {"exp"}
            ),
            (  # Test invalid exp - more than 5 minutes
                {
                    "error": "invalid_request",
                    "error_description": "Invalid exp claim in JWT - more than 5 minutes in future"
                },
                400,
                "invalid",
                {"exp": int(time()) + 50000}
            ),
            (  # Test invalid exp - string
                {
                    "error": "invalid_request",
                    "error_description": "Failed to decode JWT"
                },
                400,
                "invalid",
                {"exp": "invalid"}
            ),
        ]
    )
    def test_token_exchange_client_assertion_claims_errors(
        self,
        expected_response,
        expected_status_code,
        missing_or_invalid,
        update_claims,
        claims,
        _jwt_keys,
        nhsd_apim_proxy_url,
        cis2_subject_token_claims,
        token_data
    ):
        if missing_or_invalid == "missing":
            claims = remove_keys(claims, update_claims)
        if missing_or_invalid == "invalid":
            claims = replace_keys(claims, update_claims)

        token_data["client_assertion"] = create_client_assertion(claims, _jwt_keys["private_key_pem"])
        token_data["subject_token"] = create_subject_token(cis2_subject_token_claims)

        # When
        resp = requests.post(
            nhsd_apim_proxy_url + "/token",
            data=token_data
        )

        # Then
        body = resp.json()
        assert resp.status_code == expected_status_code
        assert (
            "message_id" in body.keys()
        )  # We assert the key but not he value for message_id
        del body["message_id"]
        assert body == expected_response

    @pytest.mark.errors
    @pytest.mark.token_exchange
    def test_token_exchange_claims_assertion_invalid_jti_claim(
        self,
        _jwt_keys,
        nhsd_apim_proxy_url,
        cis2_subject_token_claims,
        claims,
        token_data
    ):
        token_data["client_assertion"] = create_client_assertion(claims, _jwt_keys["private_key_pem"])
        token_data["subject_token"] = create_subject_token(cis2_subject_token_claims)

        # When
        response = requests.post(
            nhsd_apim_proxy_url + "/token",
            data=token_data
        )
        resp = response.json()

        assert 200 == response.status_code
        assert 'access_token' in resp['issued_token_type']

        resp = requests.post(
            nhsd_apim_proxy_url + "/token",
            data=token_data
        )

        body = resp.json()
        assert resp.status_code == 400
        assert (
            "message_id" in body.keys()
        )  # We assert the key but not he value for message_id
        del body["message_id"]
        assert body == {
            "error": "invalid_request",
            "error_description": "Non-unique jti claim in JWT"
        }

    @pytest.mark.errors
    @pytest.mark.parametrize(
        "expected_response,expected_status_code,missing_or_invalid,update_claims",
        [
            (  # Test invalid iss
                {
                    "error": "invalid_request",
                    "error_description": "Missing or non-matching iss/sub claims in JWT"
                },
                400,
                "invalid",
                {"iss": "invalid"}
            ),
            (  # Test missing iss
                {
                    "error": "invalid_request",
                    "error_description": "Missing or non-matching iss/sub claims in JWT"
                },
                400,
                "missing",
                {"iss"}
            ),
            (  # Test missing aud
                {
                    "error": "invalid_request",
                    "error_description": "Missing aud claim in JWT"
                },
                400,
                "missing",
                {"aud"}
            ),
            (  # Test missing exp
                {
                    "error": "invalid_request",
                    "error_description": "Missing exp claim in JWT"
                },
                400,
                "missing",
                {"exp"}
            ),
        ]
    )
    def test_token_exchange_subject_token_claims_errors(
        self,
        expected_response,
        expected_status_code,
        missing_or_invalid,
        update_claims,
        claims,
        _jwt_keys,
        nhsd_apim_proxy_url,
        cis2_subject_token_claims,
        token_data
    ):
        if missing_or_invalid == "missing":
            cis2_subject_token_claims = remove_keys(cis2_subject_token_claims, update_claims)
        if missing_or_invalid == "invalid":
            cis2_subject_token_claims = replace_keys(cis2_subject_token_claims, update_claims)

        token_data["subject_token"] = create_subject_token(cis2_subject_token_claims)
        token_data["client_assertion"] = create_client_assertion(claims, _jwt_keys["private_key_pem"])

        # When
        resp = requests.post(
            nhsd_apim_proxy_url + "/token",
            data=token_data
        )

        # Then
        body = resp.json()
        assert resp.status_code == expected_status_code
        assert (
            "message_id" in body.keys()
        )  # We assert the key but not he value for message_id
        del body["message_id"]
        assert body == expected_response

    @pytest.mark.simulated_auth
    @pytest.mark.token_exchange
    @pytest.mark.parametrize(
        "update_claims",
        [
            {"identity_proofing_level": "P0"},
            {"identity_proofing_level": "P5"},
            {"identity_proofing_level": "P9"}
        ]
    )
    def test_nhs_login_happy_path(
        self,
        update_claims,
        claims,
        _jwt_keys,
        nhsd_apim_proxy_url,
        nhs_login_id_token,
        token_data
    ):
        id_token_claims = replace_keys(nhs_login_id_token["claims"], update_claims)
        id_token_headers = nhs_login_id_token["headers"]

        token_data["subject_token"] = create_nhs_login_subject_token(id_token_claims, id_token_headers)
        token_data["client_assertion"] = create_client_assertion(claims, _jwt_keys["private_key_pem"])

        # When
        resp = requests.post(
            nhsd_apim_proxy_url + "/token",
            data=token_data
        )
        body = resp.json()

        assert resp.status_code == 200
        assert body["expires_in"] == "599"
        assert body["token_type"] == "Bearer"
        assert body["refresh_count"] == "0"
        assert body["issued_token_type"] == "urn:ietf:params:oauth:token-type:access_token"
        assert set(body.keys()) == {
            "access_token",
            "expires_in",
            "refresh_count",
            "refresh_token",
            "refresh_token_expires_in",
            "token_type",
            "issued_token_type"
        }

    @pytest.mark.errors
    @pytest.mark.parametrize(
        "expected_response,expected_status_code,missing_or_invalid,update_claims",
        [
            (  # Test invalid iss
                {
                    "error": "invalid_request",
                    "error_description": "Missing or non-matching iss/sub claims in JWT"
                },
                400,
                "invalid",
                {"iss": "invalid"}
            ),
            (  # Test missing iss
                {
                    "error": "invalid_request",
                    "error_description": "Missing or non-matching iss/sub claims in JWT"
                },
                400,
                "missing",
                {"iss"}
            ),
            (  # Test missing aud
                {
                    "error": "invalid_request",
                    "error_description": "Missing aud claim in JWT"
                },
                400,
                "missing",
                {"aud"}
            ),
            (  # Test missing exp
                {
                    "error": "invalid_request",
                    "error_description": "Missing exp claim in JWT"
                },
                400,
                "missing",
                {"exp"}
            ),
        ]
    )
    def test_token_exchange_nhs_login_subject_token_claims_errors(
        self,
        expected_response,
        expected_status_code,
        missing_or_invalid,
        update_claims,
        claims,
        _jwt_keys,
        nhsd_apim_proxy_url,
        nhs_login_id_token,
        token_data
    ):
        id_token_claims = nhs_login_id_token["claims"]
        id_token_headers = nhs_login_id_token["headers"]

        if missing_or_invalid == "missing":
            id_token_claims = remove_keys(id_token_claims, update_claims)
        if missing_or_invalid == "invalid":
            id_token_claims = replace_keys(id_token_claims, update_claims)

        token_data["subject_token"] = create_nhs_login_subject_token(id_token_claims, id_token_headers)
        token_data["client_assertion"] = create_client_assertion(claims, _jwt_keys["private_key_pem"])

        # When
        resp = requests.post(
            nhsd_apim_proxy_url + "/token",
            data=token_data
        )
        body = resp.json()

        # Then
        body = resp.json()
        assert resp.status_code == expected_status_code
        assert (
            "message_id" in body.keys()
        )  # We assert the key but not he value for message_id
        del body["message_id"]
        assert body == expected_response

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
    def test_userinfo_nhs_login_exchanged_token(
        self,
        _jwt_keys,
        nhsd_apim_proxy_url,
        claims,
        nhs_login_id_token,
        token_data
    ):
        id_token_claims = nhs_login_id_token["claims"]
        id_token_headers = nhs_login_id_token["headers"]

        token_data["subject_token"] = create_nhs_login_subject_token(id_token_claims, id_token_headers)
        token_data["client_assertion"] = create_client_assertion(claims, _jwt_keys["private_key_pem"])

        # When
        resp = requests.post(
            nhsd_apim_proxy_url + "/token",
            data=token_data
        )
        token_resp = resp.json()

        # Then
        token = token_resp["access_token"]
        user_info_resp = requests.get(
            nhsd_apim_proxy_url + '/userinfo',
            headers={"Authorization": f"Bearer {token}"}
        )
        assert user_info_resp.status_code == 400

        body = user_info_resp.json()
        assert (
            "message_id" in body.keys()
        )  # We assert the key but not he value for message_id
        del body["message_id"]
        assert body == {
            "error": "invalid_request",
            "error_description": "The Userinfo endpoint is only supported for Combined Auth integrations. " \
                                 "Currently this is only for NHS CIS2 authentications - for more guidance see " \
                                 "https://digital.nhs.uk/developer/guides-and-documentation/security-and" \
                                 "-authorisation/user-restricted-restful-apis-nhs-cis2-combined-authentication" \
                                 "-and-authorisation"
        }

    # ############# OAUTH TOKENS ###############

    @pytest.mark.simulated_auth
    @pytest.mark.token_exchange
    @pytest.mark.parametrize(
        "update_claims",
        [
            {"identity_proofing_level": "P0"},
            {"identity_proofing_level": "P5"},
            {"identity_proofing_level": "P9"}
        ]
    )
    def test_nhs_login_token_exchange_refresh_token(
        self,
        update_claims,
        claims,
        _jwt_keys,
        nhsd_apim_proxy_url,
        nhs_login_id_token,
        token_data,
        _test_app_credentials
    ):
        id_token_claims = replace_keys(nhs_login_id_token["claims"], update_claims)
        id_token_headers = nhs_login_id_token["headers"]

        token_data["subject_token"] = create_nhs_login_subject_token(id_token_claims, id_token_headers)
        token_data["client_assertion"] = create_client_assertion(claims, _jwt_keys["private_key_pem"])

        # When
        resp = requests.post(
            nhsd_apim_proxy_url + "/token",
            data=token_data
        )
        token_resp = resp.json()

        assert resp.status_code == 200
        assert token_resp['access_token']
        assert token_resp['refresh_token']
        assert token_resp['expires_in'] == '599'
        assert token_resp['refresh_token_expires_in'] == '3599'
        assert token_resp['issued_token_type'] == 'urn:ietf:params:oauth:token-type:access_token'

        resp = requests.post(
            nhsd_apim_proxy_url + "/token",
            data={
                "client_id": _test_app_credentials["consumerKey"],
                "client_secret": _test_app_credentials["consumerSecret"],
                "grant_type":  "refresh_token",
                "refresh_token": token_resp['refresh_token']
            },
            headers={"Content-Type": "application/x-www-form-urlencoded"}
        )
        refresh_resp = resp.json()

        assert resp.status_code == 200
        assert refresh_resp["expires_in"] == "599"
        assert refresh_resp["token_type"] == "Bearer"
        assert refresh_resp["refresh_count"] == "1"
        assert set(refresh_resp.keys()) == {
            "access_token",
            "expires_in",
            "refresh_count",
            "refresh_token",
            "refresh_token_expires_in",
            "token_type"
        }

    @pytest.mark.simulated_auth
    @pytest.mark.nhsd_apim_authorization(
        access="healthcare_worker",
        level="aal3",
        login_form={"username": "aal3"},
        authentication="separate",
        force_new_token=True
    )
    def test_cis2_token_exchange_access_tokens_valid(
        self,
        nhsd_apim_proxy_url,
        _create_function_scoped_test_app,
        _proxy_product_with_scope,
        _apigee_edge_session,
        _apigee_app_base_url,
        claims,
        _jwt_keys,
        token_data,
        cis2_subject_token_claims
    ):
        """
        Using a refresh token that was generated via token exchange, fetch and use
        a new access token, refresh token pair.
        """
        # Subscribe app to canary and identity service
        app = _create_function_scoped_test_app
        credential = app["credentials"][0]

        product_resp = subscribe_app_to_products(
            _apigee_edge_session,
            _apigee_app_base_url,
            credential,
            app["name"],
            [CANARY_PRODUCT_NAME, _proxy_product_with_scope["name"]]
        )
        assert product_resp.status_code == 200
        claims["sub"] = credential["consumerKey"]
        claims["iss"] = credential["consumerKey"]

        token_data["client_assertion"] = create_client_assertion(claims, _jwt_keys["private_key_pem"])
        token_data["subject_token"] = create_subject_token(cis2_subject_token_claims)

        # When
        resp = requests.post(
            nhsd_apim_proxy_url + "/token",
            data=token_data
        )

        body = resp.json()
        assert resp.status_code == 200
        token = body["access_token"]

        # Call Canary
        canary_resp = requests.get(
            CANARY_API_URL,
            headers={"Authorization": f"Bearer {token}"}
        )

        assert canary_resp.status_code == 200
        assert canary_resp.text == "Hello user!"

    @pytest.mark.simulated_auth
    @pytest.mark.nhsd_apim_authorization(
        access="patient",
        level="P0",
        login_form={"auth_method": "P0"},
        force_new_token=True
    )
    def test_nhs_login_token_exchange_access_tokens_valid(
        self,
        nhsd_apim_proxy_url,
        _create_function_scoped_test_app,
        _proxy_product_with_scope,
        _apigee_edge_session,
        _apigee_app_base_url,
        claims,
        _jwt_keys,
        token_data,
        nhs_login_id_token
    ):
        """
        Using a refresh token that was generated via token exchange, fetch and use
        a new access token, refresh token pair.
        """
        # Subscribe app to canary and identity service
        app = _create_function_scoped_test_app
        credential = app["credentials"][0]

        product_resp = subscribe_app_to_products(
            _apigee_edge_session,
            _apigee_app_base_url,
            credential,
            app["name"],
            [CANARY_PRODUCT_NAME, _proxy_product_with_scope["name"]]
        )
        assert product_resp.status_code == 200
        claims["sub"] = credential["consumerKey"]
        claims["iss"] = credential["consumerKey"]

        id_token_claims = nhs_login_id_token["claims"]
        id_token_headers = nhs_login_id_token["headers"]

        token_data["subject_token"] = create_nhs_login_subject_token(id_token_claims, id_token_headers)
        token_data["client_assertion"] = create_client_assertion(claims, _jwt_keys["private_key_pem"])

        # When
        resp = requests.post(
            nhsd_apim_proxy_url + "/token",
            data=token_data
        )

        body = resp.json()
        assert resp.status_code == 200
        token = body["access_token"]

        # Call Canary
        canary_resp = requests.get(
            CANARY_API_URL,
            headers={"Authorization": f"Bearer {token}"}
        )

        assert canary_resp.status_code == 200
        assert canary_resp.text == "Hello user!"

    @pytest.mark.simulated_auth
    @pytest.mark.token_exchange
    @pytest.mark.nhsd_apim_authorization(
        access="healthcare_worker",
        level="aal3",
        login_form={"username": "aal3"},
        authentication="separate",
        force_new_token=True
    )
    def test_cis2_token_exchange_refresh_token_become_invalid(
        self,
        nhsd_apim_proxy_url,
        _test_app_credentials,
        claims,
        _jwt_keys,
        cis2_subject_token_claims,
        token_data
    ):
        token_data["client_assertion"] = create_client_assertion(claims, _jwt_keys["private_key_pem"])
        token_data["subject_token"] = create_subject_token(cis2_subject_token_claims)

        # When
        resp = requests.post(
            nhsd_apim_proxy_url + "/token",
            data=token_data
        )
        token_resp = resp.json()

        assert resp.status_code == 200
        assert token_resp['access_token']
        assert token_resp['refresh_token']

        refresh_resp = requests.post(
            nhsd_apim_proxy_url + "/token",
            data={
                "client_id": _test_app_credentials["consumerKey"],
                "client_secret": _test_app_credentials["consumerSecret"],
                "grant_type":  "refresh_token",
                "refresh_token": token_resp["refresh_token"]
            },
            headers={"Content-Type": "application/x-www-form-urlencoded"}
        )
        refresh_body = refresh_resp.json()
        assert refresh_body["access_token"]
        assert refresh_body["refresh_token"]

        resp2 = requests.post(
            nhsd_apim_proxy_url + "/token",
            data={
                "client_id": _test_app_credentials["consumerKey"],
                "client_secret": _test_app_credentials["consumerSecret"],
                "grant_type":  "refresh_token",
                "refresh_token": token_resp["refresh_token"]
            },
            headers={"Content-Type": "application/x-www-form-urlencoded"}
        )
        body2 = resp2.json()

        assert resp2.status_code == 401
        assert (
            "message_id" in body2.keys()
        )  # We assert the key but not he value for message_id
        del body2["message_id"]
        assert body2 == {
            "error": "invalid_grant",
            "error_description": "refresh_token is invalid"
        }

    def test_rejects_token_request_by_password(
        self,
        nhsd_apim_proxy_url,
        _test_app_credentials,
    ):
        """
        Test that request for token using password grant type is rejected.
        """
        form_data = {
            "client_id": _test_app_credentials["consumerKey"],
            "client_secret": _test_app_credentials["consumerSecret"],
            "grant_type": "password",
            "username": "username",
            "password": "password"
        }
        resp = requests.post(
            nhsd_apim_proxy_url + "/token",
            data=form_data
        )
        body = resp.json()

        assert resp.status_code == 400
        assert (
            "message_id" in body.keys()
        )  # We assert the key but not he value for message_id
        del body["message_id"]
        assert body == {
            "error": "unsupported_grant_type",
            "error_description": "grant_type is invalid"
        }

    @pytest.mark.parametrize("token_expiry_ms, expected_time",
                             [(100000, 100), (500000, 500), (700000, 600), (1000000, 600)])
    async def test_access_token_override_with_client_credentials(self, token_expiry_ms, expected_time, cis2_subject_token_claims,
                                                                 _jwt_keys, nhsd_apim_proxy_url, claims):
        """
        Test client credential flow access token can be overridden with a time less than 10 min(600000ms or 600s)
        and NOT be overridden with a time greater than 10 min(600000ms or 600s)
        """
        client_assertion = jwt.encode(claims, _jwt_keys["private_key_pem"],
                                      algorithm="RS512",
                                      headers={'kid': 'test-1'})
        form_data = {
            "client_assertion_type": "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
            "client_assertion": client_assertion,
            "grant_type": 'client_credentials',
            "_access_token_expiry_ms": token_expiry_ms}
        response = requests.post(nhsd_apim_proxy_url + "/token", data=form_data)
        resp = response.json()

        assert response.status_code == 200
        assert int(resp['expires_in']) <= expected_time

    @pytest.mark.simulated_auth
    @pytest.mark.parametrize("token_expiry_ms, expected_time",
                             [(100000, 100), (500000, 500), (700000, 600), (1000000, 600)])
    async def test_access_token_override_with_token_exchange(self, token_expiry_ms, expected_time, _jwt_keys,
                                                             nhsd_apim_proxy_url, claims):
        """
        Test token exchange flow access token can be overridden with a time less than 10 min(600000ms or 600s)
        and NOT be overridden with a time greater than 10 min(600000ms or 600s)
        """
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
            'iat': int(time()) - 10,
            'exp': int(time()) + 600
        }

        client_assertion = jwt.encode(claims, _jwt_keys["private_key_pem"],
                                      algorithm="RS512",
                                      headers={'kid': 'test-1'})

        with open(config.ID_TOKEN_PRIVATE_KEY_ABSOLUTE_PATH, "r") as f:
            id_token_private_key = f.read()

        kid = "identity-service-tests-1"
        headers = ({}, {"kid": kid})[kid is not None]
        id_token_jwt = jwt.encode(id_token_claims, id_token_private_key, algorithm="RS512", headers=headers)

        form_data = {
            "grant_type": "urn:ietf:params:oauth:grant-type:token-exchange",
            "subject_token_type": "urn:ietf:params:oauth:token-type:id_token",
            "client_assertion_type": "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
            "subject_token": id_token_jwt,
            "client_assertion": client_assertion,
            "_access_token_expiry_ms": token_expiry_ms
        }

        response = requests.post(nhsd_apim_proxy_url + "/token", data=form_data)
        resp = response.json()

        assert response.status_code == 200
        assert int(resp['expires_in']) <= expected_time

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

    @pytest.mark.simulated_auth
    @pytest.mark.nhsd_apim_authorization(
        access="healthcare_worker",
        level="aal3",
        login_form={"username": "aal3"},
        authentication="separate",
        force_new_token=True
    )
    def test_cis2_refresh_tokens_generated_with_expected_expiry_separated_auth(
        self,
        _nhsd_apim_auth_token_data
    ):
        """
        Test that refresh tokens generated via CIS2 have an expiry time of 12 hours for separated authentication.
        """
        assert _nhsd_apim_auth_token_data['expires_in'] == '599'
        assert _nhsd_apim_auth_token_data['refresh_token_expires_in'] == '43199'

    # @pytest.mark.skip(reason="It is not feasible to run this test each build due to the timeframe required, "
    #                          "run manually if needed.")
    # async def test_cis2_refresh_token_expires_after_12_hours(self):
    #     """
    #     Test that a refresh token received via a CIS2 login is valid for up to 12 hours.
    #     Run pytest with the -s arg to display the stdout and show the wait time countdown.
    #     """
    #     # Generate access token using token-exchange
    #     id_token_jwt = self.oauth.create_id_token_jwt()
    #     client_assertion_jwt = self.oauth.create_jwt(kid='test-1')
    #     resp = await self.oauth.get_token_response(
    #         grant_type="token_exchange",
    #         _jwt=client_assertion_jwt,
    #         id_token_jwt=id_token_jwt
    #     )
    #
    #     refresh_token = resp['body']['refresh_token']
    #
    #     assert refresh_token
    #     assert resp['body']['expires_in'] == '599'
    #     assert resp['body']['refresh_token_expires_in'] == '43199'
    #
    #     # Wait 12 hours and check that the token has expired
    #     for remaining in range(43200, 0, -1):
    #         mins, sec = divmod(remaining, 60)
    #         hours, mins = divmod(mins, 60)
    #         sys.stdout.write("\r")
    #         sys.stdout.write("{:2d} hours {:2d} minutes {:2d} seconds remaining.".format(hours, mins, sec))
    #         sys.stdout.flush()
    #         sleep(1)
    #
    #     # Try to use the now expired refresh token to get another access token
    #     resp2 = await self.oauth.get_token_response(grant_type="refresh_token", refresh_token=refresh_token)
    #     print(resp2)
    #     assert resp2['status_code'] == 401

    # @pytest.mark.skip(reason="It is not feasible to run this test each build due to the timeframe required, "
    #                          "run manually if needed.")
    # @pytest.mark.parametrize('scope', ['P9', 'P5', 'P0'])
    # async def test_nhs_login_refresh_token_invalid_after_1_hour(self, scope):
    #     """
    #     Test that a refresh token received via a NHS Login is invalid after 1 hour (existing behaviour).
    #     Run pytest with the -s arg to display the stdout and show the wait time countdown.
    #     """
    #     id_token_claims = {
    #         "aud": "tf_-APIM-1",
    #         "id_status": "verified",
    #         "token_use": "id",
    #         "auth_time": 1616600683,
    #         "iss": "https://internal-dev.api.service.nhs.uk",
    #         "vot": "P9.Cp.Cd",
    #         "exp": int(time()) + 600,
    #         "iat": int(time()) - 10,
    #         "vtm": "https://auth.sandpit.signin.nhs.uk/trustmark/auth.sandpit.signin.nhs.uk",
    #         "jti": str(uuid4()),
    #         "identity_proofing_level": scope,
    #         "nhs_number": "900000000001"
    #     }
    #     id_token_headers = {
    #         "sub": "49f470a1-cc52-49b7-beba-0f9cec937c46",
    #         "aud": "APIM-1",
    #         "kid": "nhs-login",
    #         "iss": "https://internal-dev.api.service.nhs.uk",
    #         "typ": "JWT",
    #         "exp": 1616604574,
    #         "iat": 1616600974,
    #         "alg": "RS512",
    #         "jti": str(uuid4()),
    #     }
    #
    #     with open(ID_TOKEN_NHS_LOGIN_PRIVATE_KEY_ABSOLUTE_PATH, "r") as f:
    #         contents = f.read()
    #
    #     client_assertion_jwt = self.oauth.create_jwt(kid="test-1")
    #     id_token_jwt = self.oauth.create_id_token_jwt(
    #         algorithm="RS512",
    #         claims=id_token_claims,
    #         headers=id_token_headers,
    #         signing_key=contents,
    #     )
    #     resp = await self.oauth.get_token_response(
    #         grant_type="token_exchange",
    #         _jwt=client_assertion_jwt,
    #         id_token_jwt=id_token_jwt,
    #     )
    #     refresh_token = resp['body']['refresh_token']
    #
    #     assert refresh_token
    #     assert resp['body']['expires_in'] == '599'
    #     assert resp['body']['refresh_token_expires_in'] == '3599'
    #
    #     # Wait 1 hour (the previous refresh token expiry time) and check that the token is still valid
    #     for remaining in range(3600, 0, -1):
    #         mins, sec = divmod(remaining, 60)
    #         sys.stdout.write("\r")
    #         sys.stdout.write("{:2d} minutes {:2d} seconds remaining.".format(mins, sec))
    #         sleep(1)
    #
    #     # Get new access token using refresh token
    #     resp2 = await self.oauth.get_token_response(grant_type="refresh_token", refresh_token=refresh_token)
    #     assert resp2['status_code'] == 401
