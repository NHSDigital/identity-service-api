import pytest
import requests

from time import time

from e2e.tests.utils.helpers import (
    change_jwks_url,
    create_client_assertion,
    remove_keys,
    replace_keys,
)


class TestClientCredentialsJWT:
    """A test suit to test the client credentials flow"""

    @pytest.mark.happy_path
    @pytest.mark.nhsd_apim_authorization(
        access="application", level="level3", force_new_token=True
    )
    def test_successful_jwt_token_response(self, _nhsd_apim_auth_token_data):
        assert "access_token" in _nhsd_apim_auth_token_data.keys()
        assert (
            "issued_at" in _nhsd_apim_auth_token_data.keys()
        )  # Added by pytest_nhsd_apim
        assert _nhsd_apim_auth_token_data["expires_in"] == "599"
        assert _nhsd_apim_auth_token_data["token_type"] == "Bearer"

    @pytest.mark.errors
    @pytest.mark.parametrize(
        "algorithm",
        [
            ("RS256"),
            ("RS384"),
            ("PS256"),
            ("PS384"),
            ("PS512"),
            ("HS256"),
            ("HS384"),
            ("HS512"),
        ],
    )
    def test_incorrect_jwt_algorithm(
        self,
        claims,
        nhsd_apim_proxy_url,
        _jwt_keys,
        token_data_client_credentials,
        algorithm,
    ):
        token_data_client_credentials["client_assertion"] = create_client_assertion(
            claims, _jwt_keys["private_key_pem"], algorithm=algorithm
        )

        resp = requests.post(
            nhsd_apim_proxy_url + "/token",
            data=token_data_client_credentials,
        )
        body = resp.json()

        assert resp.status_code == 400
        assert (
            "message_id" in body.keys()
        )  # We assert the key but not the value for message_id
        del body["message_id"]
        assert body == {
            "error": "invalid_request",
            "error_description": "Invalid 'alg' header in client_assertion JWT - unsupported JWT algorithm - must be 'RS512'",
        }

    @pytest.mark.errors
    @pytest.mark.parametrize(
        "expected_response,expected_status_code,missing_or_invalid,update_headers",
        [
            (  # Test missing kid
                {
                    "error": "invalid_request",
                    "error_description": "Missing 'kid' header in client_assertion JWT",
                },
                400,
                "missing",
                {"kid"},
            ),
            (  # Test invalid kid
                {
                    "error": "invalid_request",
                    "error_description": "Invalid 'kid' header in client_assertion JWT - no matching public key",
                },
                401,
                "invalid",
                {"kid": "invalid"},
            ),
            (  # Test invalid typ
                {
                    "error": "invalid_request",
                    "error_description": "Invalid 'typ' header in client_assertion JWT - must be 'JWT'",
                },
                400,
                "invalid",
                {"typ": "invalid"},
            ),
            (  # Test None typ
                {
                    "error": "invalid_request",
                    "error_description": "Invalid 'typ' header in client_assertion JWT - must be 'JWT'",
                },
                400,
                "invalid",
                {"typ": None},
            ),
            (  # Test invalid alg
                {
                    "error": "invalid_request",
                    "error_description": "Invalid 'alg' header in client_assertion JWT - unsupported JWT algorithm - must be 'RS512'",
                },
                400,
                "invalid",
                {"alg": "HS512"},
            ),
        ],
    )
    def test_missing_or_invalid_headers(
        self,
        claims,
        _jwt_keys,
        nhsd_apim_proxy_url,
        expected_response,
        expected_status_code,
        missing_or_invalid,
        update_headers,
        token_data_client_credentials,
    ):
        additional_headers = {"kid": "test-1", "alg": "RS512"}

        if missing_or_invalid == "missing":
            additional_headers = remove_keys(additional_headers, update_headers)
        if missing_or_invalid == "invalid":
            additional_headers = replace_keys(additional_headers, update_headers)

        token_data_client_credentials["client_assertion"] = create_client_assertion(
            claims, _jwt_keys["private_key_pem"], additional_headers=additional_headers
        )

        # When
        resp = requests.post(
            nhsd_apim_proxy_url + "/token", data=token_data_client_credentials
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
        "expected_response,expected_status_code,missing_or_invalid,replaced_claims",
        [
            (  # Test invalid sub and iss claims
                {
                    "error": "invalid_request",
                    "error_description": "Invalid 'iss'/'sub' claims in client_assertion JWT",
                },
                401,
                "invalid",
                {"sub": "invalid", "iss": "invalid"},
            ),
            (
                # Test sub different to iss
                {
                    "error": "invalid_request",
                    "error_description": "Missing or non-matching 'iss'/'sub' claims in client_assertion JWT",
                },
                400,
                "invalid",
                {"sub": "invalid"},
            ),
            (  # Test missing sub
                {
                    "error": "invalid_request",
                    "error_description": "Missing or non-matching 'iss'/'sub' claims in client_assertion JWT",
                },
                400,
                "missing",
                {"sub"},
            ),
            (
                # Test iss different to sub
                {
                    "error": "invalid_request",
                    "error_description": "Missing or non-matching 'iss'/'sub' claims in client_assertion JWT",
                },
                400,
                "invalid",
                {"iss": "invalid"},
            ),
            (  # Test missing iss
                {
                    "error": "invalid_request",
                    "error_description": "Missing or non-matching 'iss'/'sub' claims in client_assertion JWT",
                },
                400,
                "missing",
                {"iss"},
            ),
            (
                # Test invalid jti - integer
                {
                    "error": "invalid_request",
                    "error_description": "Invalid 'jti' claim in client_assertion JWT - must be a unique string value such as a GUID",
                },
                400,
                "invalid",
                {"jti": 1234567890},
            ),
            (  # Test missing jti
                {
                    "error": "invalid_request",
                    "error_description": "Missing 'jti' claim in client_assertion JWT",
                },
                400,
                "missing",
                {"jti"},
            ),
            (
                # Test invalid aud
                {
                    "error": "invalid_request",
                    "error_description": "Missing or invalid 'aud' claim in client_assertion JWT",
                },
                401,
                "invalid",
                {"aud": "invalid"},
            ),
            (  # Test missing aud
                {
                    "error": "invalid_request",
                    "error_description": "Missing or invalid 'aud' claim in client_assertion JWT",
                },
                401,
                "missing",
                {"aud"},
            ),
            (  # Test invalid exp - string
                {
                    "error": "invalid_request",
                    "error_description": "Invalid 'exp' claim in client_assertion JWT - must be an integer",
                },
                400,
                "invalid",
                {"exp": str(int(time()) + 300)},
            ),
            (
                # Test exp in the past
                {
                    "error": "invalid_request",
                    "error_description": "Invalid 'exp' claim in client_assertion JWT - JWT has expired",
                },
                400,
                "invalid",
                {"exp": int(time()) - 20},
            ),
            (
                # Test exp above 5 min
                {
                    "error": "invalid_request",
                    "error_description": "Invalid 'exp' claim in client_assertion JWT - more than 5 minutes in future",
                },
                400,
                "invalid",
                {"exp": int(time()) + 360},
            ),
            (  # Test missing exp
                {
                    "error": "invalid_request",
                    "error_description": "Missing 'exp' claim in client_assertion JWT",
                },
                400,
                "missing",
                {"exp"},
            ),
        ],
    )
    def test_missing_or_invalid_claims(
        self,
        claims,
        _jwt_keys,
        nhsd_apim_proxy_url,
        expected_response,
        expected_status_code,
        missing_or_invalid,
        replaced_claims,
        token_data_client_credentials,
    ):
        if missing_or_invalid == "missing":
            claims = remove_keys(claims, replaced_claims)
        if missing_or_invalid == "invalid":
            claims = replace_keys(claims, replaced_claims)

        token_data_client_credentials["client_assertion"] = create_client_assertion(
            claims, _jwt_keys["private_key_pem"]
        )

        resp = requests.post(
            nhsd_apim_proxy_url + "/token",
            data=token_data_client_credentials,
        )
        body = resp.json()

        assert resp.status_code == expected_status_code
        assert (
            "message_id" in body.keys()
        )  # We assert the key but not he value for message_id
        del body["message_id"]
        assert body == expected_response

    @pytest.mark.errors
    @pytest.mark.nhsd_apim_authorization(
        access="application", level="level3", force_new_token=True
    )
    def test_reusing_same_jti(
        self, _jwt_keys, nhsd_apim_proxy_url, claims, token_data_client_credentials
    ):
        token_data_client_credentials["client_assertion"] = create_client_assertion(
            claims, _jwt_keys["private_key_pem"]
        )

        resp = requests.post(
            nhsd_apim_proxy_url + "/token",
            data=token_data_client_credentials,
        )

        assert resp.status_code == 200

        resp = requests.post(
            nhsd_apim_proxy_url + "/token",
            data=token_data_client_credentials,
        )

        body = resp.json()
        assert (
            "message_id" in body.keys()
        )  # We assert the key but not he value for message_id
        del body["message_id"]
        assert body == {
            "error": "invalid_request",
            "error_description": "Non-unique 'jti' claim in client_assertion JWT",
        }

    @pytest.mark.errors
    @pytest.mark.parametrize(
        "expected_response,expected_status_code,missing_or_invalid,data_override",
        [
            (  # Test invalid client_assertion_type
                {
                    "error": "invalid_request",
                    "error_description": "Missing or invalid client_assertion_type - "
                    "must be 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer'",
                },
                400,
                "invalid",
                {"client_assertion_type": "invalid"},
            ),
            (  # Test missing client_assertion_type
                {
                    "error": "invalid_request",
                    "error_description": "Missing or invalid client_assertion_type - "
                    "must be 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer'",
                },
                400,
                "missing",
                {"client_assertion_type"},
            ),
            (  # Test invalid client_assertion
                {
                    "error": "invalid_request",
                    "error_description": "Malformed JWT in client_assertion",
                },
                400,
                "invalid",
                {"client_assertion": "invalid"},
            ),
            (  # Test missing client_assertion
                {
                    "error": "invalid_request",
                    "error_description": "Missing client_assertion",
                },
                400,
                "missing",
                {"client_assertion"},
            ),
            (  # Test invalid grant_type
                {
                    "error": "unsupported_grant_type",
                    "error_description": "grant_type is invalid",
                },
                400,
                "invalid",
                {"grant_type": "invalid"},
            ),
            (  # Test missing grant_type
                {
                    "error": "invalid_request",
                    "error_description": "grant_type is missing",
                },
                400,
                "missing",
                {"grant_type"},
            ),
        ],
    )
    def test_missing_or_invalid_payload(
        self,
        claims,
        _jwt_keys,
        nhsd_apim_proxy_url,
        token_data_client_credentials,
        expected_response,
        expected_status_code,
        missing_or_invalid,
        data_override,
    ):
        token_data_client_credentials["client_assertion"] = create_client_assertion(
            claims, _jwt_keys["private_key_pem"]
        )

        if missing_or_invalid == "missing":
            token_data_client_credentials = remove_keys(
                token_data_client_credentials, data_override
            )
        if missing_or_invalid == "invalid":
            token_data_client_credentials = replace_keys(
                token_data_client_credentials, data_override
            )

        resp = requests.post(
            nhsd_apim_proxy_url + "/token", data=token_data_client_credentials
        )
        body = resp.json()
        assert resp.status_code == expected_status_code
        assert "message_id" in body.keys()
        del body["message_id"]  # We dont assert message_id as it is a random value.
        assert body == expected_response

    @pytest.mark.nhsd_apim_authorization(access="application", level="level3")
    def test_userinfo_client_credentials_token(
        self, nhsd_apim_proxy_url, nhsd_apim_auth_headers
    ):
        resp = requests.get(
            nhsd_apim_proxy_url + "/userinfo", headers=nhsd_apim_auth_headers
        )
        body = resp.json()

        assert resp.status_code == 400
        assert (
            "message_id" in body.keys()
        )  # We assert the key but not he value for message_id
        del body["message_id"]
        assert body == {
            "error": "invalid_request",
            "error_description": "The Userinfo endpoint is only supported for Combined Auth integrations. "
            "Currently this is only for NHS CIS2 authentications - for more guidance see "
            "https://digital.nhs.uk/developer/guides-and-documentation/security-and-authorisation/"
            "user-restricted-restful-apis-nhs-cis2-combined-authentication-and-authorisation",
        }

    @pytest.mark.nhsd_apim_authorization(
        access="application", level="level3", force_new_token=True
    )
    @pytest.mark.parametrize(
        "token_expiry_ms, expected_time",
        [(100000, 100), (500000, 500), (700000, 600), (1000000, 600)],
    )
    def test_access_token_override_with_client_credentials(
        self,
        token_expiry_ms,
        expected_time,
        _jwt_keys,
        nhsd_apim_proxy_url,
        claims,
        token_data_client_credentials,
    ):
        """
        Test client credential flow access token can be overridden with a time less than 10 min(600000ms or 600s)
        and NOT be overridden with a time greater than 10 min(600000ms or 600s)
        """
        token_data_client_credentials["client_assertion"] = create_client_assertion(
            claims, _jwt_keys["private_key_pem"]
        )
        token_data_client_credentials["_access_token_expiry_ms"] = token_expiry_ms

        response = requests.post(
            nhsd_apim_proxy_url + "/token", data=token_data_client_credentials
        )
        resp = response.json()

        assert response.status_code == 200
        assert int(resp["expires_in"]) <= expected_time

    @pytest.mark.errors
    def test_no_jwks_resource_url_set(
        self,
        claims,
        _jwt_keys,
        nhsd_apim_proxy_url,
        _apigee_edge_session,
        _apigee_app_base_url,
        _create_function_scoped_test_app,
        token_data_client_credentials,
    ):
        app = _create_function_scoped_test_app
        credential = app["credentials"][0]
        claims["sub"] = credential["consumerKey"]
        claims["iss"] = credential["consumerKey"]

        jwks_resp = change_jwks_url(
            _apigee_edge_session,
            _apigee_app_base_url,
            _create_function_scoped_test_app,
            should_remove=True,
        )
        assert jwks_resp.status_code == 200

        token_data_client_credentials["client_assertion"] = create_client_assertion(
            claims, _jwt_keys["private_key_pem"]
        )

        resp = requests.post(
            nhsd_apim_proxy_url + "/token", data=token_data_client_credentials
        )
        body = resp.json()
        assert resp.status_code == 403
        assert (
            "message_id" in body.keys()
        )  # We assert the key but not he value for message_id
        del body["message_id"]
        assert body == {
            "error": "public_key error",
            "error_description": "You need to register a public key to use this authentication method"
            " - please contact support to configure",
        }

    @pytest.mark.errors
    @pytest.mark.parametrize(
        "jwks_resource_url, expected_status_code, expected_error_body",
        [
            (
                # This url will fail cause it does not have a forward slash at the end...
                "https://google.com",
                403,
                {
                    "error": "public_key error",
                    "error_description": "The JWKS endpoint, for your client_assertion can't be reached",
                },
            ),
            (
                # Change the rerource url to an existing key that does not matches the test_app private key.
                "https://raw.githubusercontent.com/NHSDigital/identity-service-jwks/main/jwks/internal-dev/9baed6f4-1361-4a8e-8531-1f8426e3aba8.json",
                401,
                {
                    "error": "public_key error",
                    "error_description": "JWT signature verification failed",
                },
            ),
        ],
    )
    def test_invalid_jwks_resource_url(
        self,
        claims,
        _jwt_keys,
        nhsd_apim_proxy_url,
        _apigee_edge_session,
        _apigee_app_base_url,
        _create_function_scoped_test_app,
        token_data_client_credentials,
        jwks_resource_url,
        expected_status_code,
        expected_error_body,
    ):
        app = _create_function_scoped_test_app
        credential = app["credentials"][0]
        claims["sub"] = credential["consumerKey"]
        claims["iss"] = credential["consumerKey"]

        jwks_resp = change_jwks_url(
            _apigee_edge_session,
            _apigee_app_base_url,
            _create_function_scoped_test_app,
            new_jwks_resource_url=jwks_resource_url,
        )
        assert jwks_resp.status_code == 200

        token_data_client_credentials["client_assertion"] = create_client_assertion(
            claims, _jwt_keys["private_key_pem"]
        )

        resp = requests.post(
            nhsd_apim_proxy_url + "/token", data=token_data_client_credentials
        )
        body = resp.json()
        assert resp.status_code == expected_status_code
        assert (
            "message_id" in body.keys()
        )  # We assert the key but not he value for message_id
        del body["message_id"]
        assert body == expected_error_body
