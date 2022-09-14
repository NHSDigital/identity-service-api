import pytest
from uuid import uuid4
from time import time
import requests
import jwt
from e2e.tests.oauth.utils.helpers import create_client_assertion


@pytest.fixture()
def set_jwks_resource_url(
    _apigee_edge_session, _apigee_app_base_url, _create_test_app, request
):

    mark = request.node.get_closest_marker("jwks_resource_url")
    if not mark or not mark.args:
        raise ValueError("Could not find pytest.mark.jwks_resource_url")
    new_jwks_resource_url = mark.args[0]

    url = _apigee_app_base_url + "/" + _create_test_app["name"] + "/attributes"
    get_resp = _apigee_edge_session.get(url + "/jwks-resource-url")
    original_jwks_resource_url = get_resp.json()["value"]

    if new_jwks_resource_url is not None:
        app_url = original_jwks_resource_url
        while app_url != new_jwks_resource_url:
            post_resp = _apigee_edge_session.post(
                url + "/jwks-resource-url",
                json={"name": "jwks-resource-url", "value": new_jwks_resource_url},
            )
            assert post_resp.json()["value"] == new_jwks_resource_url
            app_url = _apigee_edge_session.get(url + "/jwks-resource-url").json()[
                "value"
            ]
    else:
        delete_resp = _apigee_edge_session.delete(url + "/jwks-resource-url")
        assert delete_resp.status_code == 200
    yield

    jwks_attribute = {"name": "jwks-resource-url", "value": original_jwks_resource_url}
    if new_jwks_resource_url is not None:
        while app_url != original_jwks_resource_url:
            post_resp2 = _apigee_edge_session.post(
                url + "/jwks-resource-url", json=jwks_attribute
            )
            assert post_resp2.json()["value"] == original_jwks_resource_url
            app_url = _apigee_edge_session.get(url + "/jwks-resource-url").json()[
                "value"
            ]
    else:
        post_resp2 = _apigee_edge_session.post(
            url, json={"attribute": [jwks_attribute]}
        )
        assert jwks_attribute in post_resp2.json()["attribute"]


@pytest.fixture()
def claims(_test_app_credentials, nhsd_apim_proxy_url):
    claims = {
        "sub": _test_app_credentials["consumerKey"],
        "iss": _test_app_credentials["consumerKey"],
        "jti": str(uuid4()),
        "aud": nhsd_apim_proxy_url + "/token",
        "exp": int(time()) + 300,  # 5 minutes in the future
    }
    return claims


# Some of the following tests require to modify the test_app by the
# pytest-nhsd-apim module. Once the app is updated in apigee we still need to
# retry the test until the app changes propagates inside Apigee and the proxy
# can pick those changes so we simply rerun the test a sensible amount of times
# and hope it will pass.
@pytest.mark.flaky(reruns=60, reruns_delay=1)
class TestClientCredentialsJWT:
    """ A test suit to test the client credentials flow """

    @pytest.mark.happy_path
    @pytest.mark.nhsd_apim_authorization(
        access="application", level="level3", force_new_token=True
    )
    def test_successful_jwt_token_response(self, _nhsd_apim_auth_token_data):
        assert "access_token" in _nhsd_apim_auth_token_data.keys()
        assert "issued_at" in _nhsd_apim_auth_token_data.keys() # Added by pytest_nhsd_apim
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
        self, claims, nhsd_apim_proxy_url, _jwt_keys, algorithm
    ):
        expected_status_code = 400
        expected_response = {
            "error": "invalid_request",
            "error_description": "Invalid 'alg' header in JWT - unsupported JWT algorithm - must be 'RS512'",
        }
        additional_headers = {"kid": "test-1"}
        client_assertion = jwt.encode(
            claims,
            _jwt_keys["private_key_pem"],
            algorithm=algorithm,
            headers=additional_headers,
        )
        resp = requests.post(
            nhsd_apim_proxy_url + "/token",
            data={
                "client_assertion_type": "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
                "client_assertion": client_assertion,
                "grant_type": "client_credentials",
            },
        )
        body = resp.json()
        assert resp.status_code == expected_status_code
        assert (
            "message_id" in body.keys()
        )  # We assert the key but not he value for message_id
        del body["message_id"]
        assert body == expected_response

    @pytest.mark.errors
    @pytest.mark.parametrize(
        "expected_response,expected_status_code,replaced_claims",
        [
            (  # Test invalid sub and iss claims
                {
                    "error": "invalid_request",
                    "error_description": "Invalid iss/sub claims in JWT",
                },
                401,
                {"sub": "invalid", "iss": "invalid"},
            ),
            (
                # Test sub different to iss
                {
                    "error": "invalid_request",
                    "error_description": "Missing or non-matching iss/sub claims in JWT",
                },
                400,
                {"sub": "invalid"},
            ),
            (
                # Test iss different to sub
                {
                    "error": "invalid_request",
                    "error_description": "Missing or non-matching iss/sub claims in JWT",
                },
                400,
                {"iss": "invalid"},
            ),
            (
                # Test invalid jti
                {
                    "error": "invalid_request",
                    "error_description": "Failed to decode JWT",
                },
                400,
                {"jti": 1234567890},
            ),
            (
                # Test invalid aud
                {
                    "error": "invalid_request",
                    "error_description": "Missing or invalid aud claim in JWT",
                },
                401,
                {"aud": "invalid"},
            ),
            (
                # Test invalid exp
                {
                    "error": "invalid_request",
                    "error_description": "Failed to decode JWT",
                },
                400,
                {"exp": "invalid"},
            ),
            (
                # Test exp in the past
                {
                    "error": "invalid_request",
                    "error_description": "Invalid exp claim in JWT - JWT has expired",
                },
                400,
                {"exp": int(time()) - 20},
            ),
            (
                # Test exp above 5 min
                {
                    "error": "invalid_request",
                    "error_description": "Invalid exp claim in JWT - more than 5 minutes in future",
                },
                400,
                {"exp": int(time()) + 360},
            ),
        ],
    )
    def test_invalid_claims(
        self,
        claims,
        _jwt_keys,
        nhsd_apim_proxy_url,
        expected_response,
        expected_status_code,
        replaced_claims,
    ):
        claims = {**claims, **replaced_claims}
        additional_headers = {"kid": "test-1"}
        client_assertion = jwt.encode(
            claims,
            _jwt_keys["private_key_pem"],
            algorithm="RS512",
            headers=additional_headers,
        )
        resp = requests.post(
            nhsd_apim_proxy_url + "/token",
            data={
                "client_assertion_type": "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
                "client_assertion": client_assertion,
                "grant_type": "client_credentials",
            },
        )
        body = resp.json()
        assert resp.status_code == expected_status_code
        assert (
            "message_id" in body.keys()
        )  # We assert the key but not he value for message_id
        del body["message_id"]
        assert body == expected_response

    @pytest.mark.errors
    @pytest.mark.parametrize(
        "expected_response,expected_status_code,missing_claims",
        [
            (  # Test missing sub
                {
                    "error": "invalid_request",
                    "error_description": "Missing or non-matching iss/sub claims in JWT",
                },
                400,
                {"sub"},
            ),
            (  # Test missing iss
                {
                    "error": "invalid_request",
                    "error_description": "Missing or non-matching iss/sub claims in JWT",
                },
                400,
                {"iss"},
            ),
            (  # Test missing jti
                {
                    "error": "invalid_request",
                    "error_description": "Missing jti claim in JWT",
                },
                400,
                {"jti"},
            ),
            (  # Test missing aud
                {
                    "error": "invalid_request",
                    "error_description": "Missing or invalid aud claim in JWT",
                },
                401,
                {"aud"},
            ),
            (  # Test missing exp
                {
                    "error": "invalid_request",
                    "error_description": "Missing exp claim in JWT",
                },
                400,
                {"exp"},
            ),
        ],
    )
    def test_missing_claims(
        self,
        claims,
        _jwt_keys,
        nhsd_apim_proxy_url,
        expected_response,
        expected_status_code,
        missing_claims,
    ):
        for key in missing_claims:
            claims.pop(key)
        additional_headers = {"kid": "test-1"}
        client_assertion = jwt.encode(
            claims,
            _jwt_keys["private_key_pem"],
            algorithm="RS512",
            headers=additional_headers,
        )
        resp = requests.post(
            nhsd_apim_proxy_url + "/token",
            data={
                "client_assertion_type": "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
                "client_assertion": client_assertion,
                "grant_type": "client_credentials",
            },
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
    def test_reusing_same_jti(self, _jwt_keys, nhsd_apim_proxy_url, _test_app_credentials):
        claims = {
            "sub": _test_app_credentials["consumerKey"],
            "iss": _test_app_credentials["consumerKey"],
            "jti": '6cd46139-af51-4f78-b850-74fcdf70c75b',
            "aud": nhsd_apim_proxy_url + "/token",
            "exp": int(time()) + 300,  # 5 minutes in the future
        }
        additional_headers = {"kid": "test-1"}
        client_assertion = jwt.encode(
            claims,
            _jwt_keys["private_key_pem"],
            algorithm="RS512",
            headers=additional_headers,
        )
        resp = requests.post(
            nhsd_apim_proxy_url + "/token",
            data={
                "client_assertion_type": "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
                "client_assertion": client_assertion,
                "grant_type": "client_credentials",
            },
        )

        assert resp.status_code == 200

        resp = requests.post(
            nhsd_apim_proxy_url + "/token",
            data={
                "client_assertion_type": "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
                "client_assertion": client_assertion,
                "grant_type": "client_credentials",
            },
        )

        body = resp.json()
        assert (
            "message_id" in body.keys()
        )  # We assert the key but not he value for message_id
        del body["message_id"]
        assert body == {
            "error": "invalid_request",
            "error_description": "Non-unique jti claim in JWT",
        }

    @pytest.mark.errors
    @pytest.mark.parametrize(
        "expected_response,expected_status_code,data_override",
        [
            (  # Test invalid client_assertion_type
                {
                    "error": "invalid_request",
                    "error_description": "Missing or invalid client_assertion_type - "
                    "must be 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
                },
                400,
                {"client_assertion_type": "invalid"},
            ),
            (  # Test invalid client_assertion
                {
                    "error": "invalid_request",
                    "error_description": "Malformed JWT in client_assertion",
                },
                400,
                {"client_assertion": "invalid"},
            ),
            (  # Test invalid grant_type
                {
                    "error": "unsupported_grant_type",
                    "error_description": "grant_type is invalid",
                },
                400,
                {"grant_type": "invalid"},
            ),
        ],
    )
    def test_invalid_payload(
        self,
        claims,
        _jwt_keys,
        nhsd_apim_proxy_url,
        expected_response,
        expected_status_code,
        data_override,
    ):
        additional_headers = {"kid": "test-1"}
        client_assertion = jwt.encode(
            claims,
            _jwt_keys["private_key_pem"],
            algorithm="RS512",
            headers=additional_headers,
        )

        data = {
            "client_assertion_type": "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
            "client_assertion": client_assertion,
            "grant_type": "client_credentials",
        }

        data = {**data, **data_override}

        resp = requests.post(nhsd_apim_proxy_url + "/token", data=data)
        body = resp.json()
        assert resp.status_code == expected_status_code
        assert "message_id" in body.keys()
        del body["message_id"]  # We dont assert message_id as it is a random value.
        assert body == expected_response

    @pytest.mark.errors
    @pytest.mark.parametrize(
        "expected_response,expected_status_code,data_missing",
        [
            (  # Test missing client_assertion_type
                {
                    "error": "invalid_request",
                    "error_description": "Missing or invalid client_assertion_type - "
                    "must be 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
                },
                400,
                {"client_assertion_type"},
            ),
            (  # Test missing client_assertion_type
                {
                    "error": "invalid_request",
                    "error_description": "Missing client_assertion",
                },
                400,
                {"client_assertion"},
            ),
            (  # Test missing grant_type
                {
                    "error": "invalid_request",
                    "error_description": "grant_type is missing",
                },
                400,
                {"grant_type"},
            ),
        ],
    )
    def test_missing_data_in_payload(
        self,
        claims,
        _jwt_keys,
        nhsd_apim_proxy_url,
        expected_response,
        expected_status_code,
        data_missing,
    ):
        additional_headers = {"kid": "test-1"}
        client_assertion = jwt.encode(
            claims,
            _jwt_keys["private_key_pem"],
            algorithm="RS512",
            headers=additional_headers,
        )

        data = {
            "client_assertion_type": "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
            "client_assertion": client_assertion,
            "grant_type": "client_credentials",
        }
        for key in data_missing:
            data.pop(key)
        resp = requests.post(nhsd_apim_proxy_url + "/token", data=data)
        body = resp.json()
        assert resp.status_code == expected_status_code
        assert (
            "message_id" in body.keys()
        )  # We assert the key but not he value for message_id
        del body["message_id"]
        assert body == expected_response

    @pytest.mark.errors
    @pytest.mark.parametrize(
        "expected_response,expected_status_code,headers",
        [
            (  # Test invalid kid
                {
                    "error": "invalid_request",
                    "error_description": "Invalid 'kid' header in JWT - no matching public key",
                },
                401,
                {"kid": "invalid"},
            ),
            (  # Test missing kid
                {
                    "error": "invalid_request",
                    "error_description": "Missing 'kid' header in JWT",
                },
                400,
                {},
            ),
        ],
    )
    def test_kid(
        self,
        claims,
        _jwt_keys,
        nhsd_apim_proxy_url,
        expected_response,
        expected_status_code,
        headers,
    ):
        additional_headers = headers
        client_assertion = jwt.encode(
            claims,
            _jwt_keys["private_key_pem"],
            algorithm="RS512",
            headers=additional_headers,
        )

        data = {
            "client_assertion_type": "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
            "client_assertion": client_assertion,
            "grant_type": "client_credentials",
        }

        resp = requests.post(nhsd_apim_proxy_url + "/token", data=data)
        body = resp.json()
        assert resp.status_code == expected_status_code
        assert (
            "message_id" in body.keys()
        )  # We assert the key but not he value for message_id
        del body["message_id"]
        assert body == expected_response

    @pytest.mark.nhsd_apim_authorization(access="application", level="level3")
    def test_userinfo_client_credentials_token(
        self, nhsd_apim_proxy_url, nhsd_apim_auth_headers
    ):
        expected_status_code = 400
        expected_response = {
            "error": "invalid_request",
            "error_description": "The Userinfo endpoint is only supported for Combined Auth integrations. "
            "Currently this is only for NHS CIS2 authentications - for more guidance see "
            "https://digital.nhs.uk/developer/guides-and-documentation/security-and-authorisation/"
            "user-restricted-restful-apis-nhs-cis2-combined-authentication-and-authorisation",
        }
        resp = requests.get(
            nhsd_apim_proxy_url + "/userinfo", headers=nhsd_apim_auth_headers
        )
        body = resp.json()
        assert expected_status_code == resp.status_code
        assert (
            "message_id" in body.keys()
        )  # We assert the key but not he value for message_id
        del body["message_id"]
        assert body == expected_response

    @pytest.mark.nhsd_apim_authorization(
        access="application", level="level3", force_new_token=True
    )
    @pytest.mark.parametrize(
        "token_expiry_ms, expected_time",
        [
            (100000, 100),
            (500000, 500),
            (700000, 600),
            (1000000, 600)
        ]
    )
    def test_access_token_override_with_client_credentials(
        self,
        token_expiry_ms,
        expected_time,
        _jwt_keys,
        nhsd_apim_proxy_url,
        claims
    ):
        """
        Test client credential flow access token can be overridden with a time less than 10 min(600000ms or 600s)
        and NOT be overridden with a time greater than 10 min(600000ms or 600s)
        """
        client_assertion = create_client_assertion(claims, _jwt_keys["private_key_pem"])
        form_data = {
            "client_assertion_type": "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
            "client_assertion": client_assertion,
            "grant_type": 'client_credentials',
            "_access_token_expiry_ms": token_expiry_ms
        }
        response = requests.post(nhsd_apim_proxy_url + "/token", data=form_data)
        resp = response.json()

        assert response.status_code == 200
        assert int(resp['expires_in']) <= expected_time

    @pytest.mark.errors
    @pytest.mark.jwks_resource_url(None)
    def test_no_jwks_resource_url_set(
        self, set_jwks_resource_url, claims, _jwt_keys, nhsd_apim_proxy_url
    ):
        additional_headers = {"kid": "test-1"}
        client_assertion = jwt.encode(
            claims,
            _jwt_keys["private_key_pem"],
            algorithm="RS512",
            headers=additional_headers,
        )

        data = {
            "client_assertion_type": "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
            "client_assertion": client_assertion,
            "grant_type": "client_credentials",
        }
        resp = requests.post(nhsd_apim_proxy_url + "/token", data=data)
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
    @pytest.mark.jwks_resource_url("https://google.com")
    def test_invalid_jwks_resource_url(
        self, set_jwks_resource_url, claims, _jwt_keys, nhsd_apim_proxy_url
    ):
        additional_headers = {"kid": "test-1"}
        client_assertion = jwt.encode(
            claims,
            _jwt_keys["private_key_pem"],
            algorithm="RS512",
            headers=additional_headers,
        )

        data = {
            "client_assertion_type": "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
            "client_assertion": client_assertion,
            "grant_type": "client_credentials",
        }
        resp = requests.post(nhsd_apim_proxy_url + "/token", data=data)
        body = resp.json()
        assert resp.status_code == 403
        assert (
            "message_id" in body.keys()
        )  # We assert the key but not he value for message_id
        del body["message_id"]
        assert body == {
            "error": "public_key error",
            "error_description": "The JWKS endpoint, for your client_assertion can't be reached",
        }
