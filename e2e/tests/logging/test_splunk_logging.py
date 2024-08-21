import pytest
import requests

from uuid import uuid4

from e2e.tests.utils.config import MOCK_CIS2_USERNAMES
from e2e.tests.utils.helpers import (
    create_client_assertion,
    create_subject_token,
    create_nhs_login_subject_token,
    get_auth_info,
    get_auth_item,
    get_variable_from_trace,
)


class TestSplunkLoggingFields:
    """Test suite for testing logging fields are sent to splunk"""
    # We are on our second generation of mock identity provider for
    # healthcare_worker access (CIS2). This allows you to log-in using a
    # username.

    # Create a list of pytest.param for each combination of username and level for combined auth
    combined_auth_params = [
        pytest.param(
           False, username, "apim-mock-nhs-cis2", level,
           marks=pytest.mark.nhsd_apim_authorization(
                access="healthcare_worker",
                level=level,
                login_form={"username": username},
                force_new_token=True,
            ),
        )
        for level, usernames in MOCK_CIS2_USERNAMES.items()
        for username in usernames
    ]

    # Create a list of pytest.param for each combination of username and level for separate auth
    separate_auth_params = [
        pytest.param(
            username, level,
            marks=pytest.mark.nhsd_apim_authorization(
                access="healthcare_worker",
                level=level,
                login_form={"username": username},
                authentication="separate",
                force_new_token=True,
            ),
        )
        for level, usernames in MOCK_CIS2_USERNAMES.items()
        for username in usernames
    ]

    @pytest.mark.happy_path
    @pytest.mark.logging
    @pytest.mark.parametrize(
        "is_nhs_login,username,provider,level", combined_auth_params +
        [
            pytest.param(
                True,
                "9912003071",
                "apim-mock-nhs-login",
                "P9",
                marks=pytest.mark.nhsd_apim_authorization(
                    access="patient",
                    level="P9",
                    login_form={"username": "9912003071"},
                    force_new_token=True,
                ),
            ),
        ]
    )
    def test_splunk_fields_for_authorize_endpoint(
        self,
        nhsd_apim_proxy_url,
        trace,
        authorize_params,
        is_nhs_login,
        username,
        provider,
        level
    ):
        session_name = str(uuid4())
        header_filters = {"trace_id": session_name}
        trace.post_debugsession(session=session_name, header_filters=header_filters)

        if is_nhs_login:
            authorize_params["scope"] = "nhs-login"

        get_auth_info(
            url=nhsd_apim_proxy_url + "/authorize",
            authorize_params=authorize_params,
            username=username,
            headers=header_filters,
        )

        payload = get_variable_from_trace(
            trace, session_name, "splunkCalloutRequest.content"
        )

        trace.delete_debugsession_by_name(session_name)

        auth = payload["auth"]
        auth_meta = auth["meta"]

        assert auth_meta["auth_type"] == "user"
        assert auth_meta["grant_type"] == "authorization_code"
        assert auth_meta["level"] == ""  # level is unknown when hitting /authorize

        assert auth_meta["provider"] == provider

        auth_user = auth["user"]
        assert auth_user["user_id"] == ""  # user_id is unknown when hitting /authorize

    @pytest.mark.happy_path
    @pytest.mark.logging
    @pytest.mark.parametrize(
        "is_nhs_login,username,provider,level", combined_auth_params +
        [
            # NHS Login
            pytest.param(
                True,
                "9912003071",
                "apim-mock-nhs-login",
                "p9",
                marks=pytest.mark.nhsd_apim_authorization(
                    access="patient",
                    level="P9",
                    login_form={"username": "9912003071"},
                    force_new_token=True,
                ),
            ),
        ]
    )
    def test_splunk_fields_for_callback_endpoint(
        self,
        nhsd_apim_proxy_url,
        trace,
        authorize_params,
        is_nhs_login,
        username,
        provider,
        level,
    ):
        session_name = str(uuid4())
        header_filters = {"trace_id": session_name}
        trace.post_debugsession(session=session_name, header_filters=header_filters)

        if is_nhs_login:
            authorize_params["scope"] = "nhs-login"

        # Make authorize request, which includes callback call
        get_auth_info(
            url=nhsd_apim_proxy_url + "/authorize",
            authorize_params=authorize_params,
            username=username,
            callback_headers=header_filters,
        )

        payload = get_variable_from_trace(
            trace, session_name, "splunkCalloutRequest.content"
        )

        trace.delete_debugsession_by_name(session_name)

        auth = payload["auth"]
        auth_meta = auth["meta"]

        assert auth_meta["auth_type"] == "user"
        assert auth_meta["grant_type"] == "authorization_code"
        assert auth_meta["level"] == level
        assert auth_meta["provider"] == provider

        auth_user = auth["user"]
        assert auth_user["user_id"] == username

    @pytest.mark.happy_path
    @pytest.mark.logging
    @pytest.mark.parametrize(
        "is_nhs_login,username,provider,level", combined_auth_params +
        [
            # NHS Login
            pytest.param(
                True,
                "9912003071",
                "apim-mock-nhs-login",
                "p9",
                marks=pytest.mark.nhsd_apim_authorization(
                    access="patient",
                    level="P9",
                    login_form={"username": "9912003071"},
                    force_new_token=True,
                ),
            ),
        ],
    )
    def test_splunk_fields_for_token_endpoint_authorization_code(
        self,
        nhsd_apim_proxy_url,
        trace,
        authorize_params,
        token_data_authorization_code,
        is_nhs_login,
        username,
        provider,
        level,
    ):
        if is_nhs_login:
            authorize_params["scope"] = "nhs-login"

        auth_info = get_auth_info(
            url=nhsd_apim_proxy_url + "/authorize",
            authorize_params=authorize_params,
            username=username,
        )
        token_data_authorization_code["code"] = get_auth_item(auth_info, "code")

        session_name = str(uuid4())
        header_filters = {"trace_id": session_name}
        trace.post_debugsession(session=session_name, header_filters=header_filters)

        resp = requests.post(
            nhsd_apim_proxy_url + "/token",
            headers={
                "Content-Type": "application/x-www-form-urlencoded",
                "trace_id": session_name,
            },
            data=token_data_authorization_code,
        )

        payload = get_variable_from_trace(
            trace, session_name, "splunkCalloutRequest.content"
        )

        trace.delete_debugsession_by_name(session_name)

        assert resp.status_code == 200

        auth = payload["auth"]
        auth_meta = auth["meta"]

        assert auth_meta["auth_type"] == "user"
        assert auth_meta["grant_type"] == "authorization_code"
        assert auth_meta["level"] == level

        assert auth_meta["provider"] == provider

        auth_user = auth["user"]
        assert auth_user["user_id"] == username

    @pytest.mark.happy_path
    @pytest.mark.logging
    @pytest.mark.nhsd_apim_authorization(
        access="application", level="level3", force_new_token=True
    )
    def test_splunk_fields_for_token_endpoint_client_credentials(
        self,
        nhsd_apim_proxy_url,
        trace,
        claims,
        token_data_client_credentials,
        _jwt_keys,
    ):
        token_data_client_credentials["client_assertion"] = create_client_assertion(
            claims, _jwt_keys["private_key_pem"]
        )
        session_name = str(uuid4())
        header_filters = {"trace_id": session_name}
        trace.post_debugsession(session=session_name, header_filters=header_filters)

        resp = requests.post(
            nhsd_apim_proxy_url + "/token",
            headers={
                "Content-Type": "application/x-www-form-urlencoded",
                "trace_id": session_name,
            },
            data=token_data_client_credentials,
        )

        payload = get_variable_from_trace(
            trace, session_name, "splunkCalloutRequest.content"
        )

        trace.delete_debugsession_by_name(session_name)

        assert resp.status_code == 200

        auth = payload["auth"]
        auth_meta = auth["meta"]

        assert auth_meta["auth_type"] == "app"
        assert auth_meta["grant_type"] == "client_credentials"
        assert auth_meta["level"] == "level3"
        assert auth_meta["provider"] == "apim"

        auth_user = auth["user"]
        assert auth_user["user_id"] == ""

    @pytest.mark.happy_path
    @pytest.mark.logging
    @pytest.mark.parametrize("username, level", separate_auth_params)
    def test_splunk_fields_for_token_endpoint_token_exchange_cis2(
        self,
        nhsd_apim_proxy_url,
        trace,
        claims,
        token_data_token_exchange,
        _jwt_keys,
        cis2_subject_token_claims,
        username,
        level
    ):
        token_data_token_exchange["client_assertion"] = create_client_assertion(
            claims, _jwt_keys["private_key_pem"]
        )
        token_data_token_exchange["subject_token"] = create_subject_token(
            cis2_subject_token_claims
        )

        session_name = str(uuid4())
        header_filters = {"trace_id": session_name}
        trace.post_debugsession(session=session_name, header_filters=header_filters)

        resp = requests.post(
            nhsd_apim_proxy_url + "/token",
            headers={
                "Content-Type": "application/x-www-form-urlencoded",
                "trace_id": session_name,
            },
            data=token_data_token_exchange,
        )

        payload = get_variable_from_trace(
            trace, session_name, "splunkCalloutRequest.content"
        )

        trace.delete_debugsession_by_name(session_name)

        assert resp.status_code == 200

        auth = payload["auth"]
        auth_meta = auth["meta"]

        assert auth_meta["auth_type"] == "user"
        assert auth_meta["grant_type"] == "token_exchange"
        assert auth_meta["level"] == "aal3"
        assert auth_meta["provider"] == "apim-mock-nhs-cis2"

        auth_user = auth["user"]
        assert auth_user["user_id"] == "787807429511"  # sub on subject-token claims

    @pytest.mark.happy_path
    @pytest.mark.logging
    @pytest.mark.nhsd_apim_authorization(
        access="patient",
        level="P9",
        login_form={"username": "9912003071"},
        authentication="separate",
        force_new_token=True,
    )
    def test_splunk_fields_for_token_endpoint_token_exchange_nhs_login(
        self,
        nhsd_apim_proxy_url,
        trace,
        claims,
        token_data_token_exchange,
        _jwt_keys,
        nhs_login_id_token,
    ):
        id_token_claims = nhs_login_id_token["claims"]
        id_token_headers = nhs_login_id_token["headers"]

        token_data_token_exchange["subject_token"] = create_nhs_login_subject_token(
            id_token_claims, id_token_headers
        )
        token_data_token_exchange["client_assertion"] = create_client_assertion(
            claims, _jwt_keys["private_key_pem"]
        )

        session_name = str(uuid4())
        header_filters = {"trace_id": session_name}
        trace.post_debugsession(session=session_name, header_filters=header_filters)

        resp = requests.post(
            nhsd_apim_proxy_url + "/token",
            headers={
                "Content-Type": "application/x-www-form-urlencoded",
                "trace_id": session_name,
            },
            data=token_data_token_exchange,
        )

        payload = get_variable_from_trace(
            trace, session_name, "splunkCalloutRequest.content"
        )

        trace.delete_debugsession_by_name(session_name)

        assert resp.status_code == 200

        auth = payload["auth"]
        auth_meta = auth["meta"]

        assert auth_meta["auth_type"] == "user"
        assert auth_meta["grant_type"] == "token_exchange"
        assert auth_meta["level"] == "p9"
        assert auth_meta["provider"] == "apim-mock-nhs-login"

        auth_user = auth["user"]
        assert auth_user["user_id"] == "9912003071"
