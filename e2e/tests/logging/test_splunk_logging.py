import pytest
import requests
import json

from lxml import html
from urllib.parse import urlparse, parse_qs
from uuid import uuid4


# TO DO - shared with test_authorization_code tests. Move out to shared file
def get_auth_info(url, authorize_params, username):
    # Log in to Keycloak and get code
    session = requests.Session()
    resp = session.get(
        url=url,
        params=authorize_params,
        verify=False
    )

    tree = html.fromstring(resp.content.decode())

    form = tree.get_element_by_id("kc-form-login")
    url = form.action
    resp2 = session.post(url, data={"username": username})

    return urlparse(resp2.history[-1].headers["Location"]).query


# TO DO - shared with test_authorization_code tests. Move out to shared file
def get_auth_item(auth_info, item):
    auth_item = parse_qs(auth_info)[item]
    if isinstance(auth_item, list):
        auth_item = auth_item[0]

    return auth_item


def get_payload_sent_to_splunk(debug, session_name, path_suffix):
    trace_ids = debug.get_transaction_data(session_name=session_name)
    for trace_id in trace_ids:
        trace_data = debug.get_transaction_data_by_id(
            session_name=session_name, transaction_id=trace_id
        )

        for data in trace_data["point"]:
            if data["id"] == "FlowInfo":
                for result in data["results"]:
                    if result["ActionResult"] == "DebugInfo":
                        for property in result["properties"]["property"]:
                            if property["name"] == "proxy.pathsuffix" and property["value"] == path_suffix:
                                target_trace_data = trace_data
    
    if not target_trace_data:
        raise Exception(f"Could not find trace data for {path_suffix}")

    payload = debug.get_apigee_variable_from_trace(
        name="splunkCalloutRequest.content", data=target_trace_data
    )

    return json.loads(payload)

@pytest.mark.mock_auth
class TestSplunkLoggingFields:
    @pytest.mark.happy_path
    @pytest.mark.logging
    def test_splunk_fields_for_authorize_endpoint_for_cis2(
        self,
        nhsd_apim_proxy_url,
        trace,
        authorize_params
    ):
        session_name = str(uuid4())
        trace.post_debugsession(session_name)

        get_auth_info(
            url=nhsd_apim_proxy_url + "/authorize",
            authorize_params=authorize_params,
            username="656005750104"
        )

        payload = get_payload_sent_to_splunk(trace, session_name, "/authorize")
        auth = payload["auth"]
        auth_meta = auth["meta"]

        assert auth_meta["auth_type"] == "user"
        assert auth_meta["grant_type"] == "authorization_code"
        assert auth_meta["level"] == ""  # level is unknown when hitting /authorize
        assert auth_meta["provider"] == "apim-mock-nhs-cis2"

        auth_user = auth["user"]
        assert auth_user["user_id"] == ""  # user_id is unknown when hitting /authorize

    @pytest.mark.happy_path
    @pytest.mark.logging
    def test_splunk_fields_for_callback_endpoint_for_cis2(
        self,
        nhsd_apim_proxy_url,
        trace,
        authorize_params
    ):
        session_name = str(uuid4())
        trace.post_debugsession(session_name)

        # Make authorize request, which includes callback call
        get_auth_info(
            url=nhsd_apim_proxy_url + "/authorize",
            authorize_params=authorize_params,
            username="656005750104"
        )

        payload = get_payload_sent_to_splunk(trace, session_name, "/callback")
        auth = payload["auth"]
        auth_meta = auth["meta"]

        assert auth_meta["auth_type"] == "user"
        assert auth_meta["grant_type"] == "authorization_code"
        assert auth_meta["level"] == "aal3"
        assert auth_meta["provider"] == "apim-mock-nhs-cis2"

        auth_user = auth["user"]
        assert auth_user["user_id"] == "656005750104"

    @pytest.mark.happy_path
    @pytest.mark.logging
    def test_splunk_fields_for_authorize_endpoint_for_nhs_login(
        self,
        nhsd_apim_proxy_url,
        trace,
        authorize_params
    ):
        session_name = str(uuid4())
        trace.post_debugsession(session_name)

        authorize_params["scope"] = "nhs-login"

        get_auth_info(
            url=nhsd_apim_proxy_url + "/authorize",
            authorize_params=authorize_params,
            username="9912003071"
        )

        payload = get_payload_sent_to_splunk(trace, session_name, "/authorize")
        auth = payload["auth"]
        auth_meta = auth["meta"]

        assert auth_meta["auth_type"] == "user"
        assert auth_meta["grant_type"] == "authorization_code"
        assert auth_meta["level"] == ""  # level is unknown when hitting /authorize
        assert auth_meta["provider"] == "apim-mock-nhs-login"

        auth_user = auth["user"]
        assert auth_user["user_id"] == ""  # user_id is unknown when hitting /authorize


    @pytest.mark.happy_path
    @pytest.mark.logging
    def test_splunk_fields_for_callback_endpoint_for_nhs_login(
        self,
        nhsd_apim_proxy_url,
        trace,
        authorize_params
    ):
        session_name = str(uuid4())
        trace.post_debugsession(session_name)

        authorize_params["scope"] = "nhs-login"

        # Make authorize request, which includes callback call
        get_auth_info(
            url=nhsd_apim_proxy_url + "/authorize",
            authorize_params=authorize_params,
            username="9912003071"
        )

        payload = get_payload_sent_to_splunk(trace, session_name, "/callback")
        auth = payload["auth"]
        auth_meta = auth["meta"]

        assert auth_meta["auth_type"] == "user"
        assert auth_meta["grant_type"] == "authorization_code"
        assert auth_meta["level"] == "p9"
        assert auth_meta["provider"] == "apim-mock-nhs-login"

        auth_user = auth["user"]
        assert auth_user["user_id"] == "9912003071"
