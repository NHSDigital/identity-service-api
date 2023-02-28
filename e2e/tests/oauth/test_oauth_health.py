import pytest
import requests


class TestOauthHealth:
    """A test suit to check the identity service health endpoint"""

    @pytest.mark.smoke
    def test_ping(self, nhsd_apim_proxy_url):
        resp = requests.get(f"{nhsd_apim_proxy_url}/_ping")
        assert resp.status_code == 200

        body = resp.json()
        assert sorted(body.keys()) == sorted(
            ["version", "revision", "releaseId", "commitId"]
        )

    @pytest.mark.smoke
    def test_status(self, nhsd_apim_proxy_url, status_endpoint_auth_headers):
        resp = requests.get(
            f"{nhsd_apim_proxy_url}/_status", headers=status_endpoint_auth_headers
        )
        assert resp.status_code == 200

        body = resp.json()
        assert body["status"] == "pass"
        assert sorted(body.keys()) == sorted(
            ["status", "version", "revision", "releaseId", "commitId", "checks"]
        )
        assert body["checks"]["nhs-cis2"]["status"] == "pass"
        assert body["checks"]["nhs-login"]["status"] == "pass"

    @pytest.mark.smoke
    @pytest.mark.parametrize("headers", [{"apikey": "invalid"}, {"invalid": "invalid"}])
    def test_status_errors(self, nhsd_apim_proxy_url, headers):
        resp = requests.get(f"{nhsd_apim_proxy_url}/_status", headers=headers)
        assert resp.status_code == 401

        body = resp.json()
        assert (
            "message_id" in body.keys()
        )  # We assert the key but not he value for message_id
        del body["message_id"]
        assert body == {
            "error": "Access Denied",
            "error_description": "Invalid api key for _status monitoring endpoint",
        }
