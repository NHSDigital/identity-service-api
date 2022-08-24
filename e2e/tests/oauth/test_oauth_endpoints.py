import pytest

from e2e.scripts.config import STATUS_ENDPOINT_API_KEY


@pytest.mark.asyncio
class TestOauthEndpoints:
    """ A test suit to verify all the oauth endpoints """

    async def test_ping(self, helper):
        assert await helper.send_request_and_check_output(
            expected_status_code=200,
            function=self.oauth.hit_oauth_endpoint,
            expected_response=["version", "revision", "releaseId", "commitId"],
            method="GET",
            endpoint="_ping",
        )

    @pytest.mark.parametrize("test_case", [
        {
            # Condition 1 Happy path
            "expected_status_code": 200,
            "expected_response": ["status", "version", "revision", "releaseId", "commitId", "checks"],
            "headers":{"apikey": f"{STATUS_ENDPOINT_API_KEY}"}
        },
        {
            # Condition 2 invalid api key
            "expected_status_code": 401,
            "expected_response": {
                "error": "Access Denied",
                "error_description": "Invalid api key for _status monitoring endpoint"
            },
            "headers": {"apikey": "invalid"}
        },
        {
            # Condition 3 invalid api key header
            "expected_status_code": 401,
            "expected_response": {
                "error": "Access Denied",
                "error_description": "Invalid api key for _status monitoring endpoint"
            },
            "headers": {"invalid": "invalid"}
        }
    ])
    async def test_status(self, helper, test_case):
        assert await helper.send_request_and_check_output(
            expected_status_code=test_case["expected_status_code"],
            function=self.oauth.hit_oauth_endpoint,
            expected_response=test_case["expected_response"],
            method="GET",
            endpoint="_status",
            headers=test_case["headers"]
        )
