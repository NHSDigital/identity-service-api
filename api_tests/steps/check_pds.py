from api_tests.scripts.generic_request import GenericRequest
from api_tests.config_files import config
from api_tests.scripts.authenticator import Authenticator
from api_tests.scripts.apigee_api import ApigeeDebugApi


class CheckPds(GenericRequest):
    def __init__(self):
        super(CheckPds, self).__init__()

    def check_asid_parameter(self, verb: str, endpoint: str, expected_status_code: int, expected_asid: list, **kwargs):
        # Start debug session
        debug_session = ApigeeDebugApi(proxy="personal-demographics-internal-dev-apm-1275-asid-per-application")

        # Send a request
        response = self.get_response(verb, expected_status_code, endpoint, **kwargs)

        # Pull ASID from the request trace
        actual_asid = debug_session.get_asid()

        # Confirm ASID is correct
        assert actual_asid == expected_asid, f"Expected ASID: {expected_asid} but got: {actual_asid}"

        # Confirm response is correct
        return self.check_status_code(response, expected_status_code)
