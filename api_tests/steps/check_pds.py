from api_tests.scripts.generic_request import GenericRequest
from api_tests.config_files import config
from api_tests.scripts.apigee_api import ApigeeDebugApi
from api_tests.scripts.pds_request import PdsRequest
from requests import Response


class CheckPds(GenericRequest):
    def __init__(self):
        super(CheckPds, self).__init__()

    def get_patient_response(self, patient_id: str, **kwargs) -> Response:
        """Send a Get request to retrieve a patient from PDS"""
        return self.get(f'{config.PDS_API}/{patient_id}', **kwargs)

    def check_asid_parameter(self, expected_status_code: int, expected_asid: list, patient_id: str, proxy: str,
                             **kwargs) -> bool:
        """Check the ASID param is behaving as expected"""
        # Start debug session
        debug_session = ApigeeDebugApi(proxy=proxy)

        # Send a request
        response = self.get_patient_response(patient_id, **kwargs)

        # Pull ASID from the request trace
        actual_asid = debug_session.get_asid()

        # Confirm ASID is correct
        assert actual_asid == expected_asid, f"Expected ASID: {expected_asid} but got: {actual_asid}"

        # Confirm response is correct
        assert self.check_status_code(response, expected_status_code), \
            f"UNEXPECTED RESPONSE {response.status_code}: {response.text}"
        return True

    @staticmethod
    def check_patch_error_response(token: str, patient_id: str, expected_response: dict):
        patient = PdsRequest(token, patient_id=patient_id, proxy="personal-demographics-pr-408")
        patient.patch_record(op='replace', path="/gender", value="male")
        assert patient.patched_record.get_error_details() == expected_response, \
            f"UNEXPECTED RESPONSE {patient.patched_record.status_code}: {patient.patched_record.response}"
        return True

    @staticmethod
    def check_patch_response_code(token: str, patient_id: str, op: str, path: str, value: str, expected_status_code):
        patient = PdsRequest(token, patient_id=patient_id, proxy="personal-demographics-pr-408")
        assert patient.patch_record(op, path, value) == expected_status_code, f"UNEXPECTED RESPONSE " \
                                                                              f"{patient.patched_record.status_code}:" \
                                                                              f" {patient.patched_record.response}"
        return True

    @staticmethod
    def check_search_response(token: str, search_params: dict, expected_patient_id: str or int):
        patient = PdsRequest(token, search_params=search_params, proxy="personal-demographics-pr-408")
        assert patient.record.records[0].id == str(expected_patient_id)
        return True

    @staticmethod
    def check_retrieve_response_code(token: str, patient_id: str, expected_status_code: int):
        # y = PdsRequest(patient_id, "5900018512", proxy="personal-demographics-pr-408") # sensitive
        # {'family':'Middleton', 'gender':'female', 'birthdate': '2000-01-01', 'given': 'Cynthia'}
        patient = PdsRequest(token, patient_id=patient_id, proxy="personal-demographics-pr-408")
        assert patient.record.status_code == expected_status_code, f"UNEXPECTED RESPONSE " \
                                                                   f"{patient.record.status_code}: " \
                                                                   f"{patient.record.response}"
        return True

    @staticmethod
    def update_patient_gender(token: str, patient_id: str):
        patient = PdsRequest(token, patient_id=patient_id, proxy="personal-demographics-pr-408")
        gender = ('male', 'female')[patient.record.gender == 'male']
        patient.patch_record(op='replace', path="/gender", value=gender)
        assert patient.patched_record.gender == gender, "Failed to update Patient gender"
        return True
