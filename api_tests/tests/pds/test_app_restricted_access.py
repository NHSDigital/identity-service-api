import pytest
from api_tests.config_files import config


@pytest.fixture()
def switch_to_application_restricted_app():
    config.CLIENT_ID = 'mOiQm5sRIbFZPQasHzfyM1my8eDjbG8T'
    config.CLIENT_SECRET = '76BGUtEGjhvezhAE'
    config.REDIRECT_URI = "https://example.com/callback"


@pytest.fixture()
def switch_to_user_restricted_app():
    config.CLIENT_ID = '3TAChuXI0LfR5Jr2OAxAVR7Ic2pcoWB1'
    config.CLIENT_SECRET = '2oC0lfMs0xhrAa2A'
    config.REDIRECT_URI = "https://example.com/callback"


@pytest.mark.usefixtures("setup")
class TestAppRestrictedAccessSuite:
    """ A test suite to confirm the ASID for a PDS request is behaving as expected """

    @pytest.mark.errors
    def test_patch_using_restricted_app(self, switch_to_application_restricted_app,
                                        get_token_with_extra_long_expiry_time):
        assert self.pds.check_patch_error_response(
            token=self.token,
            patient_id='5900023656',
            expected_response={
                'system': 'https://fhir.nhs.uk/R4/CodeSystem/Spine-ErrorOrWarningCode',
                'version': '1',
                'code': 'INVALID_SCOPE',
                'display': 'Access token has invalid scope for PATCH method',
                'diagnostics': 'Your app has insufficient permissions to use this method. Please contact support.',
                'error_resource_type': 'OperationOutcome',
                'status_code': 403
            }
        )

    @pytest.mark.happy_path
    def test_retrieve_request_using_restricted_app(self, switch_to_application_restricted_app,
                                                   get_token_with_extra_long_expiry_time):
        assert self.pds.check_retrieve_response_code(
            token=self.token,
            patient_id='5900023656',
            expected_status_code=200
        )

    @pytest.mark.happy_path
    def test_search_using_restricted_app(self, switch_to_application_restricted_app,
                                         get_token_with_extra_long_expiry_time):
        assert self.pds.check_search_response(
            token=self.token,
            search_params={'family': 'Parisian', 'gender': 'female', 'birthdate': '2003-10-23'},
            expected_patient_id=5900023656
        )

    @pytest.mark.errors
    def test_user_restricted_patch(self, switch_to_user_restricted_app, get_token_with_extra_long_expiry_time):
        assert self.pds.update_patient_gender(
            token=self.token,
            patient_id='5900023656'
        )

    @pytest.mark.happy_path
    def test_user_restricted_retrieve(self, switch_to_user_restricted_app, get_token_with_extra_long_expiry_time):
        assert self.pds.check_retrieve_response_code(
            token=self.token,
            patient_id='5900023656',
            expected_status_code=200
        )

    @pytest.mark.happy_path
    def test_user_restricted_search(self, switch_to_user_restricted_app, get_token_with_extra_long_expiry_time):
        assert self.pds.check_search_response(
            token=self.token,
            search_params={'family': 'Parisian', 'gender': 'female', 'birthdate': '2003-10-23'},
            expected_patient_id=5900023656
        )
