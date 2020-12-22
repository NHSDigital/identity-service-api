import pytest


@pytest.mark.usefixtures("setup")
class TestAppRestrictedAccessSuite:
    """ A test suite to confirm the ASID for a PDS request is behaving as expected """

    @pytest.mark.errors
    @pytest.mark.usefixtures('get_token_using_jwt')
    def test_patch_using_restricted_app(self):
        assert self.pds.check_patch_error_response(
            token=self.jwt_signed_token,
            patient_id='5900023656',
            expected_response={
                'system': 'https://fhir.nhs.uk/R4/CodeSystem/Spine-ErrorOrWarningCode',
                'version': '1',
                'code': 'INVALID_METHOD',
                'display': 'Cannot update resource with Application-Restricted access token',
                'diagnostics': 'Your app has insufficient permissions to use this method. Please contact support.',
                'error_resource_type': 'OperationOutcome',
                'status_code': 403
            }
        )

    @pytest.mark.happy_path
    @pytest.mark.usefixtures('get_token_using_jwt')
    def test_retrieve_request_using_restricted_app(self):
        assert self.pds.check_retrieve_response_code(
            token=self.jwt_signed_token,
            patient_id='5900023656',
            expected_status_code=200
        )

    @pytest.mark.happy_path
    @pytest.mark.usefixtures('get_token_using_jwt')
    def test_search_using_restricted_app(self):
        assert self.pds.check_search_response(
            token=self.jwt_signed_token,
            search_params={'family': 'Parisian', 'gender': 'female', 'birthdate': '2003-10-23'},
            expected_patient_id=5900023656
        )

    @pytest.mark.errors
    @pytest.mark.skip('Waiting for automated apps')
    def test_user_restricted_patch(self, get_token_with_extra_long_expiry_time):
        assert self.pds.update_patient_gender(
            token=self.token,
            patient_id='5900023656'
        )

    @pytest.mark.happy_path
    @pytest.mark.skip('Waiting for automated apps')
    def test_user_restricted_retrieve(self, get_token_with_extra_long_expiry_time):
        assert self.pds.check_retrieve_response_code(
            token=self.token,
            patient_id='5900023656',
            expected_status_code=200
        )

    @pytest.mark.happy_path
    @pytest.mark.skip('Waiting for automated apps')
    def test_user_restricted_search(self, get_token_with_extra_long_expiry_time):
        assert self.pds.check_search_response(
            token=self.token,
            search_params={'family': 'Parisian', 'gender': 'female', 'birthdate': '2003-10-23'},
            expected_patient_id=5900023656
        )
