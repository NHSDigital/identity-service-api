import pytest


@pytest.mark.skip(reason="Design Discussion Required")
@pytest.mark.usefixtures("setup")
class TestAsidSuite:
    """ A test suite to confirm the ASID for a PDS request is behaving as expected """

    @pytest.mark.apm_1276
    @pytest.mark.happy_path
    def test_app_with_valid_asid_where_asid_is_not_required(self, switch_to_valid_asid_application, get_token):
        assert self.pds.check_asid_parameter(
            expected_status_code=200,
            expected_asid=["200000001115", "200000001115"],
            patient_id="5900018512",
            proxy="personal-demographics-pr-387",
            headers={
                'Authorization': f'Bearer {self.token}',
                'NHSD-Session-URID': 'ROLD-ID',
                'X-Request-ID': "51b14696-6d9d-40aa-9efc-4d4c43544f63",
            })

    @pytest.mark.apm_1275
    @pytest.mark.apm_1276
    @pytest.mark.happy_path
    def test_app_without_asid_where_asid_is_not_required(self, switch_to_no_asid_application, get_token):
        """While missing the ASID parameter Apigee will auto assign a default ASID"""
        assert self.pds.check_asid_parameter(
            expected_status_code=200,
            expected_asid=["200000001115", None],
            patient_id="5900018512",
            proxy="personal-demographics-pr-387",
            headers={
                'Authorization': f'Bearer {self.token}',
                'NHSD-Session-URID': 'ROLD-ID',
                'X-Request-ID': "118ef935-8e7f-42f3-8c62-068d0069c3f1",
            })

    @pytest.mark.apm_1275
    @pytest.mark.errors
    def test_app_with_invalid_asid_where_asid_is_not_required(self, switch_to_invalid_asid_application, get_token):
        """While the application has an invalid ASID the response should error"""
        assert self.pds.check_asid_parameter(
            expected_status_code=401,
            expected_asid=["12345", "12345"],
            patient_id="5900018512",
            proxy="personal-demographics-pr-387",
            headers={
                'Authorization': f'Bearer {self.token}',
                'NHSD-Session-URID': 'ROLD-ID',
                'X-Request-ID': "7045513c-4673-435a-8486-2ba725d38798",
            })

    @pytest.mark.apm_1276
    @pytest.mark.happy_path
    def test_app_with_valid_asid_where_asid_is_required(self, switch_to_valid_asid_application,
                                                        switch_to_asid_required_proxy, get_token):
        assert self.pds.check_asid_parameter(
            expected_status_code=200,
            expected_asid=['200000001115', '200000001115', '200000001115'],
            patient_id="5900018512",
            proxy="personal-demographics-asid-required-pr-387",
            headers={
                'Authorization': f'Bearer {self.token}',
                'NHSD-Session-URID': 'ROLD-ID',
                'X-Request-ID': "46081ecd-50d4-4399-a2bf-9edc57da4137",
            })

    @pytest.mark.apm_1276
    @pytest.mark.errors
    def test_app_without_asid_where_asid_is_required(self, switch_to_asid_required_proxy, switch_to_no_asid_application,
                                                     get_token):
        """While missing the ASID parameter the response should error stating ASID is missing"""
        assert self.pds.check_asid_parameter(
            expected_status_code=400,
            expected_asid=[None],
            patient_id="5900018512",
            proxy="personal-demographics-asid-required-pr-387",
            headers={
                'Authorization': f'Bearer {self.token}',
                'NHSD-Session-URID': 'ROLD-ID',
                'X-Request-ID': "fac37ac8-c71e-4319-b13a-a1fb629c66e3",
            })

    @pytest.mark.apm_1275
    @pytest.mark.errors
    def test_app_with_invalid_asid_where_asid_is_required(self, switch_to_asid_required_proxy,
                                                          switch_to_invalid_asid_application, get_token):
        """While the application has an invalid ASID the response should error"""
        assert self.pds.check_asid_parameter(
            expected_status_code=401,
            expected_asid=["12345", "12345", "12345"],
            patient_id="5900018512",
            proxy="personal-demographics-asid-required-pr-387",
            headers={
                'Authorization': f'Bearer {self.token}',
                'NHSD-Session-URID': 'ROLD-ID',
                'X-Request-ID': "7045513c-4673-435a-8486-2ba725d38798",
            })
