import pytest
from api_tests.config_files import config
from api_tests.config_files.environments import ENV


@pytest.fixture()
def switch_to_invalid_asid_application():
    config.CLIENT_ID = ENV['oauth']['invalid_asic_client_id']
    config.CLIENT_SECRET = ENV['oauth']['invalid_asid_client_secret']
    config.REDIRECT_URI = ENV['oauth']['invalid_asid_redirect_uri']


@pytest.mark.usefixtures("setup")
class TestAsidSuite:
    """ A test suite to confirm the ASID for a PDS request is behaving as expected """

    @pytest.mark.apm_1275
    @pytest.mark.happy_path
    @pytest.mark.usefixtures('get_token')
    def test_missing_asid(self):
        """While missing the ASID parameter Apigee will auto assign a default ASID"""
        assert self.pds.check_asid_parameter(
            expected_status_code=200,
            expected_asid=["200000001115", None],
            patient_id="5900018512",
            headers={
                'Authorization': f'Bearer {self.token}',
                'NHSD-Session-URID': 'ROLD-ID',
                'X-Request-ID': "a7442c54-f13d-4fcd-8b8d-fa01ca857b42",
            })

    @pytest.mark.apm_1275
    @pytest.mark.errors
    def test_invalid_asid(self, switch_to_invalid_asid_application, get_token):
        assert self.pds.check_asid_parameter(
            expected_status_code=401,
            expected_asid=["1234", "1234"],
            patient_id="5900018512",
            headers={
                'Authorization': f'Bearer {self.token}',
                'NHSD-Session-URID': 'ROLD-ID',
                'X-Request-ID': "0b88035c-ecd1-4512-9882-0b38700879d1",
            })
