import pytest


class TestAttachLoggingFields:
    """Test logging fields are attached as attributes to access tokens"""

    def get_token_details(self, token_data):
        token_attributes = {}
        for attribute in token_data["attributes"]:
            token_attributes[attribute["name"]] = attribute["value"]
        return token_attributes
    
    # We are on our second generation of mock identity provider for
    # healthcare_worker access (CIS2). This allows you to log-in using a
    # username.
    MOCK_CIS2_USERNAMES = {
     "aal1": ["656005750110"],
     "aal2": ["656005750109", "656005750111", "656005750112"],
     "aal3": ["656005750104", "656005750105", "656005750106"],
    }

    @pytest.mark.happy_path
    @pytest.mark.logging
    @pytest.mark.parametrize(
        ("expected_token_attributes"),
        [
            # User-restricted CIS2 combined aal3 & aal2
            pytest.param(
                {
                    "auth_type": "user",
                    "auth_grant_type": "authorization_code",
                    "auth_level": level,
                    "auth_provider": "apim-mock-nhs-cis2",
                    "auth_user_id": username,
                },
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
    )
    @pytest.mark.happy_path
    @pytest.mark.logging
    @pytest.mark.parametrize(
        ("expected_token_attributes"),
        [
            # User-restricted CIS2 seperate aal3 & aal2
            pytest.param(
                {
                    "auth_type": "user",
                    "auth_grant_type": "token_exchange",
                    "auth_level": level,
                    "auth_provider": "apim-mock-nhs-cis2",
                    "auth_user_id": username,
                },
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
    )
    @pytest.mark.happy_path
    @pytest.mark.logging
    @pytest.mark.parametrize(
        ("expected_token_attributes"),
        [
            # User-restricted NHS-login combined P0
            pytest.param(
                {
                    "auth_type": "user",
                    "auth_grant_type": "authorization_code",
                    "auth_level": "p0",
                    "auth_provider": "apim-mock-nhs-login",
                    "auth_user_id": "9912003073",
                },
                marks=pytest.mark.nhsd_apim_authorization(
                    access="patient",
                    level="P0",
                    login_form={"username": "9912003073"},
                    force_new_token=True,
                ),
            ),
            # User-restricted NHS-login combined P5
            pytest.param(
                {
                    "auth_type": "user",
                    "auth_grant_type": "authorization_code",
                    "auth_level": "p5",
                    "auth_provider": "apim-mock-nhs-login",
                    "auth_user_id": "9912003072",
                },
                marks=pytest.mark.nhsd_apim_authorization(
                    access="patient",
                    level="P5",
                    login_form={"username": "9912003072"},
                    force_new_token=True,
                ),
            ),
            # User-restricted NHS-login combined P9
            pytest.param(
                {
                    "auth_type": "user",
                    "auth_grant_type": "authorization_code",
                    "auth_level": "p9",
                    "auth_provider": "apim-mock-nhs-login",
                    "auth_user_id": "9912003071",
                },
                marks=pytest.mark.nhsd_apim_authorization(
                    access="patient",
                    level="P9",
                    login_form={"username": "9912003071"},
                    force_new_token=True,
                ),
            ),
            # User-restricted NHS-login separate P0
            pytest.param(
                {
                    "auth_type": "user",
                    "auth_grant_type": "token_exchange",
                    "auth_level": "p0",
                    "auth_provider": "apim-mock-nhs-login",
                    "auth_user_id": "9912003073",
                },
                marks=pytest.mark.nhsd_apim_authorization(
                    access="patient",
                    level="P0",
                    login_form={"username": "9912003073"},
                    authentication="separate",
                    force_new_token=True,
                ),
            ),
            # User-restricted NHS-login separate P5
            pytest.param(
                {
                    "auth_type": "user",
                    "auth_grant_type": "token_exchange",
                    "auth_level": "p5",
                    "auth_provider": "apim-mock-nhs-login",
                    "auth_user_id": "9912003072",
                },
                marks=pytest.mark.nhsd_apim_authorization(
                    access="patient",
                    level="P5",
                    login_form={"username": "9912003072"},
                    authentication="separate",
                    force_new_token=True,
                ),
            ),
            # User-restricted NHS-login separate P9
            pytest.param(
                {
                    "auth_type": "user",
                    "auth_grant_type": "token_exchange",
                    "auth_level": "p9",
                    "auth_provider": "apim-mock-nhs-login",
                    "auth_user_id": "9912003071",
                },
                marks=pytest.mark.nhsd_apim_authorization(
                    access="patient",
                    level="P9",
                    login_form={"username": "9912003071"},
                    authentication="separate",
                    force_new_token=True,
                ),
            ),
            # Application-restricted client_credentials
            pytest.param(
                {
                    "auth_type": "app",
                    "auth_grant_type": "client_credentials",
                    "auth_level": "level3",
                    "auth_provider": "apim",
                    "auth_user_id": "",
                },
                marks=pytest.mark.nhsd_apim_authorization(
                    access="application", level="level3", force_new_token=True
                ),
            ),
        ],
    )
    def test_access_token_fields_for_logging(
        self, _nhsd_apim_auth_token_data, access_token_api, expected_token_attributes
    ):
        access_token = _nhsd_apim_auth_token_data["access_token"]
        token_data = access_token_api.get_token_details(access_token)
        token_attributes = self.get_token_details(token_data)

        for attribute, _ in expected_token_attributes.items():
            assert token_attributes[attribute] == expected_token_attributes[attribute]