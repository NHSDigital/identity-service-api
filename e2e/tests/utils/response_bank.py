""" A repository bank which hold large bits of information in a dictionary format.
the keys are based on the name of tests to better identify what data belongs to which test."""

BANK = {
    'test_userinfo': {
        'response': {
            "sub": "656005750104",
            "nhsid_useruid": "656005750104",
            "nhsid_org_memberships": [
                {
                    "person_orgid": "656008045105",
                    "org_name": "THE NORTH MIDLANDS AND EAST PROGRAMME FOR IT (NMEPFIT)",
                    "org_code": "Y51",
                    "gnc": "GNC123"
                },
                {
                    "person_orgid": "656005753107",
                    "org_name": "NHS CONNECTING FOR HEALTH",
                    "org_code": "X09"
                }
            ],
            "gdc_id": "GDC123",
            "initials": "S",
            "gmp_id": "GMP123",
            "consultant_id": "TestConsultant",
            "nhsid_org_roles": [
                {
                    "person_orgid": "656008045105",
                    "org_name": "THE NORTH MIDLANDS AND EAST PROGRAMME FOR IT (NMEPFIT)",
                    "org_code": "Y51"
                },
                {
                    "person_orgid": "656005753107",
                    "org_name": "NHS CONNECTING FOR HEALTH",
                    "org_code": "X09"
                }
            ],
            "title": "Mr",
            "gmc_id": "GMC123",
            "display_name": "Surekha RT cards",
            "given_name": "Test",
            "uid": "656005750104",
            "rcn_id": "RCN123",
            "nhsid_nrbac_roles": [
                {
                    "person_orgid": "656008045105",
                    "person_roleid": "656014452101",
                    "org_code": "Y51",
                    "role_name": "\"Support\":\"Support\":\"Admin/Clinical Support Access Role\"",
                    "role_code": "S8001:G8002:R8008",
                    "activities": [
                        "Execute CDS DQ Extracts (Clear)",
                        "Manage Shared Non Patient Identifiable Information",
                        "Run PbR Commissioning Extracts"
                    ],
                    "activity_codes": [
                        "B0145",
                        "B8002",
                        "B1560"
                    ]
                },
                {
                    "person_orgid": "656005753107",
                    "person_roleid": "656005754108",
                    "org_code": "X09",
                    "role_name": "\"Admin & Clerical\":\"Management - A & C\":\"Registration Authority Manager\"",
                    "role_code": "S0080:G0450:R5080",
                    "activities": [
                        "Receive Legal Override and Emergency View Alerts",
                        "Manage Allergies",
                        "Record a Patient's Self Referral",
                        "Receive SAR Refused Alerts"
                    ],
                    "activity_codes": [
                        "B0015",
                        "B0028",
                        "B0030",
                        "B0017"
                    ],
                    "workgroups": [
                        "AUG 2017 WKGP",
                        "CAR-384 One",
                        "chris irish 2",
                        "CAR-384"
                    ],
                    "workgroups_codes": [
                        "655694018104",
                        "555653110100",
                        "655681345103",
                        "555653032105"
                    ],
                    "aow": [
                        "\"Pathology\":\"Pathology\":\"Phlebotomy\"",
                        "\"Medicine\":\"Respiratory Medicine\":\"Respiratory Medicine\"",
                        "\"Pathology\":\"Pathology\":\"Pathology\"",
                        "\"Pathology\":\"Pathology\":\"Blood Transfusion\""
                    ],
                    "aow_codes": [
                        "P0020:Q0300:T0640",
                        "P0010:Q0050:T0210",
                        "P0020:Q0300:T0630",
                        "P0020:Q0300:T0660"
                    ]
                }
            ],
            "nhsid_user_orgs": [
                {
                    "org_name": "THE NORTH MIDLANDS AND EAST PROGRAMME FOR IT (NMEPFIT)",
                    "org_code": "Y51"
                },
                {
                    "org_name": "NHS CONNECTING FOR HEALTH",
                    "org_code": "X09"
                }
            ],
            "nmc_id": "NMC123",
            "middle_names": "Surekha",
            "name": "Test User",
            "idassurancelevel": "3",
            "family_name": "User",
            "email": "surekha.kommareddy@nhs.net",
            "gphc_id": "GPhC123",
            "gdp_id": "GDP123"
        }
    }
}
