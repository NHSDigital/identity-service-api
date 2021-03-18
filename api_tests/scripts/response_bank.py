""" A repository bank which hold large bits of information in a dictionary format.
the keys are based on the name of tests to better identify what data belongs to which test."""
from api_tests.scripts import config

BANK = {
    'test_authorize_endpoint': {
        'response_nhs_identity':
            """
                <!DOCTYPE html>
                <!--
                 * The contents of this file are subject to the terms of the Common Development and
                 * Distribution License (the License). You may not use this file except in compliance with the
                 * License.
                 *
                 * You can obtain a copy of the License at legal/CDDLv1.0.txt. See the License for the
                 * specific language governing permission and limitations under the License.
                 *
                 * When distributing Covered Software, include this CDDL Header Notice in each file and include
                 * the License file at legal/CDDLv1.0.txt. If applicable, add the following below the CDDL
                 * Header, with the fields enclosed by brackets [] replaced by your own identifying
                 * information: "Portions copyright [year] [name of copyright owner]".
                 *
                 * Copyright 2012-2018 ForgeRock AS. All Rights Reserved
                -->
                <html>
                    <head>
                        <meta charset="utf-8">
                        <meta http-equiv="X-UA-Compatible" content="IE=edge">
                        <meta name="viewport" content="width=device-width, initial-scale=1">
                        <title>NHS Identity</title>
                    </head>
                    <!--[if IE 9]>
                    <body style="display:none" class="ie9">
                    <![endif]-->
                    <!--[if (gt IE 9)|!(IE)]><!-->
                    <body style="display:none">
                    <!--<![endif]-->
                        <div id="messages" class="clearfix"></div>
                        <div id="wrapper">Loading...</div>
                        <footer id="footer" class="footer text-muted"></footer>
                    <script type="text/javascript" src="main.966e6ff32d.js"></script></body>
                </html>
            """,
        'response':
            """
                <htmllang="en">
                    <head>
                       <metahttp-equiv="Content-Type"content="text/html;charset=UTF-8">
                       <metacharset="utf-8">
                       <metacontent="width=device-width,initial-scale=1,shrink-to-fit=no"name="viewport">
                       <linkcrossorigin="anonymous"
                       href="https://stackpath.bootstrapcdn.com/bootstrap/4.5.0/css/bootstrap.min.css"integrity="sha384-9aIt2nRpC12Uk9gS9baDl411NQApFmC26EwAOH8WgZl5MYYxFfc+NcPb1dKGj7Sk"rel="stylesheet">
                       <style>
                          html,body{height:100%;}body{display:-ms-flexbox;display:flex;-ms-flex-align:center;
                          align-items:center;padding-top:40px;padding-bottom:40px;
                          background-color:#f5f5f5;}.form-signin{width:100%;max-width:330px;padding:15px;margin:auto;}.form-signin.checkbox{font-weight:400;}.form-signin.form-control{position:relative;box-sizing:border-box;height:auto;padding:10px;font-size:16px;}.form-signin.form-control:focus{z-index:2;}.form-signininput[type="email"]{margin-bottom:-1px;border-bottom-right-radius:0;border-bottom-left-radius:0;}.form-signininput[type="password"]{margin-bottom:10px;border-top-left-radius:0;border-top-right-radius:0;}
                       </style>
                       <title>SimulatedLoginPage</title>
                    </head>
                    <bodyclass="text-center"><formclass="form-signin"method="post"><h1class="h3mb-3font-weight-normal">Simulatedloginpage</h1>
                    <p>ThisfacilitycanbeusedtodevelopyourOAuth2ClientApplicationwithoutneedingasmartcardandsmartcardreader.</p>
                    <p>Seeour<ahref="https://digital.nhs.uk/developer/guides-and-documentation/security-and-authorisation/user-restricted-restful-apis-nhs-identity-combined-authentication-and-authorisation">documentation</a>formoreinformation.</p>
                    <buttonclass="btnbtn-lgbtn-primarybtn-block"type="submit">Signin</button><pclass="mt-5mb-3text-muted">NHSDigital</p></form>
                    </body>
                </html>
            """,
        'redirects': {
            0: {
                'status_code': 302,
                'url': f'{config.OAUTH_BASE_URI}/authorize?'
                       'client_id=Too5BdPayTQACdw1AJK1rD4nKUD0Ag7J'
                       '&redirect_uri=https%3A%2F%2Fnhsd-apim-testing-internal-dev.herokuapp.com%2Fcallback'
                       '&response_type=code',
                'headers': {
                    'Location': f'{config.OAUTH_BASE_URI}/simulated_auth?response_type=code&client_id=some-client-id'
                                f'&redirect_uri={config.OAUTH_BASE_URI}/callback&scope=openid&prompt=login'
                }
                },
            1: {
                'status_code': 302,
                'url': 'https://am.nhsspit-2.ptl.nhsd-esa.net/openam/oauth2/realms/root/realms/oidc/authorize?'
                       'response_type=code&client_id=969567331415.apps.national&'
                       f'redirect_uri={config.OAUTH_BASE_URI}/callback&scope=openid',
                'headers': {
                            'Location': 'https://am.nhsspit-2.ptl.nhsd-esa.net/openam/UI/Login?'
                                        'realm=%2Foidc&goto=https%3A%2F%2Fam.nhsspit-2.ptl.nhsd-esa.net%3A443%2Fopenam'
                                        '%2Foauth2%2Frealms%2Froot%2Frealms%2Foidc%2Fauthorize%3Fresponse_type'
                                        '%3Dcode%26client_id%3D969567331415.apps.national%26'
                                        'redirect_uri%3Dhttps%253A%252F%252Finternal-dev.api.service.nhs.uk'
                                        '%252Foauth2%252Fcallback%26scope%3Dopenid%26prompt%3Dlogin',
                           }
            },
            2: {
                'status_code': 302,
                'url': 'https://am.nhsspit-2.ptl.nhsd-esa.net/openam/UI/Login?'
                       'realm=%2Foidc&goto=https%3A%2F%2Fam.nhsspit-2.ptl.nhsd-esa.net%3A443%2Fopenam%2Foauth2%2F'
                       'realms%2Froot%2Frealms%2Foidc%2Fauthorize%3Fresponse_type%3Dcode%26client_id%3D'
                       '969567331415.apps.national%26redirect_uri%3Dhttps%253A%252F%252F'
                       'internal-dev.api.service.nhs.uk%252Foauth2%252Fcallback%26scope%3Dopenid',
                'headers': {
                    'Location': '/openam/XUI/?realm=%2Foidc&goto=https%3A%2F%2Fam.nhsspit-2.ptl.nhsd-esa.net%3A443%2F'
                                'openam%2Foauth2%2Frealms%2Froot%2Frealms%2Foidc%2Fauthorize%3Fresponse_type%3Dcode'
                                '%26client_id%3D969567331415.apps.national%26'
                                'redirect_uri%3Dhttps%253A%252F%252Finternal-dev.api.service.nhs.uk'
                                '%252Foauth2%252Fcallback%26scope%3Dopenid%26prompt%3Dlogin',
                }
            }
        }
    },
    'test_userinfo': {
        'response': {
            "nhsid_useruid": "910000000001",
            "name": "USERQ RANDOM Mr",
            "nhsid_nrbac_roles": [
                {
                    "activities": [
                        "Perform Prescription Preparation",
                        "View Patient Medication",
                        "Amend Patient Demographics",
                        "Nurse Prescribers Formulary (NPF) Prescribing"
                    ],
                    "activity_codes": [
                        "B0278",
                        "B0401",
                        "B0825",
                        "B0058"
                    ],
                    "org_code": "RBA",
                    "person_orgid": "555254239107",
                    "person_roleid": "555254240100",
                    "role_code": "S8000:G8000:R8001",
                    "role_name": "\"Clinical\":\"Clinical Provision\":\"Nurse Access Role\""
                },
                {
                    "activities": [
                        "Manage Workgroups",
                        "Independent Prescribing",
                        "Execute CDS Extracts (NHS Group Pseud. Data)",
                        "Manage Workgroup Membership"
                    ],
                    "activity_codes": [
                        "B0100",
                        "B0420",
                        "B1510",
                        "B0090"
                    ],
                    "org_code": "RBA",
                    "person_orgid": "555254239107",
                    "person_roleid": "555254242102",
                    "role_code": "S8000:G8000:R8000",
                    "role_name": "\"Clinical\":\"Clinical Provision\":\"Clinical Practitioner Access Role\""
                },
                {
                    "activities": [
                        "Perform Pharmacy Activities",
                        "Verify Prescription",
                        "Manage Pharmacy Activities",
                        "View Patient Medication"
                    ],
                    "activity_codes": [
                        "B0570",
                        "B0068",
                        "B0572",
                        "B0401"
                    ],
                    "org_code": "RBA",
                    "person_orgid": "555254239107",
                    "person_roleid": "555254241101",
                    "role_code": "S8000:G8000:R8003",
                    "role_name": "\"Clinical\":\"Clinical Provision\":\"Health Professional Access Role\""
                },
                {
                    "activities": [
                        "Perform Pharmacy Activities",
                        "Verify Prescription",
                        "Manage Pharmacy Activities",
                        "View Patient Medication"
                    ],
                    "activity_codes": [
                        "B0570",
                        "B0068",
                        "B0572",
                        "B0401"
                    ],
                    "org_code": "RBA",
                    "person_orgid": "555254239107",
                    "person_roleid": "093895563513",
                    "role_code": "S8000:G8000:R8003",
                    "role_name": "\"Clinical\":\"Clinical Provision\":\"Health Professional Access Role\""
                }
            ],
            "sub": "910000000001"
        }
    }
}
