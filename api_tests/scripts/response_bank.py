""" A repository bank which hold large bits of information in a dictionary format.
the keys are based on the name of tests to better identify what data belongs to which test."""

BANK = {
    'test_authorize_endpoint': {
        'response':
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
        'redirects': {
            0: {
                'status_code': 302,
                'url': 'https://internal-dev.api.service.nhs.uk/oauth2/authorize?'
                       'client_id=Too5BdPayTQACdw1AJK1rD4nKUD0Ag7J'
                       '&redirect_uri=https%3A%2F%2Fnhsd-apim-testing-internal-dev.herokuapp.com%2Fcallback'
                       '&response_type=code',
                'headers': {
                    'Location': 'https://am.nhsspit-2.ptl.nhsd-esa.net/openam/oauth2/realms/root/realms/oidc/authorize?'
                                'response_type=code&client_id=969567331415.apps.national'
                                '&redirect_uri=https://internal-dev.api.service.nhs.uk/oauth2/callback&scope=openid'
                }
                },
            1: {
                'status_code': 302,
                'url': 'https://am.nhsspit-2.ptl.nhsd-esa.net/openam/oauth2/realms/root/realms/oidc/authorize?'
                       'response_type=code&client_id=969567331415.apps.national&'
                       'redirect_uri=https://internal-dev.api.service.nhs.uk/oauth2/callback&scope=openid',
                'headers': {
                            'Location': 'https://am.nhsspit-2.ptl.nhsd-esa.net/openam/UI/Login?'
                                        'realm=%2Foidc&goto=https%3A%2F%2Fam.nhsspit-2.ptl.nhsd-esa.net%3A443%2Fopenam'
                                        '%2Foauth2%2Frealms%2Froot%2Frealms%2Foidc%2Fauthorize%3Fresponse_type'
                                        '%3Dcode%26client_id%3D969567331415.apps.national%26'
                                        'redirect_uri%3Dhttps%253A%252F%252Finternal-dev.api.service.nhs.uk'
                                        '%252Foauth2%252Fcallback%26scope%3Dopenid',
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
                                '%252Foauth2%252Fcallback%26scope%3Dopenid',
                }
            }
        }
    },
}
