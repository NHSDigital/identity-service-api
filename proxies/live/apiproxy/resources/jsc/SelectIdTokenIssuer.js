var issuer = context.getVariable('jwt.DecodeJWT.FromSubjectTokenFormParam.decoded.claim.iss');
var nhsCis2 = new RegExp("(NHSIdentity)");
var nhsLogin = new RegExp("(signin.nhs.uk)");
var matchNhsCis2 = nhsCis2.exec(issuer);
var matchNhsLogin = nhsLogin.exec(issuer);
var idTokenIssuer = ''


if (matchNhsCis2) {
    idTokenIssuer = 'nhsCis2'; 
    jwksPath = context.getVariable('identity-service-config.cis2.jwks_path');
} else if (matchNhsLogin) {
    idTokenIssuer = 'nhsLogin';
    jwksPath = context.getVariable('identity-service-config.nhs_login.jwks_path');

} else {
    print('error');
    idTokenIssuer = ''
}

context.setVariable('idTokenIssuer', idTokenIssuer);
context.setVariable('jwksPath', jwksPath);