var issuer = context.getVariable('jwt.DecodeJWT.FromSubjectTokenFormParam.decoded.claim.iss');
var nhsCis2 = new RegExp("(NHSIdentity)");
var nhsLogin = new RegExp("(signin.nhs.uk)");
var matchNhsCis2 = nhsCis2.exec(issuer);
var matchNhsLogin = nhsLogin.exec(issuer);
var idTokenIssuer = ''

if (matchNhsCis2) {
    print('this is nhs id');
    idTokenIssuer = 'nhsCis2'; 
    jwksPath = '/mock-nhsid-jwks/identity-service/nhs-cis2-jwks'
} else if (matchNhsLogin) {
    print('this is nhs login');
    idTokenIssuer = 'nhsLogin';
    jwksPath = '/mock-nhsid-jwks/identity-service/nhs-login-jwks'

} else {
    print('error');
    idTokenIssuer = ''
}

context.setVariable('idTokenIssuer', idTokenIssuer);
context.setVariable('jwksPath', jwksPath);