var issuer = context.getVariable('jwt.DecodeJWT.FromSubjectTokenFormParam.decoded.claim.iss');
var InvalidIdTokenIssuer = false;
var jwksPath = '';
var idTokenIssuer = '';

var nhsLoginIssuer = context.getVariable('identity-service-config.nhs-login.issuer');

if(issuer === null || issuer === '' ) {
    InvalidIdTokenIssuer = true;
} else if (issuer.includes('NHSIdentity')) {
    idTokenIssuer = 'nhsCis2'; 
    jwksPath = context.getVariable('identity-service-config.cis2.jwks_path');
} else if (issuer = nhsLoginIssuer) {
    idTokenIssuer = 'nhsLogin';
    jwksPath = context.getVariable('identity-service-config.nhs_login.jwks_path');
} else {
    InvalidIdTokenIssuer = true;
}

context.setVariable('idTokenIssuer', idTokenIssuer);
context.setVariable('jwksPath', jwksPath);
context.setVariable('InvalidIdTokenIssuer', InvalidIdTokenIssuer);