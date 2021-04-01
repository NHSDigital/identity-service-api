var issuer = context.getVariable('jwt.DecodeJWT.FromSubjectTokenFormParam.decoded.claim.iss');
var idTokenIssuer = '';
var InvalidIdTokenIssuer = false;
var jwksPath = '';

if(issuer === null || issuer === '' ) {
    InvalidIdTokenIssuer = true;
} else if (issuer.includes('NHSIdentity')) {
    idTokenIssuer = 'nhsCis2'; 
    jwksPath = context.getVariable('identity-service-config.cis2.jwks_path');
} else if (issuer.includes('signin.nhs.uk') || issuer.includes('login.nhs.uk')) {
    idTokenIssuer = 'nhsLogin';
    jwksPath = context.getVariable('identity-service-config.nhs_login.jwks_path');
} else {
    InvalidIdTokenIssuer = true;
}

context.setVariable('idTokenIssuer', idTokenIssuer);
context.setVariable('jwksPath', jwksPath);
context.setVariable('InvalidIdTokenIssuer', InvalidIdTokenIssuer)