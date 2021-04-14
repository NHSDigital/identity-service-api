var issuer = context.getVariable('jwt.DecodeJWT.FromSubjectTokenFormParam.decoded.claim.iss');
var InvalidIdTokenIssuer = false;
var jwksPath = '';
var idTokenIssuer = '';

var index = authorize_endpoint.indexOf('/authorize')
var base_url = authorize_endpoint.slice(0, index)

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