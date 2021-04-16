var exp = context.getVariable('jwt.DecodeJWT.FromSubjectTokenFormParam.decoded.claim');
var iss = context.getVariable('jwt.DecodeJWT.FromSubjectTokenFormParam.decoded.claim.iss');
var aud = context.getVariable('jwt.DecodeJWT.FromSubjectTokenFormParam.decoded.claim.aud');

var nhsLoginIssuer = context.getVariable('identity-service-config.nhs_login.issuer');
var cis2Issuer = 'https://am.nhsint.auth-ptl.cis2.spineservices.nhs.uk:443/openam/oauth2/realms/root/realms/NHSIdentity/realms/Healthcare';

var jwksPath = '';
var idTokenIssuer = '';
var isError = false;

if (exp === "" || exp === null) {
    var errorObject = { error: 'invalid_request', errorDescription: "Missing exp claim in JWT", statusCode: 400, reasonPhrase: "Bad Request" } 
    var isError = true
} else if(iss === null || iss === '' ||  iss !== cis2Issuer || iss !== nhsLoginIssuer) {
    var errorObject = { error: 'invalid_request', errorDescription: "Missing or non-matching iss/sub claims in JWT", statusCode: 400, reasonPhrase: "Bad Request" } 
    var isError = true
} else if (iss == cis2Issuer) {
    idTokenIssuer = 'nhsCis2'; 
    jwksPath = context.getVariable('identity-service-config.cis2.jwks_path');
} else if (iss == nhsLoginIssuer) {
    idTokenIssuer = 'nhsLogin';
    jwksPath = context.getVariable('identity-service-config.nhs_login.jwks_path');
}  else if(aud === null || aud === '' ) {
    var errorObject = { error: 'invalid_request', errorDescription: "Missing aud claim in JWT", statusCode: 400, reasonPhrase: "Bad Request" } 
    var isError = true
}

context.setVariable('isError', isError)
context.setVariable('idTokenIssuer', idTokenIssuer);
context.setVariable('jwksPath', jwksPath);

if (isError) {
    context.setVariable('validation.errorMessage', errorObject.error)
    context.setVariable('validation.errorDescription', errorObject.errorDescription)
    context.setVariable('validation.statusCode', errorObject.statusCode)
    context.setVariable('validation.reasonPhrase', errorObject.reasonPhrase)    
}