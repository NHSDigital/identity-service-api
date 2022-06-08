var exp = context.getVariable('idtoken_decoded_claim_exp');
var iss = context.getVariable('idtoken_decoded_claim_iss');
var aud = context.getVariable('idtoken_decoded_claim_aud');

var nhsLoginIssuer = context.getVariable('identity-service-config.nhs_login.issuer');
var cis2Issuer = context.getVariable('identity-service-config.cis2.issuer');


var jwksPath = '';
var idTokenIssuer = '';
var isError = false;

if (exp === '[""]' || exp === null) {
    var errorObject = { error: 'invalid_request', errorDescription: "Missing exp claim in JWT", statusCode: 400, reasonPhrase: "Bad Request" }
    var isError = true
} else if(iss === null || iss === '[""]' || iss !== cis2Issuer && iss !== nhsLoginIssuer) {
    var errorObject = { error: 'invalid_request', errorDescription: "Missing or non-matching iss/sub claims in JWT", statusCode: 400, reasonPhrase: "Bad Request" }
    var isError = true
} else if(aud === null || aud === '[""]' ) {
    var errorObject = { error: 'invalid_request', errorDescription: "Missing aud claim in JWT", statusCode: 400, reasonPhrase: "Bad Request" }
    var isError = true
}

if (iss == cis2Issuer) {
    idTokenIssuer = 'nhs-cis2';
    jwksPath = context.getVariable('identity-service-config.cis2.jwks_path');
} else if (iss == nhsLoginIssuer) {
    idTokenIssuer = 'nhs-login';
    jwksPath = context.getVariable('identity-service-config.nhs_login.jwks_path');
}

context.setVariable('isError', isError)
context.setVariable('idTokenIssuer', idTokenIssuer);
// same as idtokenissuer - todo: see if can set to one.
context.setVariable("apigee.auth_provider", idTokenIssuer);
context.setVariable('jwksPath', jwksPath);

if (isError) {
    context.setVariable('validation.errorMessage', errorObject.error)
    context.setVariable('validation.errorDescription', errorObject.errorDescription)
    context.setVariable('validation.statusCode', errorObject.statusCode)
    context.setVariable('validation.reasonPhrase', errorObject.reasonPhrase)
}