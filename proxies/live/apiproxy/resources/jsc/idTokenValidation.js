var isError = false;
 
var subjectClaim = context.getVariable('jwt.DecodeJWT.FromSubjectTokenFormParam.decoded.claim.sub');
var issuerClaim = context.getVariable('jwt.DecodeJWT.FromSubjectTokenFormParam.decoded.claim.iss'); 
var audienceClaim = context.getVariable('jwt.DecodeJWT.FromSubjectTokenFormParam.decoded.claim.aud');
var expirationClaim = context.getVariable('jwt.DecodeJWT.FromSubjectTokenFormParam.decoded.claim.exp');

if (subjectClaim === '' || subjectClaim === null) {
   var errorObject = { error: 'invalid_request', errorDescription: "Missing sub claim in id token JWT", statusCode: 400, reasonPhrase: "Bad Request" } 
   var isError = true
}
else if (issuerClaim === '' || issuerClaim === null) {
   var errorObject = { error: 'invalid_request', errorDescription: "Missing iss claim in id token JWT", statusCode: 400, reasonPhrase: "Bad Request" } 
   var isError = true
}
else if (audienceClaim === '' || audienceClaim === null) {
   var errorObject = { error: 'invalid_request', errorDescription: "Missing aud claim in id token JWT", statusCode: 400, reasonPhrase: "Bad Request" } 
   var isError = true
}
else if (expirationClaim === '' || expirationClaim === null) {
   var errorObject = { error: 'invalid_request', errorDescription: "Missing exp claim in id token JWT", statusCode: 400, reasonPhrase: "Bad Request" } 
   var isError = true
}

context.setVariable('isError', isError)

if (isError) {
   context.setVariable('validation.errorMessage', errorObject.error)
   context.setVariable('validation.errorDescription', errorObject.errorDescription)
   context.setVariable('validation.statusCode', errorObject.statusCode)
   context.setVariable('validation.reasonPhrase', errorObject.reasonPhrase)    
}
