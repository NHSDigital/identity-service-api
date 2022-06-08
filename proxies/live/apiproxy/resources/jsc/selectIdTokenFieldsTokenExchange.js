var exp = context.getVariable('jwt.DecodeJWT.FromSubjectTokenFormParam.decoded.claim.exp');
var iss = context.getVariable('jwt.DecodeJWT.FromSubjectTokenFormParam.decoded.claim.iss');
var aud = context.getVariable('jwt.DecodeJWT.FromSubjectTokenFormParam.decoded.claim.aud');

context.setVariable('idtoken_decoded_claim_exp', exp)
context.setVariable('idtoken_decoded_claim_iss', iss);
context.setVariable('idtoken_decoded_claim_aud', aud);