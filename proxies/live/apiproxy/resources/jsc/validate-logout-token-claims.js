var idp = context.getVariable("idp");

var aud_claim = context.getVariable("jwt.DecodeJWT.LogoutToken.decoded.claim.aud");
var iss_claim = context.getVariable("jwt.DecodeJWT.LogoutToken.decoded.claim.iss");
var sub_claim = context.getVariable("jwt.DecodeJWT.LogoutToken.decoded.claim.sub");
var sid_claim = context.getVariable("jwt.DecodeJWT.LogoutToken.decoded.claim.sid");
var events_claim = context.getVariable("jwt.DecodeJWT.LogoutToken.decoded.claim.events");
var nonce_claim = context.getVariable("jwt.DecodeJWT.LogoutToken.decoded.claim.nonce");

if(idp === 'cis2'){
    var client_id = context.getVariable("identity-service-config.cis2.client_id");
    var base_url = context.getVariable("identity-service-config.cis2.issuer");
}
// Left here for future implementation for nhs_login
//else{
//    var client_id = context.getVariable("identity-service-config.nhs_login.client_id");
//    var base_url = context.getVariable("identity-service-config.nhs_login.issuer");
//}

aud_claim = JSON.parse(aud_claim);
 
function eventsCheck(str) {
    try {
        events_json = JSON.parse(str);
        return events_json.events.hasOwnProperty("http://schemas.openid.net/event/backchannel-logout");
    } catch (e) {
        return false;
    }
}

if (aud_claim !== client_id) {
    context.setVariable('claims_validation.error', "invalid_request")
    context.setVariable('claims_validation.error_description', "Invalid aud claim in JWT")
    context.setVariable('claims_validation.is_valid', false)
} else if (iss_claim.toLowerCase() !== base_url.toLowerCase()) {
	context.setVariable('claims_validation.error', "invalid_request")
	context.setVariable('claims_validation.error_description', "Invalid iss claim in JWT")
	context.setVariable('claims_validation.is_valid', false)
} else if (sid_claim === null && sub_claim === null) {
	context.setVariable('claims_validation.error', "invalid_request")
	context.setVariable('claims_validation.error_description', "Invalid sid claim in JWT")
	context.setVariable('claims_validation.is_valid', false)
} else if (!eventsCheck(events_claim)) {
	context.setVariable('claims_validation.error', "invalid_request")
	context.setVariable('claims_validation.error_description', "Invalid events claim in JWT")
	context.setVariable('claims_validation.is_valid', false)
} else if (nonce_claim !== null) {
	context.setVariable('claims_validation.error', "invalid_request")
	context.setVariable('claims_validation.error_description', "Invalid nonce claim in JWT")
	context.setVariable('claims_validation.is_valid', false)
}


