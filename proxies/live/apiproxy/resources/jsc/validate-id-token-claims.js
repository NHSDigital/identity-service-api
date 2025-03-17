var idp = context.getVariable("idp");
var aud_claim = context.getVariable("jwt.DecodeJWT.FromExternalIdToken.decoded.claim.aud");
var iss_claim = context.getVariable("jwt.DecodeJWT.FromExternalIdToken.decoded.claim.iss");

if(idp == 'nhs-login'){
    var client_id = context.getVariable("identity-service-config.nhs_login.client_id");
    var base_url = context.getVariable("identity-service-config.nhs_login.issuer");
}
else{
    var client_id = context.getVariable("identity-service-config.cis2.client_id");
    var base_url = context.getVariable("identity-service-config.cis2.issuer");
}


aud_claim = JSON.parse(aud_claim);
            


if(aud_claim != client_id)
    {
        context.setVariable('claims_validation.error', "invalid_request")
        context.setVariable('claims_validation.error_description', "Invalid 'aud' claim in external ID token JWT")
        context.setVariable('claims_validation.is_valid', false)
    }
    
else if(iss_claim.toLowerCase() != base_url.toLowerCase())
    {
      context.setVariable('claims_validation.error', "invalid_request")
      context.setVariable('claims_validation.error_description', "Invalid iss claim in external ID token JWT")
      context.setVariable('claims_validation.is_valid', false)
    }
