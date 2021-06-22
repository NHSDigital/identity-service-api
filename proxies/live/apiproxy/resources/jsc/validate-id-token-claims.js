var aud_claim = context.getVariable("jwt.DecodeJWT.FromExternalIdToken.decoded.claim.aud");
var iss_claim = context.getVariable("jwt.DecodeJWT.FromExternalIdToken.decoded.claim.iss");

var client_id = context.getVariable("identity-service-config.cis2.client_id");

aud_claim = JSON.parse(aud_claim);
            
var base_url = context.getVariable("identity-service-config.cis2.issuer");


if(aud_claim != client_id)
    {
        context.setVariable('claims_validation.error', "invalid_request")
        context.setVariable('claims_validation.error_description', "Invalid aud claim in JWT")
        context.setVariable('claims_validation.is_valid', false)
    }
    
else if(iss_claim.toLowerCase() != base_url.toLowerCase())
    {
      context.setVariable('claims_validation.error', "invalid_request")
      context.setVariable('claims_validation.error_description', "Invalid iss claim in JWT")
      context.setVariable('claims_validation.is_valid', false)
    }
