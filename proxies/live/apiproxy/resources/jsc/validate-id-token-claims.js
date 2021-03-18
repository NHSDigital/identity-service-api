var aud_claim = context.getVariable("jwt.DecodeJWT.FromExternalIdToken.decoded.claim.aud");
var iss_claim = context.getVariable("jwt.DecodeJWT.FromExternalIdToken.decoded.claim.iss");
var authorize_endpoint = context.getVariable("private.apigee.authorize_endpoint");

var client_id = context.getVariable("private.apigee.client_id");
var message_id = context.getVariable("messageid");

aud_claim = JSON.parse(aud_claim);
validation = {
              message_id: message_id,
              is_valid: true,
              message : ""    
            };
            
var index = authorize_endpoint.indexOf('/authorize')
var base_url = authorize_endpoint.slice(0, index)


if(aud_claim != client_id)
    {
        message =   
        {
          error: "AudClaim Invalid",
          error_description: "Aud claim does not match",
          message_id: message_id
        }
        validation.is_valid = false;
        validation.message = JSON.stringify(message);
    }
    
else if(iss_claim.toLowerCase() != base_url.toLowerCase())
    {
        message =   
        {
          error: "IssClaim Invalid",
          error_description: "Iss claim does not match",
          message_id: message_id
        }
        validation.is_valid = false;
        validation.message = JSON.stringify(message);
    }
context.setVariable("claims_validation.is_valid", validation.is_valid);    
context.setVariable("claims_validation.message", validation.message);