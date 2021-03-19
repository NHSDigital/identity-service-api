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
          error: "invalid_request",
          error_description: "Invalid aud claim in JWT",
          message_id: message_id
        }
        validation.is_valid = false;
        validation.message = JSON.stringify(message);
    }
    
else if(iss_claim.toLowerCase() != base_url.toLowerCase())
    {
        message =   
        {
          error: "invalid_request",
          error_description: "Invalid iss claim in JWT",
          message_id: message_id
        }
        validation.is_valid = false;
        validation.message = JSON.stringify(message);
    }
context.setVariable("claims_validation.is_valid", validation.is_valid);    
context.setVariable("claims_validation.message", validation.message);
