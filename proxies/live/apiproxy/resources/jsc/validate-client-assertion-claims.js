decodedJwt = context.getVariable('jwt.DecodeJWT.FromClientAssertionFormParam.payload-json');
decodedJwt = JSON.parse(decodedJwt);

var InvalidExpiryTime = true

if(typeof jwt.exp == "number"){
    InvalidExpiryTime = false
}

context.setVariable('InvalidExpiryTime', InvalidExpiryTime);
