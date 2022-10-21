decodedJwt = context.getVariable('jwt.DecodeJWT.FromClientAssertionFormParam.payload-json');
decodedJwt = JSON.parse(decodedJwt);

var InvalidExpiryTime = true

if(typeof decodedJwt.exp == "number"){
    InvalidExpiryTime = false
}

context.setVariable('InvalidJwt.InvalidExpiryTimeType', InvalidExpiryTime);
