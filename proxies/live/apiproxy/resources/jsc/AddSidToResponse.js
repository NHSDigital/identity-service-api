//Parse the respose from the target.
var res = JSON.parse(context.proxyResponse.content);
var sid = context.getVariable('jwt.DecodeJWT.FromExternalIdToken.decoded.claim.sid');

//Add sid value to response
res.sid = sid;
          
//Set the response variable. 
context.proxyResponse.content = JSON.stringify(res);