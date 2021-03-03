jwks = context.getVariable('jwks');
kid = context.getVariable('jwt.DecodeJWT.FromSubjectTokenFormParam.decoded.header.kid');
print(jwks);
print(kid);


// if (context.getVariable('identity_service.simulated_idp') == 'true') {
//   state = context.getVariable('request.queryparam.state') || "";
// } else {
//   state = context.getVariable('request.queryparam.state');
// }
// redirect_uri = context.getVariable('request.queryparam.redirect_uri');
// response_type = context.getVariable('request.queryparam.response_type');
// scope = context.getVariable('apigee.user_restricted_scopes');

// var cacheEntry = {
//   client_id: client_id,
//   redirect_uri: redirect_uri,
//   state: state,
//   response_type: response_type,
//   scope: scope
// };

// context.setVariable('cacheEntry', JSON.stringify(cacheEntry));
