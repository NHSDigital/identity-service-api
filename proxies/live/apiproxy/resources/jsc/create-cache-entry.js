client_id = context.getVariable('request.queryparam.client_id');
// We will permit this for simulated_idp, but not for real authorization
if (context.getVariable('identity-service-config.cis2.simulated_idp') == 'true') {
  state = context.getVariable('request.queryparam.state') || "";
} else {
  state = context.getVariable('request.queryparam.state');
}
redirect_uri = context.getVariable('request.queryparam.redirect_uri');
response_type = context.getVariable('request.queryparam.response_type');
scope = context.getVariable('oauthv2accesstoken.OAuthV2.GenerateAccessTokenDummy.scope');
idp = context.getVariable('request.queryparam.scope');

var cacheEntry = {
  client_id: client_id,
  redirect_uri: redirect_uri,
  state: state,
  response_type: response_type,
  scope: scope,
  idp: idp
};

context.setVariable('cacheEntry', JSON.stringify(cacheEntry));
