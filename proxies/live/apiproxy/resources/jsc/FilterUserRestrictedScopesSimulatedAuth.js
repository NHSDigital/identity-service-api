var id_token_acr = context.getVariable('jwt.DecodeJWT.FromGeneratedIdTokenSimulatedAuth.decoded.claim.acr');
var api_product_scopes = String(context.getVariable('oauthv2accesstoken.OAuthV2.GenerateAccessTokenDummy.scope'));
id_token_acr = ':' + id_token_acr.slice(0, 4).toLowerCase() + ':';

if (api_product_scopes == 'null') {
    api_product_scopes = String(context.getVariable('oauthv2accesstoken.OAuthV2.TokenExchangeGenerateAccessToken.scope'));
}

var scopes_list = api_product_scopes.split(" ");
// var regex = new RegExp("(urn:nhsd:apim:user-nhs-id:aal3:)");
var regex = new RegExp(id_token_acr);
var filtered_user_restricted_scopes = scopes_list.filter(scope => {
    if (regex.test(scope)) {
        return scope;
    }
});
filtered_user_restricted_scopes = filtered_user_restricted_scopes.join(' ');
context.setVariable('apigee.user_restricted_scopes', filtered_user_restricted_scopes);