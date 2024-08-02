var idp = context.getVariable('idp');

if(idp == 'nhs-login'){
    var id_token_acr = context.getVariable('jwt.DecodeJWT.FromExternalIdToken.decoded.claim.identity_proofing_level');
    id_token_acr = ':' + id_token_acr.slice(0, 2) + ':'; 
}
else{
    var id_token_acr = context.getVariable('jwt.DecodeJWT.FromExternalIdToken.decoded.claim.authentication_assurance_level');
    id_token_acr = ':aal' + id_token_acr + ':';
}

print("ID_TOKEN_CHECK",jwt);

var api_product_scopes = String(context.getVariable('original_scope'));

if (api_product_scopes == 'null') {
    api_product_scopes = String(context.getVariable('oauthv2accesstoken.OAuthV2.TokenExchangeGenerateAccessToken.scope'));
}

var scopes_list = api_product_scopes.split(" ");
var regex = new RegExp(id_token_acr);
var filtered_user_restricted_scopes = scopes_list.filter(scope => {
    if (regex.test(scope)) {
        return scope;
    }
});
filtered_user_restricted_scopes = filtered_user_restricted_scopes.join(' ');
context.setVariable('apigee.user_restricted_scopes', filtered_user_restricted_scopes);
