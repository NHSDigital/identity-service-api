var api_product_scopes = String(context.getVariable('original_scope'));
var idTokenIssuer = context.getVariable('idTokenIssuer');
if (idTokenIssuer == "nhs-cis2") {
    var id_token_acr = context.getVariable('jwt.DecodeJWT.FromSubjectTokenFormParam.decoded.claim.authentication_assurance_level');
    id_token_acr = ':aal'+ id_token_acr+':';
}
else {
    var id_token_acr = context.getVariable('jwt.DecodeJWT.FromSubjectTokenFormParam.decoded.claim.identity_proofing_level');
    id_token_acr = ':' + id_token_acr.slice(0, 2) + ':';
}


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