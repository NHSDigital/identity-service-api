var api_product_scopes = String(context.getVariable('original_scope'));
var idTokenIssuer = context.getVariable('idTokenIssuer');
var acr = context.getVariable('jwt.DecodeJWT.FromSubjectTokenFormParam.decoded.claim.acr');
var identity_proofing_level = context.getVariable('jwt.DecodeJWT.FromSubjectTokenFormParam.decoded.claim.identity_proofing_level');
var isError = false;
var missing_claim = '';

if (acr === '') {
    var isError = true;
    var missing_claim = 'acr';
}
else if (identity_proofing_level === '') {
    var isError = true;
    var missing_claim = 'identity_proofing_level';
}

if (idTokenIssuer == "nhsCis2") {
    var id_token_acr = context.getVariable('jwt.DecodeJWT.FromSubjectTokenFormParam.decoded.claim.acr');
    id_token_acr = ':' + id_token_acr.slice(0, 4).toLowerCase() + ':';   
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
context.setVariable('isError', isError);
context.setVariable('missing_claim', missing_claim);