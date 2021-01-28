var api_product_scopes = String(context.getVariable('oauthv2accesstoken.OAuthV2.GenerateAccessTokenSimulatedAuth.scope'));

var scopes_list = api_product_scopes.split(" ");
var regex = new RegExp("(urn:nhsd:apim:user:aal3:*)");
var filtered_user_restricted_scopes = scopes_list.filter(scope => {
    if (regex.test(scope)) {
        return scope;
    }
});

context.setVariable('apigee.user_restricted_scopes', filtered_user_restricted_scopes);