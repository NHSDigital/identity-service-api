scope = context.getVariable('oauthv2accesstoken.OAuthV2.ClientCredentialsGenerateAccessToken.scope');

context.setVariable('apigee.has_invalid_scopes', scope != null);