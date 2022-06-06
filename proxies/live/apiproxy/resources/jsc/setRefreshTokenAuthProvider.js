const authProvider = context.getVariable("oauthv2refreshtoken.GetOAuthV2Info.RefreshTokenAttributes.accesstoken.auth_provider");
context.setVariable("apigee.auth_provider", authProvider);