token_first_issued = parseInt(context.getVariable('oauthv2accesstoken.OAuthV2.GenerateRefreshToken._first_issued'));
time_now = parseInt(context.getVariable('system.timestamp'));

context.setVariable('private.apigee.access_token_age_ms', time_now - token_first_issued);
