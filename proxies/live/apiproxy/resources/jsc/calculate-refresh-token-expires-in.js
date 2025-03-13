/*
    We don't want users to be able to refresh access tokens forever.
    
    There are two configurable ways to control this:
        * refresh_tokens_validity_ms: maximum time refresh tokens can be used, counting from time of initial auth
        * refresh_token_expiry_ms: maximum age of a single refresh token

    This policy uses these values, and the time of first auth, to calculate the correct expiry time of a refresh
    token that is being issued.
*/

if (context.getVariable("oauthV2.GetOAuthV2Info.RefreshTokenAttributes.failed")) {
    // GetOAuthV2Info.RefreshTokenAttributes may have failed due to an invalid refresh token
    // In this case the _first_issued attribute can't be accessed and we can't do any calculations
    // Need to set this variable to *something* to satisfy the OAuthV2.GenerateRefreshToken policy
    context.setVariable('apigee.refresh_token_expires_in_ms', '1');
}
else {
    const now_ms = parseInt(context.getVariable('system.timestamp'));
    // When the user logged in and the first access token was issued:
    const token_first_issued_ms = parseInt(context.getVariable('oauthv2refreshtoken.GetOAuthV2Info.RefreshTokenAttributes.accesstoken._first_issued'));

    // Config option: Time from first authorization we no longer want to allow a further refresh
    const refresh_tokens_validity_ms = parseInt(context.getVariable('apigee.refresh_tokens_validity_ms'));

    // Config option: Individual refresh token lifespan
    const refresh_token_expiry_ms = parseInt(context.getVariable('apigee.refresh_token_expiry_ms'));

    // Time after which refresh tokens can no longer be used and the user must re-authorise
    const refresh_tokens_end_time_ms = token_first_issued_ms + refresh_tokens_validity_ms;

    // Time after which this individual refresh token will become invalid
    const this_refresh_token_expiry_time_ms = now_ms + refresh_token_expiry_ms;

    // Use the earliest time
    const refresh_token_expiry_time_ms = Math.min(this_refresh_token_expiry_time_ms, refresh_tokens_end_time_ms);

    // Express as ms from now
    var refresh_token_expires_in_ms = refresh_token_expiry_time_ms - now_ms;

    // We don't want a negative value (can happen during tests that manipulate the expiry times)
    refresh_token_expires_in_ms = Math.max(0, refresh_token_expires_in_ms)
    // Need to stringify otherwise it saves as scientific notation and can't be read properly
    context.setVariable('apigee.refresh_token_expires_in_ms', refresh_token_expires_in_ms.toString());
}
