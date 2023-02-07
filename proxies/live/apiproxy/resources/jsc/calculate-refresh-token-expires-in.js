token_first_issued_ms = parseInt(context.getVariable('oauthv2refreshtoken.GetOAuthV2Info.RefreshTokenAttributes.accesstoken._first_issued'));
now_ms = parseInt(context.getVariable('system.timestamp'));
refresh_tokens_validity_ms = parseInt(context.getVariable('apigee.refresh_tokens_validity_ms'));
refresh_token_expiry_ms = parseInt(context.getVariable('apigee.refresh_token_expiry_ms'));

// Time after which refresh tokens can no longer be used and the user must re-authorise
refresh_tokens_end_time_ms = token_first_issued_ms + refresh_tokens_validity_ms;

// Time after which this individual refresh token will become invalid
this_refresh_token_expiry_time_ms = now_ms + refresh_token_expiry_ms;

// Use the earliest time
refresh_token_expiry_time_ms = this_refresh_token_expiry_time_ms < refresh_tokens_end_time_ms ? this_refresh_token_expiry_time_ms : refresh_tokens_end_time_ms;

// Express as ms from now
refresh_token_expires_in_ms = refresh_token_expiry_time_ms - now
context.setVariable('apigee.refresh_token_expires_in_ms', refresh_token_expires_in_ms)