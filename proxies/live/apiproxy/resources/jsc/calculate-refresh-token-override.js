refresh_token_override_ms = parseInt(context.getVariable('request.formparam._refresh_token_expiry_ms'));
refresh_token_default_ms = parseInt(context.getVariable('identity-service-config.cis2.refresh_token_expiry_ms'));

context.setVariable('apigee.can_override_refresh_token', refresh_token_override_ms < refresh_token_default_ms);
