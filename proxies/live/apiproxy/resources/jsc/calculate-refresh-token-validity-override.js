refresh_tokens_validity_ms = parseInt(context.getVariable('request.formparam._refresh_tokens_validity_ms'));
refresh_token_default_validity_ms = parseInt(context.getVariable('apigee.refresh_tokens_validity_ms'));

context.setVariable('apigee.can_override_refresh_token_validity', refresh_tokens_validity_ms < refresh_token_default_validity_ms);
