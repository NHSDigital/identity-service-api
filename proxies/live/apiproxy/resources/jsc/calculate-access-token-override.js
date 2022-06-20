access_token_override_ms = parseInt(context.getVariable('request.formparam._access_token_expiry_ms'));
access_token_default_ms = parseInt(context.getVariable('apigee.access_token_expiry_ms'));

context.setVariable('apigee.can_override_access_token', access_token_override_ms < access_token_default_ms);
