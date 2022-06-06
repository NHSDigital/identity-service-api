const authProvider = context.getVariable('idTokenIssuer');

if (authProvider !== null && authProvider === "nhs-cis2") {
    var refreshTokenDefaultMs = context.getVariable('identity-service-config.cis2.refresh_token_expiry_ms');
    var refreshTokenDefaultValidityMs = context.getVariable('identity-service-config.cis2.refresh_tokens_validity_ms');
    var accessTokenDefaultMs = context.getVariable(`identity-service-config.cis2.access_token_expiry_ms`);
} else {
    var refreshTokenDefaultMs = context.getVariable('identity-service-config.nhs_login.refresh_token_expiry_ms');
    var refreshTokenDefaultValidityMs = context.getVariable('identity-service-config.nhs_login.refresh_tokens_validity_ms');
    var accessTokenDefaultMs = context.getVariable(`identity-service-config.nhs_login.access_token_expiry_ms`);
}

context.setVariable('apigee.auth_provider', authProvider);
context.setVariable('apigee.refresh_token_expiry_ms', refreshTokenDefaultMs);
context.setVariable('apigee.refresh_tokens_validity_ms', refreshTokenDefaultValidityMs);
context.setVariable('apigee.access_token_expiry_ms', accessTokenDefaultMs);
