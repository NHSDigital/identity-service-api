const authProvider = context.getVariable('idTokenIssuer');

var provider= 'nhs_login';
if (authProvider !== null && authProvider === "nhs-cis2") {
    provider = 'cis2'
}

var refreshTokenDefaultMs = context.getVariable(`identity-service-config.${provider}.refresh_token_expiry_ms`);
var refreshTokenDefaultValidityMs = context.getVariable(`identity-service-config.${provider}.refresh_tokens_validity_ms`);

var accessTokenDefaultMs = context.getVariable(`identity-service-config.${provider}.access_token_expiry_ms`);


context.setVariable('apigee.auth_provider', authProvider);
context.setVariable('apigee.refresh_token_expiry_ms', refreshTokenDefaultMs);
context.setVariable('apigee.refresh_tokens_validity_ms', refreshTokenDefaultValidityMs);
context.setVariable('apigee.access_token_expiry_ms', accessTokenDefaultMs);
