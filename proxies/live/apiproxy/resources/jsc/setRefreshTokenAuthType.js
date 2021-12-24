const authProvider = String(context.getVariable('session.auth_provider'));
let refreshTokenDefaultMs;
let refreshTokenDefaultValidityMs;

if (authProvider !== null && authProvider === "nhs-cis2") {
    refreshTokenDefaultMs = parseInt(context.getVariable('identity-service-config.cis2.refresh_token_expiry_ms'));
    refreshTokenDefaultValidityMs = parseInt(context.getVariable('identity-service-config.cis2.refresh_tokens_validity_ms'));
} else {
    refreshTokenDefaultMs = parseInt(context.getVariable('identity-service-config.nhs_login.refresh_token_expiry_ms'));
    refreshTokenDefaultValidityMs = parseInt(context.getVariable('identity-service-config.nhs_login.refresh_tokens_validity_ms'));
}

context.setVariable('apigee.refresh_token_expiry_ms', refreshTokenDefaultMs);
context.setVariable('apigee.refresh_tokens_validity_ms', refreshTokenDefaultValidityMs);
