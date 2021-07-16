function set_variables(location, vars) {

    if (typeof vars !== 'object') {
        return;
    }

    for (var key in vars)
    {
        if (!vars.hasOwnProperty(key))
            continue;
        variable = location + '.' + key;
        value = vars[key];
        if (typeof value === 'object' && value !== null) {
            set_variables(variable, value);
        }
        else {
            context.setVariable(variable, value);
        }
    }
}

var identityServiceConfig =  JSON.parse(context.getVariable("private.config_raw"));
set_variables("identity-service-config", identityServiceConfig)
// REMOVE ME! DO NOT APPROVE THE REVIEW IF THIS IS STILL HERE!!
context.setVariable("identity-service-config.cis2.authorize_endpoint", "https://internal-dev.api.service.nhs.uk/mock-nhsid-jwks-pr-38/simulated_auth")
context.setVariable("identity-service-config.cis2.redirect_uri", "https://internal-dev.api.service.nhs.uk/oauth2-pr-234/callback")
