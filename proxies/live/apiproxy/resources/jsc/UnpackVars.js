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
