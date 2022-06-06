const authProvider = context.getVariable("idTokenIssuer");
context.setVariable("apigee.auth_provider", authProvider);