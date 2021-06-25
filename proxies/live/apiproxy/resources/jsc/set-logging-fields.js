var grant_type = context.getVariable("request.formparam.grant_type");
var provider = "unknown";
var level = "unknown";

if (grant_type === "authorization_code") {
  var issuer = context.getVariable("jwt.DecodeJWT.FromExternalIdToken.claim.issuer");
  provider = getProvider(issuer);

  var claim_acr = context.getVariable("jwt.DecodeJWT.FromExternalIdToken.claim.acr");
  level = getLevel(claim_acr);

} else {
  // Now it's either client-credentials or token-exhange. We can't rely on apigee since, there is no support for token-exchange
  if (context.getVariable("request.formparam.subject_token")) {
    // Then it's token-exchange
    scope = context.getVariable("apigee.user_restricted_scopes");
    level = getLevel(scope);

    issuer = context.getVariable("idTokenIssuer");
    provider = getProvider(issuer);
  } else {
    scope = context.getVariable("apigee.application_restricted_scopes");
    level = getLevel(scope);

    provider = "apim";
  }
}

context.setVariable("splunk.auth.provider", provider);
context.setVariable("splunk.auth.level", level);

function getLevel(level) {
  if (level) {
    level = level.toLowerCase();

    if (level.includes("aal3")) {
      return "aal3";
    }
    if (level.includes(":level3")) {
      return "level3";
    }
    if (level.includes(":p9:")) {
      return "p9";
    }
  }
  return "unknown";
}

function getProvider(provider) {
  if (provider) {
    provider = provider.toLowerCase();
    print(provider);

    if (provider.includes("cis2") || provider.includes("nhscis2")) {
      return "nhs-cis2";
    }
    if (provider.includes("nhslogin")) {
      return "nhs-login";
    }
  }
  return "unknown";
}
