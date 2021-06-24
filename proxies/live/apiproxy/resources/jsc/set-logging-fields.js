var provider = "unknown";
var issuer = context.getVariable("jwt.DecodeJWT.FromExternalIdToken.claim.issuer");
if (issuer) {
  if (issuer.includes("cis2")) {
    provider = "cis2";
  }
}

var level = "unknown";
var claim_acr = context.getVariable("jwt.DecodeJWT.FromExternalIdToken.claim.acr");
if (claim_acr) {
  if (claim_acr.toLowerCase().includes("aal3")) {
    level = "aal3";
  }
}

context.setVariable("splunk.auth.provider", provider);
context.setVariable("splunk.auth.level", level);
