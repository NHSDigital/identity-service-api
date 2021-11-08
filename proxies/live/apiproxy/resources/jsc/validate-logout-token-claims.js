var idp = context.getVariable("idp");

var aud_claim = context.getVariable(
  "jwt.DecodeJWT.LogoutToken.decoded.claim.aud"
);
var iss_claim = context.getVariable(
  "jwt.DecodeJWT.LogoutToken.decoded.claim.iss"
);
var sub_claim = context.getVariable(
  "jwt.DecodeJWT.LogoutToken.decoded.claim.sub"
);
var sid_claim = context.getVariable(
  "jwt.DecodeJWT.LogoutToken.decoded.claim.sid"
);
var events_claim = context.getVariable(
  "jwt.DecodeJWT.LogoutToken.decoded.claim.events"
);
var nonce_claim = context.getVariable(
  "jwt.DecodeJWT.LogoutToken.decoded.claim.nonce"
);

if (idp !== "nhs-login") {
  var client_id = context.getVariable("identity-service-config.cis2.client_id");
  var base_url = context.getVariable("identity-service-config.cis2.issuer");
}
// Left here for future implementation for nhs_login
//else{
//    var client_id = context.getVariable("identity-service-config.nhs_login.client_id");
//    var base_url = context.getVariable("identity-service-config.nhs_login.issuer");
//}

function eventsCheck(str) {
  try {
    events_json = JSON.parse(str);
    return events_json.hasOwnProperty(
      "http://schemas.openid.net/event/backchannel-logout"
    );
  } catch (e) {
    return false;
  }
}

if (aud_claim !== null) {
  aud_claim = JSON.parse(aud_claim)[0];
}

if (iss_claim) {
  iss_claim = iss_claim.toLowerCase();
}

// Change hardcoded aud and iss when we play APM-2524
if (aud_claim !== "9999999999") {
  context.setVariable("claims_validation.error", "invalid_request");
  context.setVariable(
    "claims_validation.error_description",
    "Missing/invalid aud claim in JWT"
  );
  context.setVariable("claims_validation.is_valid", false);
} else if (
  iss_claim !==
  "https://am.nhsdev.auth-ptl.cis2.spineservices.nhs.uk:443/openam/oauth2/realms/root/realms/oidc"
) {
  context.setVariable("claims_validation.error", "invalid_request");
  context.setVariable(
    "claims_validation.error_description",
    "Missing/invalid iss claim in JWT"
  );
  context.setVariable("claims_validation.is_valid", false);
} else if (sid_claim === null) {
  context.setVariable("claims_validation.error", "invalid_request");
  context.setVariable(
    "claims_validation.error_description",
    "Missing sid claim in JWT"
  );
  context.setVariable("claims_validation.is_valid", false);
} else if (!eventsCheck(events_claim)) {
  context.setVariable("claims_validation.error", "invalid_request");
  context.setVariable(
    "claims_validation.error_description",
    "Missing/invalid events claim in JWT"
  );
  context.setVariable("claims_validation.is_valid", false);
} else if (nonce_claim !== null) {
  context.setVariable("claims_validation.error", "invalid_request");
  context.setVariable(
    "claims_validation.error_description",
    "Prohibited nonce claim in JWT"
  );
  context.setVariable("claims_validation.is_valid", false);
}
