
function extractJsonVariable(contextVariableName) {
  return JSON.parse(
    context.getVariable(
      "jwt.DecodeJWT.FromClientAssertionFormParam."
      + contextVariableName
    )
  )
}

jwtHeaders = extractJsonVariable('header-json')
jwtPayload = extractJsonVariable('payload-json')

// Set context variables based on the condition in the second argument
context.setVariable('InvalidJwt.MissingKidHeader', !jwtHeaders.kid);
context.setVariable('InvalidJwt.MissingOrInvalidTypHeader', jwtHeaders.typ != "jwt");
context.setVariable('InvalidJwt.MissingExpClaim', !jwtPayload.exp);
context.setVariable('InvalidJwt.InvalidExpiryTime', typeof jwtPayload.exp != "number");

// We advise to limit expiry time to now + 5 minutes. Allowing an extra 10 seconds to mitigate edge cases:
context.setVariable('InvalidJwt.ExpClaimTooLong', typeof jwtPayload.exp == "number" && jwtPayload.exp > 310);

context.setVariable('InvalidJwt.MissingOrInvalidIssClaim', !jwtPayload.iss || jwtPayload.iss != jwtPayload.sub);
context.setVariable('InvalidJwt.MissingJtiClaim', !jwtPayload.jti);
