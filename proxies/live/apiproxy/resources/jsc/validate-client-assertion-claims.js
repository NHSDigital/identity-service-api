// Declare error message strings
missingKidCondition = !jwtHeaders.kid
missingKidMessage = "Missing 'kid' header in JWT"
noErrorMessage = ""


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

context.setVariable(
  'InvalidJwt.ErrorMessage',
  missingKidCondition && missingKidMessage
  || noErrorMessage
)


context.setVariable('InvalidJwt.MissingOrInvalidTypHeader', typeof jwtHeaders.typ != "string" || jwtHeaders.typ.toLowerCase() != "jwt");
context.setVariable('InvalidJwt.MissingExpClaim', !jwtPayload.exp);
context.setVariable('InvalidJwt.InvalidExpiryTime', typeof jwtPayload.exp != "number");
context.setVariable('InvalidJwt.MissingOrInvalidIssClaim', !jwtPayload.iss || jwtPayload.iss != jwtPayload.sub);
context.setVariable('InvalidJwt.MissingJtiClaim', !jwtPayload.jti);
context.setVariable('InvalidJwt.InvalidJtiClaim', typeof jwtPayload.jti != "string");

// We advise to limit expiry time to now + 5 minutes. Allowing an extra 10 seconds to mitigate edge cases:
seconds_remaining = context.getVariable("jwt.DecodeJWT.FromClientAssertionFormParam.seconds_remaining")
context.setVariable('InvalidJwt.ExpClaimTooLong', seconds_remaining > 310);
