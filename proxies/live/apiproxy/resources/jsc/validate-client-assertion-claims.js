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
expExpiry = context.getVariable("jwt.DecodeJWT.FromClientAssertionFormParam.seconds_remaining")

// Declare error message strings
missingKidMessage = "Missing 'kid' header in JWT"
missingOrInvalidTypMessage = "Invalid 'typ' header in JWT - must be 'JWT'"
missingExpClaimMessage = "Missing exp claim in JWT"
invalidExpiryTimeMessage = "Exp claim must be an integer"
missingOrInvalidIssClaimMessage = "Missing or non-matching iss/sub claims in JWT"
missingJtiClaimMessage = "Missing jti claim in JWT"
invalidJtiMessage = "Jti claim must be a unique string value such as a GUID"
expClaimTooLongMessage = "Invalid exp claim in JWT - more than 5 minutes in future"
noErrorMessage = ""

// Set conditions for trigger error messages
missingKidCondition = !jwtHeaders.kid
missingOrInvalidTypCondition = typeof jwtHeaders.typ != "string" || jwtHeaders.typ.toLowerCase() != "jwt"
missingExpClaimCondition = !jwtPayload.exp
invalidExpiryTimeCondition = typeof jwtPayload.exp != "number"
missingOrInvalidIssClaimCondition = !jwtPayload.iss || jwtPayload.iss != jwtPayload.sub
missingJtiClaimCondition = !jwtPayload.jti
invalidJtiClaimCondition = typeof jwtPayload.jti != "string"
// We advise to limit expiry time to now + 5 minutes. Allowing an extra 10 seconds to mitigate edge cases:
expClaimTooLongCondition = expExpiry > 310

// Set the error message to the first error condition that returns true
context.setVariable('InvalidJwt.ErrorMessage',
  missingKidCondition && missingKidMessage
  || missingOrInvalidTypCondition && missingOrInvalidTypMessage
  || missingExpClaimCondition && missingExpClaimMessage
  || invalidExpiryTimeCondition && invalidExpiryTimeMessage
  || missingOrInvalidIssClaimCondition && missingOrInvalidIssClaimMessage
  || missingJtiClaimCondition && missingJtiClaimMessage
  || invalidJtiClaimCondition && invalidJtiMessage
  || expClaimTooLongCondition && expClaimTooLongMessage
  || noErrorMessage
)
