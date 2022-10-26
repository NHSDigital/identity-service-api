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
cachedJtiValue = context.getVariable("JTICachedValue")
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
invalidAlgHeaderMessage = "Invalid 'alg' header in JWT - unsupported JWT algorithm - must be 'RS512'"
jwtExpiredMessage = "Invalid exp claim in JWT - JWT has expired"
jtiExistsInCacheMessage = "Non-unique jti claim in JWT"
noErrorMessage = ""

// Set conditions for triggering error messages
missingKidCondition = !jwtHeaders.kid
missingOrInvalidTypCondition = typeof jwtHeaders.typ != "string" || jwtHeaders.typ.toLowerCase() != "jwt"
missingExpClaimCondition = !jwtPayload.exp
invalidExpiryTimeCondition = typeof jwtPayload.exp != "number"
missingOrInvalidIssClaimCondition = !jwtPayload.iss || jwtPayload.iss != jwtPayload.sub
missingJtiClaimCondition = !jwtPayload.jti
invalidJtiClaimCondition = typeof jwtPayload.jti != "string"
invalidAlgHeaderCondition = jwtHeaders.alg != "RS512"
jtiExistsInCacheCondition = cachedJtiValue == jwtPayload.jti
// JS Date constructor uses milliseconds, exp uses seconds, so multiply exp by 1000 to convert to ms
jwtExpiredCondition = new Date() > new Date(jwtPayload.exp * 1000)
// We advise to limit expiry time to now + 5 minutes. Allowing an extra 10 seconds to mitigate edge cases:
expClaimTooLongCondition = expExpiry > 310

// Set the error message to the first error condition that returns true
context.setVariable('InvalidJwt.ErrorMessage',
  invalidAlgHeaderCondition && invalidAlgHeaderMessage
  || jwtExpiredCondition && jwtExpiredMessage
  || missingKidCondition && missingKidMessage
  || missingOrInvalidTypCondition && missingOrInvalidTypMessage
  || missingExpClaimCondition && missingExpClaimMessage
  || invalidExpiryTimeCondition && invalidExpiryTimeMessage
  || missingOrInvalidIssClaimCondition && missingOrInvalidIssClaimMessage
  || missingJtiClaimCondition && missingJtiClaimMessage
  || invalidJtiClaimCondition && invalidJtiMessage
  // Checking that the JTI exists in the cache should happen after checking that the JTI is valid
  || jtiExistsInCacheCondition && jtiExistsInCacheMessage
  || expClaimTooLongCondition && expClaimTooLongMessage
  || noErrorMessage
)
