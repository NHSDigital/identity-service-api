function extractJsonVariable(contextVariableName) {
  return JSON.parse(
    context.getVariable(
      "jwt.DecodeJWT.FromSubjectTokenFormParam."
      + contextVariableName
    )
  )
}


jwtHeaders = extractJsonVariable('header-json')
jwtPayload = extractJsonVariable('payload-json')
cachedJtiValue = context.getVariable("JTICachedValue")
expExpiry = context.getVariable("jwt.DecodeJWT.DecodeJWT.FromSubjectTokenFormParam.seconds_remaining")

// Declare error message strings


missingKidMessage = "Missing 'kid' header in Subject Token JWT"
missingOrInvalidTypMessage = "Invalid 'typ' header in Subject Token JWT - must be 'JWT'"
missingExpClaimMessage = "Missing exp claim in Subject Token JWT"
invalidExpiryTimeMessage = "Exp claim in Subject Token must be an integer"
missingIssClaimMessage = "Missing iss claims in Subject Token JWT"
missingJtiClaimMessage = "Missing jti claim in Subject Token JWT"
invalidJtiMessage = "Jti claim in Subject Token must be a unique string value such as a GUID"
expClaimTooLongMessage = "Invalid exp claim in Subject Token JWT - more than 5 minutes in future"
missingAlgHeaderMessage = "Missing 'alg' header in Subject Token JWT"
invalidAlgHeaderMessage = "Invalid 'alg' header in Subject Token JWT - must be 'RS512' algorithm"
jwtExpiredMessage = "Invalid exp claim in Subject Token JWT - JWT has expired"
jtiExistsInCacheMessage = "Non-unique jti claim in Subject Token JWT"
missingAudMessage = "Missing aud claim in Subject Token JWT"
noErrorMessage = ""

// Set conditions for triggering error messages
missingKidCondition = !jwtHeaders.kid
missingOrInvalidTypCondition = typeof jwtHeaders.typ != "string" || jwtHeaders.typ.toLowerCase() != "jwt"
missingExpClaimCondition = !jwtPayload.exp
invalidExpiryTimeCondition = typeof jwtPayload.exp != "number"
missingIssClaimCondition = !jwtPayload.iss
missingJtiClaimCondition = !jwtPayload.jti
missingAlgHeaderCondition = !jwtHeaders.alg
invalidJtiClaimCondition = typeof jwtPayload.jti != "string"
invalidAlgHeaderCondition = jwtHeaders.alg != "RS512"
jtiExistsInCacheCondition = cachedJtiValue == jwtPayload.jti
// JS Date constructor uses milliseconds, exp uses seconds, so multiply exp by 1000 to convert to ms
jwtExpiredCondition = new Date() > new Date(jwtPayload.exp * 1000)
// We advise to limit expiry time to now + 5 minutes. Allowing an extra 10 seconds to mitigate edge cases:
expClaimTooLongCondition = expExpiry > 310
missingAudCondtion = !jwtPayload.aud

// Set the error message to the first error condition that returns true
context.setVariable('InvalidJwt.ErrorMessage',
  jwtExpiredCondition && jwtExpiredMessage
  || invalidAlgHeaderCondition && invalidAlgHeaderMessage
  || missingAlgHeaderCondition && missingAlgHeaderMessage
  || missingKidCondition && missingKidMessage
  || missingOrInvalidTypCondition && missingOrInvalidTypMessage
  || missingExpClaimCondition && missingExpClaimMessage
  || invalidExpiryTimeCondition && invalidExpiryTimeMessage
  || missingJtiClaimCondition && missingJtiClaimMessage
  || missingIssClaimCondition && missingIssClaimMessage
  || invalidJtiClaimCondition && invalidJtiMessage
  // Checking that the JTI exists in the cache should happen after checking that the JTI is valid
  || expClaimTooLongCondition && expClaimTooLongMessage
  || missingAudCondtion && missingAudMessage
  || noErrorMessage
)

