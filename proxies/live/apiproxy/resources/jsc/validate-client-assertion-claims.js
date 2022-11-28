function extractJsonVariable(contextVariableName) {
  return JSON.parse(
    context.getVariable(
      "jwt.DecodeJWT.FromClientAssertionFormParam." + contextVariableName
    )
  );
}

const jwtHeaders = extractJsonVariable("header-json");
const jwtPayload = extractJsonVariable("payload-json");
const expExpiry = extractJsonVariable("seconds_remaining");
const cachedJtiValue = context.getVariable("JTICachedValue");

// Declare error message strings
// Headers
const missingKidMessage = "Missing 'kid' header in client_assertion JWT";
const missingOrInvalidTypMessage =
  "Invalid 'typ' header in client_assertion JWT - must be 'JWT'";
const missingAlgHeaderMessage = "Missing 'alg' header in client_assertion JWT";
const invalidAlgHeaderMessage =
  "Invalid 'alg' header in client_assertion JWT - unsupported JWT algorithm - must be 'RS512'";
// Claims
const missingExpClaimMessage = "Missing 'exp' claim in client_assertion JWT";
const invalidExpiryTimeMessage =
  "Invalid 'exp' claim in client_assertion JWT - must be an integer";
const expClaimTooLongMessage =
  "Invalid 'exp' claim in client_assertion JWT - more than 5 minutes in future";
const jwtExpiredMessage =
  "Invalid 'exp' claim in client_assertion JWT - JWT has expired";
const missingOrInvalidIssClaimMessage =
  "Missing or non-matching iss/sub claims in client_assertion JWT";
const missingJtiClaimMessage = "Missing 'jti' claim in client_assertion JWT";
const invalidJtiMessage =
  "Invalid 'jti' claim in client_assertion JWT - must be a unique string value such as a GUID";
const jtiExistsInCacheMessage = "Non-unique jti claim in client_assertion JWT";
const noErrorMessage = "";

// Set conditions for triggering error messages
// Headers
const missingKidCondition = !jwtHeaders.kid;
const missingOrInvalidTypCondition =
  typeof jwtHeaders.typ != "string" || jwtHeaders.typ.toLowerCase() != "jwt";
const missingAlgHeaderCondition = !jwtHeaders.alg;
const invalidAlgHeaderCondition = jwtHeaders.alg != "RS512";
// Claims
const missingExpClaimCondition = !jwtPayload.exp;
const invalidExpiryTimeCondition = typeof jwtPayload.exp != "number";
// JS Date constructor uses milliseconds, exp uses seconds, so multiply exp by 1000 to convert to ms
const jwtExpiredCondition = new Date() > new Date(jwtPayload.exp * 1000);
// We advise to limit expiry time to now + 5 minutes. Allowing an extra 10 seconds to mitigate edge cases:
const expClaimTooLongCondition = expExpiry > 310;
const missingOrInvalidIssClaimCondition =
  !jwtPayload.iss || jwtPayload.iss != jwtPayload.sub;
const missingJtiClaimCondition = !jwtPayload.jti;
const invalidJtiClaimCondition = typeof jwtPayload.jti != "string";
const jtiExistsInCacheCondition = cachedJtiValue == jwtPayload.jti;

// Set the error message to the first error condition that returns true
context.setVariable(
  "InvalidJwt.ErrorMessage",
  (invalidAlgHeaderCondition && invalidAlgHeaderMessage) ||
    (invalidAlgHeaderCondition && invalidAlgHeaderMessage) ||
    (jwtExpiredCondition && jwtExpiredMessage) ||
    (missingKidCondition && missingKidMessage) ||
    (missingOrInvalidTypCondition && missingOrInvalidTypMessage) ||
    (missingExpClaimCondition && missingExpClaimMessage) ||
    (invalidExpiryTimeCondition && invalidExpiryTimeMessage) ||
    (missingOrInvalidIssClaimCondition && missingOrInvalidIssClaimMessage) ||
    (missingJtiClaimCondition && missingJtiClaimMessage) ||
    (invalidJtiClaimCondition && invalidJtiMessage) ||
    // Checking that the JTI exists in the cache should happen after checking that the JTI is valid
    (jtiExistsInCacheCondition && jtiExistsInCacheMessage) ||
    (expClaimTooLongCondition && expClaimTooLongMessage) ||
    noErrorMessage
);
