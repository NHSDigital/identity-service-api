function extractJsonVariable(contextVariableName) {
  return JSON.parse(
    context.getVariable(
      "jwt.DecodeJWT.FromSubjectTokenFormParam." + contextVariableName
    )
  );
}

const jwtHeaders = extractJsonVariable("header-json");
const jwtPayload = extractJsonVariable("payload-json");
// const cachedJtiValue = context.getVariable("JTICachedValue");
const expExpiry = context.getVariable(
  "jwt.DecodeJWT.DecodeJWT.FromSubjectTokenFormParam.seconds_remaining"
);

// Declare error message strings
// Headers
const missingKidMessage = "Missing 'kid' header in subject_token JWT";
const missingOrInvalidTypMessage =
  "Invalid 'typ' header in subject_token JWT - must be 'JWT'";
const missingAlgHeaderMessage = "Missing 'alg' header in subject_token JWT";
// Claims
const missingExpClaimMessage = "Missing 'exp' claim in subject_token JWT";
const expClaimTooLongMessage =
  "Invalid 'exp' claim in subject_token JWT - more than 5 minutes in future";
const invalidExpiryTimeMessage =
  "Invalid 'exp' claim in subject_token JWT - must be an integer";
const jwtExpiredMessage =
  "Invalid 'exp' claim in subject_token JWT - JWT has expired";
const missingIssClaimMessage = "Missing 'iss' claim in subject_token JWT";
const missingAudMessage = "Missing 'aud' claim in subject_token JWT";
// TO DO - is jti needed here? Not used on cis2
// missingJtiClaimMessage = "Missing jti claim in subject_token JWT"
// invalidJtiMessage = "Jti claim in subject_token must be a unique string value such as a GUID"
// jtiExistsInCacheMessage = "Non-unique jti claim in subject_token JWT"
const noErrorMessage = "";

// Set conditions for triggering error messages
const missingKidCondition = !jwtHeaders.kid;
const missingOrInvalidTypCondition =
  typeof jwtHeaders.typ != "string" || jwtHeaders.typ.toLowerCase() != "jwt";
const missingAlgHeaderCondition = !jwtHeaders.alg;
const missingExpClaimCondition = !jwtPayload.exp;
const invalidExpiryTimeCondition = typeof jwtPayload.exp != "number";
// JS Date constructor uses milliseconds, exp uses seconds, so multiply exp by 1000 to convert to ms
const jwtExpiredCondition = new Date() > new Date(jwtPayload.exp * 1000);
// We advise to limit expiry time to now + 5 minutes. Allowing an extra 10 seconds to mitigate edge cases:
const expClaimTooLongCondition = expExpiry > 310;
const missingIssClaimCondition = !jwtPayload.iss;
const missingAudCondtion = !jwtPayload.aud;
// missingJtiClaimCondition = !jwtPayload.jti
// invalidJtiClaimCondition = typeof jwtPayload.jti != "string"
// jtiExistsInCacheCondition = cachedJtiValue == jwtPayload.jti

// Set the error message to the first error condition that returns true
context.setVariable(
  "InvalidJwt.ErrorMessage",
  (jwtExpiredCondition && jwtExpiredMessage) ||
    (missingAlgHeaderCondition && missingAlgHeaderMessage) ||
    (missingKidCondition && missingKidMessage) ||
    (missingOrInvalidTypCondition && missingOrInvalidTypMessage) ||
    (missingExpClaimCondition && missingExpClaimMessage) ||
    (invalidExpiryTimeCondition && invalidExpiryTimeMessage) ||
    // || missingJtiClaimCondition && missingJtiClaimMessage
    (missingIssClaimCondition && missingIssClaimMessage) ||
    // || invalidJtiClaimCondition && invalidJtiMessage
    // Checking that the JTI exists in the cache should happen after checking that the JTI is valid
    (expClaimTooLongCondition && expClaimTooLongMessage) ||
    (missingAudCondtion && missingAudMessage) ||
    noErrorMessage
);
