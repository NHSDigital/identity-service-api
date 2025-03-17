function extractJsonVariable(contextVariableName) {
  return JSON.parse(
    context.getVariable(
      "jwt.DecodeJWT.FromSubjectTokenFormParam." + contextVariableName
    )
  );
}

function createError(message, statusCode) {
  return {
    errorMessage: message,
    statusCode: statusCode,
  };
}

const jwtHeaders = extractJsonVariable("header-json");
const jwtPayload = extractJsonVariable("payload-json");

// Declare error message strings
// Headers
const missingKidMessage = "Missing 'kid' header in subject_token JWT";
const missingOrInvalidTypMessage =
  "Invalid 'typ' header in subject_token JWT - must be 'JWT'";
const missingAlgHeaderMessage = "Missing 'alg' header in subject_token JWT";
// Claims
const missingExpClaimMessage = "Missing 'exp' claim in subject_token JWT";
const invalidExpiryTimeMessage =
  "Invalid 'exp' claim in subject_token JWT - must be an integer";
const jwtExpiredMessage =
  "Invalid 'exp' claim in subject_token JWT - JWT has expired";
const missingIssClaimMessage = "Missing 'iss' claim in subject_token JWT";
const missingAudMessage = "Missing 'aud' claim in subject_token JWT";
const noErrorMessage = "";

// Set conditions for triggering error messages
// Headers
const missingKidCondition = !jwtHeaders.kid;
const missingOrInvalidTypCondition =
  typeof jwtHeaders.typ != "string" || jwtHeaders.typ.toLowerCase() != "jwt";
const missingAlgHeaderCondition = !jwtHeaders.alg;
// Claims
const missingExpClaimCondition = !jwtPayload.exp;
const invalidExpiryTimeCondition = typeof jwtPayload.exp != "number";
// JS Date constructor uses milliseconds, exp uses seconds, so multiply exp by 1000 to convert to ms
const jwtExpiredCondition = new Date() > new Date(jwtPayload.exp * 1000);
const missingIssClaimCondition = !jwtPayload.iss;
const missingAudCondtion = !jwtPayload.aud;

// Set the error message to the first error condition that returns true
const err =
  (jwtExpiredCondition && createError(jwtExpiredMessage, 400)) ||
  (missingAlgHeaderCondition && createError(missingAlgHeaderMessage, 400)) ||
  (missingKidCondition && createError(missingKidMessage, 400)) ||
  (missingOrInvalidTypCondition && createError(missingOrInvalidTypMessage, 400)) ||
  (missingExpClaimCondition && createError(missingExpClaimMessage, 400)) ||
  (invalidExpiryTimeCondition && createError(invalidExpiryTimeMessage, 400)) ||
  (missingIssClaimCondition && createError(missingIssClaimMessage, 400)) ||
  (missingAudCondtion && createError(missingAudMessage, 401)) ||
  createError(noErrorMessage, 200);

context.setVariable("invalid_jwt.error_message", err.errorMessage);
context.setVariable("invalid_jwt.error_status_code", err.statusCode);
