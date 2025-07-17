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

// === Subject Token Error Messages ===
const missingKidMessage = "Missing 'kid' header in subject_token JWT";
const missingOrInvalidTypMessage =
  "Invalid 'typ' header in subject_token JWT - must be 'JWT'";
const missingAlgHeaderMessage = "Missing 'alg' header in subject_token JWT";
const missingExpClaimMessage = "Missing 'exp' claim in subject_token JWT";
const invalidExpiryTimeMessage =
  "Invalid 'exp' claim in subject_token JWT - must be an integer";
const jwtExpiredMessage =
  "Invalid 'exp' claim in subject_token JWT - JWT has expired";
const missingIssClaimMessage = "Missing 'iss' claim in subject_token JWT";
const missingAudMessage = "Missing 'aud' claim in subject_token JWT";
const noErrorMessage = "";


// === JWT Validation Functions ===
function validateJwt(header, payload) {
  if (!header.kid) return createError(missingKidMessage, 400);
  if (typeof header.typ !== "string" || header.typ.toLowerCase() !== "jwt")
    return createError(missingOrInvalidTypMessage, 400);
  if (!header.alg) return createError(missingAlgHeaderMessage, 400);
  if (!payload.exp) return createError(missingExpClaimMessage, 400);
  if (typeof payload.exp !== "number")
    return createError(invalidExpiryTimeMessage, 400);
  if (new Date() > new Date(payload.exp * 1000))
    return createError(jwtExpiredMessage, 400);
  if (!payload.iss) return createError(missingIssClaimMessage, 400);
  if (!payload.aud) return createError(missingAudMessage, 401);

  return null;
}

// === Main Execution ===
const jwtHeaders = extractJsonVariable("header-json");
const jwtPayload = extractJsonVariable("payload-json");
var err = validateJwt(jwtHeaders, jwtPayload);
var is_nhs_login = false;
if (!err) {
  err = createError(noErrorMessage, 200);
  if (jwtPayload.nhs_number) {
    is_nhs_login = true;
  }
}

// === Conditional act.sub Validation ===
if (
  err.errorMessage === "" &&
  jwtPayload.act &&
  typeof jwtPayload.act.sub === "string" &&
  is_nhs_login
) {
  context.setVariable("act_jwt_token", jwtPayload.act.sub);
}

// === Output to Apigee Variables ===
context.setVariable("invalid_jwt.error_message", err.errorMessage);
context.setVariable("invalid_jwt.error_status_code", err.statusCode);
