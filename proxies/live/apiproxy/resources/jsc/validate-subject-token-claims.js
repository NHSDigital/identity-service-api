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

function decodeNestedJWT(jwt) {
  const parts = jwt.split(".");
  if (parts.length !== 3) return null;
  try {
    const header = JSON.parse(atob(parts[0]));
    const payload = JSON.parse(atob(parts[1]));
    return { header, payload };
  } catch (e) {
    return null;
  }
}

// === Subject Token Error Messages ===
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

// === act.sub JWT Error Messages ===
const actMissingKidMessage = "Missing 'kid' header in act.sub JWT";
const actMissingOrInvalidTypMessage = "Invalid 'typ' header in act.sub JWT - must be 'JWT'";
const actMissingAlgHeaderMessage = "Missing 'alg' header in act.sub JWT";
const actMissingExpClaimMessage = "Missing 'exp' claim in act.sub JWT";
const actInvalidExpiryTimeMessage = "Invalid 'exp' claim in act.sub JWT - must be an integer";
const actMissingIssMessage = "Missing 'iss' claim in act.sub JWT";
const actMissingAudMessage = "Missing 'aud' claim in act.sub JWT";
const actCorruptJwtMessage = "act.sub JWT is corrupt or unparseable";

// === Main JWT Validations ===
function validateJwt(header, payload) {
  // header validations
  if (!header.kid) return createError(missingKidMessage, 400);
  if (typeof header.typ !== "string" || header.typ.toLowerCase() !== "jwt")
    return createError(missingOrInvalidTypMessage, 400);
  if (!header.alg) return createError(missingAlgHeaderMessage, 400);
  // payload validations
  if (!payload.exp) return createError(missingExpClaimMessage, 400);
  if (typeof payload.exp !== "number")
    return createError(invalidExpiryTimeMessage, 400);
  if (new Date() > new Date(payload.exp * 1000))
    return createError(jwtExpiredMessage, 400);
  if (!payload.iss) return createError(missingIssClaimMessage, 400);
  if (!payload.aud) return createError(missingAudMessage, 401);

  return null;
}

// === Nested JWT Validations ===
function validateActJwt(header, payload) {
  // header validations
  if (!header.kid) return createError(actMissingKidMessage, 400);
  if (typeof header.typ !== "string" || header.typ.toLowerCase() !== "jwt")
    return createError(actMissingOrInvalidTypMessage, 400);
  if (!header.alg) return createError(actMissingAlgHeaderMessage, 400);
  // payload validations
  if (!payload.exp) return createError(actMissingExpClaimMessage, 400);
  if (typeof payload.exp !== "number")
    return createError(actInvalidExpiryTimeMessage, 400);
  if (!payload.iss) return createError(actMissingIssMessage, 400);
  if (!payload.aud) return createError(actMissingAudMessage, 401);

  return null;
}

// === Process Subject Token ===
const jwtHeaders = extractJsonVariable("header-json");
const jwtPayload = extractJsonVariable("payload-json");
let err = validateJwt(jwtHeaders, jwtPayload);
if (!err) err = createError(noErrorMessage, 200);

// ===  Conditional act.sub Validation (only if no error above) ===
if (err.errorMessage === "" && (jwtPayload.act && typeof jwtPayload.act.sub === "string")) {
  const nestedJwt = decodeNestedJWT(jwtPayload.act.sub);
  if (!nestedJwt) {
    err = createError(actCorruptJwtMessage, 400);
  } else {
    const nestedErr = validateJwt(nestedJwt.header, nestedJwt.payload);
    if (nestedErr) err = nestedErr;
  }
}

// === Unified Output ===
context.setVariable("invalid_jwt.error_message", err.errorMessage);
context.setVariable("invalid_jwt.error_status_code", err.statusCode);