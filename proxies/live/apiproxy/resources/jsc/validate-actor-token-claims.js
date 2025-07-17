function extractJsonVariable(contextVariableName) {
  return JSON.parse(
    context.getVariable(
      "jwt.DecodeJWT.FromActToken." + contextVariableName
    )
  );
}

function createError(message, statusCode) {
  return {
    errorMessage: message,
    statusCode: statusCode,
  };
}


// === act.sub JWT Error Messages ===
const actMissingKidMessage = "Missing 'kid' header in act.sub JWT";
const actMissingOrInvalidTypMessage =
  "Invalid 'typ' header in act.sub JWT - must be 'JWT'";
const actMissingAlgHeaderMessage = "Missing 'alg' header in act.sub JWT";
const actMissingExpClaimMessage = "Missing 'exp' claim in act.sub JWT";
const actInvalidExpiryTimeMessage =
  "Invalid 'exp' claim in act.sub JWT - must be an integer";
const actMissingIssMessage = "Missing 'iss' claim in act.sub JWT";
const actMissingAudMessage = "Missing 'aud' claim in act.sub JWT";
const actMissingNhsNumMessage = "Missing 'nhs_number' claim in act.sub JWT";
const actCorruptJwtMessage = "act.sub JWT is corrupt or unparseable";
const noErrorMessage = "";


function validateActJwt(header, payload) {
  if (!header.kid) return createError(actMissingKidMessage, 400);
  if (typeof header.typ !== "string" || header.typ.toLowerCase() !== "jwt")
    return createError(actMissingOrInvalidTypMessage, 400);
  if (!header.alg) return createError(actMissingAlgHeaderMessage, 400);
  if (!payload.exp) return createError(actMissingExpClaimMessage, 400);
  if (typeof payload.exp !== "number")
    return createError(actInvalidExpiryTimeMessage, 400);
  if (!payload.iss) return createError(actMissingIssMessage, 400);
  if (!payload.aud) return createError(actMissingAudMessage, 400);
  if (!payload.nhs_number)
    return createError(actMissingNhsNumMessage, 400);

  return null;
}

// === Main Execution ===
const jwtHeaders = extractJsonVariable("header-json");
const jwtPayload = extractJsonVariable("payload-json");
var err = validateActJwt(jwtHeaders, jwtPayload);
var actor_id = '';
var delegated = 'true';
if (!err) {
  err = createError(noErrorMessage, 200);
  actor_id = jwtPayload.nhs_number;
}

// === Output to Apigee Variables ===
context.setVariable("jwt.act.nhs_number", actor_id);
context.setVariable("jwt.act.delegation", delegated);
context.setVariable("invalid_jwt.error_message", err.errorMessage);
context.setVariable("invalid_jwt.error_status_code", err.statusCode);
