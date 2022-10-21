
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

var MissingKidHeader = true
var InvalidExpiryTime = true

if(typeof jwtPayload.exp == "number") InvalidExpiryTime = false

if (jwtHeaders.kid) MissingKidHeader = false

context.setVariable('InvalidJwt.MissingKidHeader', MissingKidHeader);
context.setVariable('InvalidJwt.InvalidExpiryTimeType', InvalidExpiryTime);
