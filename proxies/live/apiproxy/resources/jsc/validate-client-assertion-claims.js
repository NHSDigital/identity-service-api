
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

// Set context variables based on the condition in the second argument
context.setVariable('InvalidJwt.MissingKidHeader', jwtPayload.exp == "number");
context.setVariable('InvalidJwt.InvalidExpiryTime', !!jwtHeaders.kid);
