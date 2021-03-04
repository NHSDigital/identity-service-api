jwksString = context.getVariable('jwks');
jwksObj = JSON.parse(jwksString)
kid = context.getVariable('jwt.DecodeJWT.FromSubjectTokenFormParam.decoded.header.kid');
id_token_kid=jwksObj.keys[0].kid;

print(jwksObj.keys[0].kid);
print(kid);

token_updated='true';
if (kid != id_token_kid) {
  token_updated='false'
}

context.setVariable('token_updated', token_updated);
