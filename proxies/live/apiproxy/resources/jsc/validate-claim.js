jwksString = context.getVariable('jwks');
jwksObj = JSON.parse(jwksString)
kid = context.getVariable('jwt.DecodeJWT.FromSubjectTokenFormParam.decoded.header.kid');

print(jwksObj.keys[0].kid);
print(kid);

token_updated='false';

for (let i = 0; i < jwksObj.keys.length; i++) {
  if (kid = jwksObj.keys[i].kid) {
    return token_updated='true'
  }
}


context.setVariable('token_updated', token_updated);
