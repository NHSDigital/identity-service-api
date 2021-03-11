jwksString = context.getVariable('jwks');
jwksObj = JSON.parse(jwksString);
kid = context.getVariable('jwt.DecodeJWT.FromExternalIdToken.decoded.header.kid');

token_updated='false';

for (var i = 0; i < jwksObj.keys.length; i++) {
  if (kid == jwksObj.keys[i].kid) {
      token_updated='true';
  }
}

context.setVariable('token_updated', token_updated);
