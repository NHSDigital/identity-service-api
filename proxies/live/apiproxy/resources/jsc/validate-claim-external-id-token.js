jwksString = context.getVariable('jwks');
jwksObj = JSON.parse(jwksString);
kid = context.getVariable('jwt.DecodeJWT.FromExternalIdToken.decoded.header.kid');

jwks_updated = false;

for (var i = 0; i < jwksObj.keys.length; i++) {
  if (kid == jwksObj.keys[i].kid) {
      jwks_updated = true;
  }
}

context.setVariable('jwks_updated', jwks_updated);
