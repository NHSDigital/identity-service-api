jwksString = context.getVariable('jwks');
jwksObj = JSON.parse(jwksString);
kid = context.getVariable('jwt.DecodeJWT.FromExternalIdToken.decoded.header.kid');

jwks_kid_found = false;

for (var i = 0; i < jwksObj.keys.length; i++) {
  if (kid == jwksObj.keys[i].kid) {
      jwks_kid_found = true;
  }
}

context.setVariable('jwks_kid_found', jwks_kid_found);
