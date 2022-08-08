var urlvalue = 'https://raw.githubusercontent.com/NHSDigital/identity-service-jwks/6c88da16dd898ab53b5f5ea97174c826a35d10b7/jwks/int/f6bcd6f9-1eb5-40c2-9020-4d57ea73f911.json';//'verifyapikey.VerifyAPIKey.FromJWT.jwks-resource-url');
var re = new RegExp('^(https?:\/\/[^/]+)(\/.*)$');
var match = re.exec(urlvalue);
if (match) {
  context.setVariable('servicecallout.ServiceCallout.ClientCredentialsGrantGetJWKS.target.url', match[1]);
  context.setVariable('sc_urlPath', match[2]);
}
