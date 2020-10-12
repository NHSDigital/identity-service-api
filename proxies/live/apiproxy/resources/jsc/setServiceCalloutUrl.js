var urlvalue = context.getVariable('verifyapikey.VerifyAPIKey.FromJWT.jwks-resource-url');
var re = new RegExp('^(https?:\/\/[^/]+)(\/.*)$');
var match = re.exec(urlvalue);
if (match) {
  context.setVariable('servicecallout.ServiceCallout.GetJWKS.target.url', match[1]);
  context.setVariable('sc_urlPath', match[2]);
}
