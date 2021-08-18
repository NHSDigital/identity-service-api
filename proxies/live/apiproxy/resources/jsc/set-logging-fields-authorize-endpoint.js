context.setVariable('accesstoken.auth_grant_type', 'authorization_code')
context.setVariable('accesstoken.auth_type', 'user')

cis2_issuer = context.getVariable('identity-service-config.cis2.issuer')
is_mock_cis2_provider = cis2_issuer.includes('api.service.nhs.uk')

nhs_login_issuer = context.getVariable('identity-service-config.nhs_login.issuer')
is_mock_nhs_login_provider = nhs_login_issuer.includes('api.service.nhs.uk')

is_nhs_login = context.getVariable('idp') === 'nhs-login'
provider = ''
if (is_nhs_login) {
  if (is_mock_nhs_login_provider) {
    provider = 'apim-mock-nhs-login'
  } else {
    provider = 'nhs-login'
  }
} else {
  if (is_mock_cis2_provider) {
    provider = 'apim-mock-cis2'
  } else {
    provider = 'cis2'
  }
}
context.setVariable('accesstoken.auth_provider', provider)
context.setVariable('accesstoken.auth_level', '')
context.setVariable('accesstoken.auth_user_id', '')
