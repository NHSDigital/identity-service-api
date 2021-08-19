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

var claim_acr = context.getVariable('jwt.DecodeJWT.FromExternalIdToken.claim.acr')
var proofing_level = context.getVariable('jwt.DecodeJWT.FromExternalIdToken.claim.identity_proofing_level')

if (claim_acr) {
  level = getLevel(claim_acr)
} else if (proofing_level) {
  level = getLevel(proofing_level)
}
context.setVariable('accesstoken.auth_level', level)

if (provider === 'nsh-login' || provider === 'apim-mock-nhs-login') {
  user_id = context.getVariable('jwt.DecodeJWT.FromExternalIdToken.claim.nhs_number')
} else {
  user_id = context.getVariable('jwt.DecodeJWT.FromExternalIdToken.claim.subject')
}
context.setVariable('accesstoken.auth_user_id', user_id)

function getLevel(level) {
  if (level) {
    level = level.toLowerCase()

    if (level.includes('aal3')) {
      return 'aal3'
    }
    if (level.includes('level3')) {
      return 'level3'
    }
    if (level.includes('p9')) {
      return 'p9'
    }
    if (level.includes('p5')) {
      return 'p5'
    }
    if (level.includes('p0')) {
      return 'p0'
    }
  }
  return 'unknown'
}
