var auth_grant_type = '' // apigee doesn't support token_exchange. This variable holds the "correct" auth grant_type
var auth_type = 'app'
var level = ''
var user_id = ''

var grant_type = context.getVariable('request.formparam.grant_type')
var pathsuffix = context.getVariable('proxy.pathsuffix')
if (grant_type === 'authorization_code' || pathsuffix === '/authorize' || pathsuffix === '/callback') {
  auth_grant_type = 'authorization_code'
  auth_type = 'user'
  provider = getProvider()
  if (pathsuffix === '/authorize') {
    level = ''
    user_id = ''
  } else {
    if (provider.includes('nhs-login')) {
      proofing_level = context.getVariable('jwt.DecodeJWT.FromExternalIdToken.claim.identity_proofing_level')

      level = getLevel(proofing_level)
      user_id = context.getVariable('jwt.DecodeJWT.FromExternalIdToken.claim.nhs_number')
    } else {
      claim_acr = context.getVariable('jwt.DecodeJWT.FromExternalIdToken.claim.authentication_assurance_level')

      level = getLevel(claim_acr)
      user_id = context.getVariable('jwt.DecodeJWT.FromExternalIdToken.claim.subject')
    }
  }

} else if (context.getVariable('request.formparam.subject_token')) {
  auth_grant_type = 'token_exchange'
  auth_type = 'user'
  provider = getProvider()
  scope = context.getVariable('apigee.user_restricted_scopes')
  level = getLevel(scope)

  if (provider.includes('nhs-login')) {
    user_id = user_id = context.getVariable('jwt.VerifyJWT.SubjectToken.claim.nhs_number')
  } else {
    user_id = context.getVariable('jwt.VerifyJWT.SubjectToken.claim.subject')
  }

} else {
  auth_grant_type = 'client_credentials'
  auth_type = 'app'
  provider = 'apim'
  user_id = ''
  scope = context.getVariable('apigee.application_restricted_scopes')
  level = getLevel(scope)
}

// Populate variables; these are embedded into apigee access token
context.setVariable('splunk.auth.grant_type', auth_grant_type)
context.setVariable('splunk.auth.type', auth_type)
context.setVariable('splunk.auth.provider', provider)
context.setVariable('splunk.auth.level', level)
context.setVariable('splunk.auth.user_id', user_id)

// Populate variables; these are used in LogToSplunk shared-flow. IS doesn't have VerifyAccessToken that's why we need to populate these manually.
context.setVariable('accesstoken.auth_grant_type', auth_grant_type)
context.setVariable('accesstoken.auth_type', auth_type)
context.setVariable('accesstoken.auth_level', level)
context.setVariable('accesstoken.auth_provider', provider)
context.setVariable('accesstoken.auth_user_id', user_id)

function getProvider() {
  var cis2_issuer = context.getVariable('identity-service-config.cis2.issuer')
  var is_mock_cis2_provider = cis2_issuer.includes('api.service.nhs.uk') || cis2_issuer.includes('identity.ptl.api.platform.nhs.uk')

  var nhs_login_issuer = context.getVariable('identity-service-config.nhs_login.issuer')
  var is_mock_nhs_login_provider = nhs_login_issuer.includes('api.service.nhs.uk') || nhs_login_issuer.includes('identity.ptl.api.platform.nhs.uk')

  var is_nhs_login = context.getVariable('idp') === 'nhs-login'
    || context.getVariable('jwt.DecodeJWT.FromExternalIdToken.claim.nhs_number')
    || context.getVariable('jwt.VerifyJWT.SubjectToken.claim.nhs_number')

  var provider = ''
  if (is_nhs_login) {
    if (is_mock_nhs_login_provider) {
      provider = 'apim-mock-nhs-login'
    } else {
      provider = 'nhs-login'
    }
  } else {
    if (is_mock_cis2_provider) {
      provider = 'apim-mock-nhs-cis2'
    } else {
      provider = 'nhs-cis2'
    }
  }

  return provider
}

function getLevel(level) {
  if (level) {
    level = level.toLowerCase()

    if (level.includes(3)) {
      return 'aal3'
    }
    if (level.includes(2)) {
      return 'aal2'
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
