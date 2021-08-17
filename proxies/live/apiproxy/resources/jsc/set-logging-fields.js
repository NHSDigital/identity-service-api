var grant_type = context.getVariable('request.formparam.grant_type')
var auth_grant_type = grant_type // apigee doesn't support token_exchange. This variable holds the "correct" auth grant_type
var auth_type = 'app'
var provider = 'unknown'
var level = 'unknown'
var user_id = ''

if (grant_type === 'authorization_code') {
  auth_grant_type = 'authorization_code'
  auth_type = 'user'

  var token_issuer = context.getVariable('jwt.DecodeJWT.FromExternalIdToken.claim.issuer')
  var cis2_issuer = context.getVariable('identity-service-config.cis2.issuer')
  var nhslogin_issuer = context.getVariable('identity-service-config.nhs_login.issuer')
  if (token_issuer.includes('api.service.nhs.uk')) {
    nhs_number = context.getVariable('jwt.DecodeJWT.FromExternalIdToken.claim.nhs_number')
    if (nhs_number) {
      provider = 'apim-mock-nhs-login'
    } else {
      provider = 'apim-mock-cis2'
    }
  } else if (token_issuer === cis2_issuer)
    provider = 'nhs-cis2'
  else if (token_issuer === nhslogin_issuer)
    provider = 'nhs-login'
  else
    provider = 'unknown'

  var claim_acr = context.getVariable('jwt.DecodeJWT.FromExternalIdToken.claim.acr')
  var proofing_level = context.getVariable('jwt.DecodeJWT.FromExternalIdToken.claim.identity_proofing_level')

  if (claim_acr) {
    level = getLevel(claim_acr)
  } else if (proofing_level) {
    level = getLevel(proofing_level)
  }

  if (provider === 'nsh-login' || provider === 'apim-mock-nhs-login') {
    user_id = context.getVariable('jwt.DecodeJWT.FromExternalIdToken.claim.nhs_number')
  } else {
    user_id = context.getVariable('jwt.DecodeJWT.FromExternalIdToken.claim.subject')
  }

} else {
  // Now it's either client-credentials or token-exhange.
  // We can't rely on apigee since, there is no support for token-exchange
  if (context.getVariable('request.formparam.subject_token')) { // Then it's token-exchange
    auth_grant_type = 'token_exchange'
    auth_type = 'user'

    scope = context.getVariable('apigee.user_restricted_scopes')
    level = getLevel(scope)

    issuer = context.getVariable('idTokenIssuer')
    provider = getProvider(issuer)

    if (provider === 'nhs-login' || provider === 'apim-mock-nhs-login') {
      user_id = user_id = context.getVariable('jwt.VerifyJWT.SubjectToken.claim.nhs_number')
    } else {
      user_id = context.getVariable('jwt.VerifyJWT.SubjectToken.claim.subject')
    }

  } else {
    auth_grant_type = 'client_credentials'
    auth_type = 'app'

    scope = context.getVariable('apigee.application_restricted_scopes')
    level = getLevel(scope)

    provider = 'apim'
    user_id = ''
  }
}

context.setVariable('splunk.auth.grant_type', auth_grant_type)
context.setVariable('splunk.auth.type', auth_type)
context.setVariable('splunk.auth.provider', provider)
context.setVariable('splunk.auth.level', level)
context.setVariable('splunk.auth.user_id', user_id)

// Identity Service doesn't have VerifyAccessToken. Below variables must be populated, so LogToSplunk can log auth data
context.setVariable('accesstoken.auth_grant_type', auth_grant_type)
context.setVariable('accesstoken.auth_type', auth_type)
context.setVariable('accesstoken.auth_level', level)
context.setVariable('accesstoken.auth_provider', provider)
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

function getProvider(provider) {
  if (provider) {
    provider = provider.toLowerCase()

    if (provider.includes('cis2') || provider.includes('nhscis2')) {
      return 'nhs-cis2'
    }
    if (provider.includes('nhslogin')) {
      return 'nhs-login'
    }
  }
  return 'unknown'
}
