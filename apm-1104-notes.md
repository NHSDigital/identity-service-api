apiproduct.developer.quota.limit
    verifyapikey.VerifyAPIKey.ClientId.apiproduct.developer.quota.limit
apiproduct.developer.quota.interval
    verifyapikey.VerifyAPIKey.ClientId.apiproduct.developer.quota.interval
apiproduct.developer.quota.timeunit
    verifyapikey.VerifyAPIKey.ClientId.apiproduct.developer.quota.timeunit

apiproduct.ratelimit
    verifyapikey.VerifyAPIKey.ClientId.apiproduct.ratelimit



 * Flow.GetAuthorization (Done)
    * VerifyAPIKey.ClientId
        VerifyAPIKey.ClientId.... -> apiproduct.developer.quota.interval

 * Flow.PostToken (Done)
    * VerifyAPIKey.FromClientSecretFormParam

 * Flow.PostTokenSimulatedAuth (Done)
    * VerifyAPIKey.FromClientSecretFormParam

 * Flow.PostRefreshToken
    * OAuthV2.GenerateRefreshToken

 * Flow.GetCallback - Can't
    * OAuthV2.GenerateAuthCode

 * Flow.SimulatedUserAuth - Won't

 * Flow.SimulatedUserAuthPost - Won't

 * Flow.GetUserInfo
    * OAuthV2.VerifyAccessToken

