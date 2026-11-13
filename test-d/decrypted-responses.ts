// Type-level regression tests. Nothing here runs; compilation is the assertion.
import * as client from 'openid-client'

type Equals<A, B> = [A] extends [B] ? ([B] extends [A] ? true : never) : never

declare const authorizationCode: Awaited<
  ReturnType<typeof client.authorizationCodeGrant>
>
declare const refreshToken: Awaited<ReturnType<typeof client.refreshTokenGrant>>
declare const deviceCode: Awaited<
  ReturnType<typeof client.pollDeviceAuthorizationGrant>
>
declare const backchannelAuthentication: Awaited<
  ReturnType<typeof client.pollBackchannelAuthenticationGrant>
>
declare const genericGrant: Awaited<
  ReturnType<typeof client.genericGrantRequest>
>
declare const implicitAuthentication: Awaited<
  ReturnType<typeof client.implicitAuthentication>
>
declare const userInfo: Awaited<ReturnType<typeof client.fetchUserInfo>>
declare const introspection: Awaited<
  ReturnType<typeof client.tokenIntrospection>
>

const decryptedAuthorizationCode =
  client.getDecryptedResponses(authorizationCode)
const decryptedRefreshToken = client.getDecryptedResponses(refreshToken)
const decryptedDeviceCode = client.getDecryptedResponses(deviceCode)
const decryptedBackchannelAuthentication = client.getDecryptedResponses(
  backchannelAuthentication,
)
const decryptedGenericGrant = client.getDecryptedResponses(genericGrant)
const decryptedImplicitAuthentication = client.getDecryptedResponses(
  implicitAuthentication,
)
const decryptedUserInfo = client.getDecryptedResponses(userInfo)
const decryptedIntrospection = client.getDecryptedResponses(introspection)

const _authorizationCode: Equals<
  typeof decryptedAuthorizationCode,
  client.DecryptedAuthorizationCodeResponses | undefined
> = true
const _refreshToken: Equals<typeof decryptedRefreshToken, string | undefined> =
  true
const _deviceCode: Equals<typeof decryptedDeviceCode, string | undefined> = true
const _backchannelAuthentication: Equals<
  typeof decryptedBackchannelAuthentication,
  string | undefined
> = true
const _genericGrant: Equals<typeof decryptedGenericGrant, string | undefined> =
  true
const _implicitAuthentication: Equals<
  typeof decryptedImplicitAuthentication,
  string | undefined
> = true
const _userInfo: Equals<typeof decryptedUserInfo, string | undefined> = true
const _introspection: Equals<
  typeof decryptedIntrospection,
  string | undefined
> = true

const _tokenEndpointIdToken: string | undefined =
  decryptedAuthorizationCode?.id_token?.token_endpoint
const _authorizationEndpointIdToken: string | undefined =
  decryptedAuthorizationCode?.id_token?.authorization_endpoint
const _authorizationResponse: string | undefined =
  decryptedAuthorizationCode?.authorization_response

// @ts-expect-error Decryption support is configured at runtime.
decryptedAuthorizationCode.id_token
// @ts-expect-error Code grants return a structured record, not a compact JWS.
const _codeIsNotAString: string | undefined = decryptedAuthorizationCode
// @ts-expect-error Other token grants return a compact JWS, not a record.
decryptedRefreshToken?.id_token
// @ts-expect-error Implicit authentication returns a compact JWS, not a record.
decryptedImplicitAuthentication?.id_token
// @ts-expect-error UserInfo returns a compact JWS, not a record.
decryptedUserInfo?.userinfo
// @ts-expect-error Introspection returns a compact JWS, not a record.
decryptedIntrospection?.introspection
// @ts-expect-error Code grant records do not contain UserInfo responses.
decryptedAuthorizationCode?.userinfo
// @ts-expect-error Only processed response objects are accepted.
client.getDecryptedResponses('compact JWS')

if (decryptedAuthorizationCode) {
  // @ts-expect-error Decrypted response records are readonly.
  decryptedAuthorizationCode.authorization_response = 'compact JWS'
  // @ts-expect-error Decrypted response records are readonly.
  decryptedAuthorizationCode.id_token = {}
  if (decryptedAuthorizationCode.id_token) {
    // @ts-expect-error ID Token sources are readonly.
    decryptedAuthorizationCode.id_token.token_endpoint = 'compact JWS'
    // @ts-expect-error ID Token sources are readonly.
    decryptedAuthorizationCode.id_token.authorization_endpoint = 'compact JWS'
  }
}

declare const eitherResult: typeof authorizationCode | typeof userInfo
const decryptedEither = client.getDecryptedResponses(eitherResult)
const _union: Equals<
  typeof decryptedEither,
  client.DecryptedAuthorizationCodeResponses | string | undefined
> = true

// Existing public response types remain valid annotations for returned results.
const oldAuthorizationCode: client.TokenEndpointResponse &
  client.TokenEndpointResponseHelpers = authorizationCode
const oldRefreshToken: client.TokenEndpointResponse = refreshToken
const oldImplicitAuthentication: client.IDToken = implicitAuthentication
const oldUserInfo: client.UserInfoResponse = userInfo
const oldIntrospection: client.IntrospectionResponse = introspection

const decryptedOldAuthorizationCode =
  client.getDecryptedResponses(oldAuthorizationCode)
const decryptedOldRefreshToken = client.getDecryptedResponses(oldRefreshToken)
const decryptedOldImplicitAuthentication = client.getDecryptedResponses(
  oldImplicitAuthentication,
)
const decryptedOldUserInfo = client.getDecryptedResponses(oldUserInfo)
const decryptedOldIntrospection = client.getDecryptedResponses(oldIntrospection)

// Widening to an existing response interface loses the function's origin.
const _oldAuthorizationCode: Equals<
  typeof decryptedOldAuthorizationCode,
  client.DecryptedAuthorizationCodeResponses | string | undefined
> = true
const _oldRefreshToken: Equals<
  typeof decryptedOldRefreshToken,
  client.DecryptedAuthorizationCodeResponses | string | undefined
> = true
const _oldImplicitAuthentication: Equals<
  typeof decryptedOldImplicitAuthentication,
  client.DecryptedAuthorizationCodeResponses | string | undefined
> = true
const _oldUserInfo: Equals<
  typeof decryptedOldUserInfo,
  client.DecryptedAuthorizationCodeResponses | string | undefined
> = true
const _oldIntrospection: Equals<
  typeof decryptedOldIntrospection,
  client.DecryptedAuthorizationCodeResponses | string | undefined
> = true
