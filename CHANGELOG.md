# Changelog
All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [v2.0.5](https://github.com/in2workspace/in2-verifier-api/releases/tag/v2.0.5)
### Fixed
- Small text fixes in login template. 

## [v2.0.4](https://github.com/in2workspace/in2-verifier-api/releases/tag/v2.0.4)
### Removed
- Remove hardcoded visible "DOME" references in UI.

## [v2.0.3](https://github.com/in2workspace/in2-verifier-api/releases/tag/v2.0.3)
### Changed
- For frontend pages, set language from Accept-Language header before using default language.

## [v2.0.2](https://github.com/in2workspace/in2-verifier-api/releases/tag/v2.0.2)
### Added
- Get default language from configuration, use it to translate HTML templates.

## [v2.0.1](https://github.com/in2workspace/in2-verifier-api/releases/tag/v2.0.1)
- ### Added
- Implement Authorization Code Flow with PKCE

## [v2.0.0](https://github.com/in2workspace/in2-verifier-api/releases/tag/v2.0.0)
- New major version to align with the new major version of EUDIStack project.

## [v1.3.11](https://github.com/in2workspace/in2-verifier-api/releases/tag/v1.3.10)
### Added
- Added revocation function for new credentials with credentialStatus.
- Test for verify that is working the revocation

## [v1.3.10](https://github.com/in2workspace/in2-verifier-api/releases/tag/v1.3.10)
### Added
- Added access for prometheus at spring security at matcher.

## [v1.3.9](https://github.com/in2workspace/in2-verifier-api/releases/tag/v1.3.9)
### Added
- Added access for prometheus at spring security.

## [v1.3.8](https://github.com/in2workspace/in2-verifier-api/releases/tag/v1.3.8)
### Added
- Validated audience and nonce for OpenID4VP.
- Added specific OpenID4VP exceptions.
- Handled type claim in Authorization Request.

## [v1.3.7](https://github.com/in2workspace/in2-verifier-api/releases/tag/v1.3.7)
### Fixed
- Modify the response token according to the grant type (client_credentials should not include id_token or 
refresh_token).
- Set the scopes profile and email in the response id_token, regardless of whether they are sent in the request.
- Change the client_id_schema to did:key in the authorization request.
- Modify the client_id in the response access_token so that it returns the URL.
- Add LEARCredentialMachine.
- Extract DID Key as environment variable.

## [v1.3.6](https://github.com/in2workspace/in2-verifier-api/releases/tag/v1.3.6)
### Fixed
- Add compatibility on LEARCredentialEmployee v2.0 for LEARCredential v1.0 claims

## [v1.3.5](https://github.com/in2workspace/in2-verifier-api/releases/tag/v1.3.5)
### Fixed
- Problem related to the M2M vp_token validation

## [v1.3.4](https://github.com/in2workspace/in2-verifier-api/releases/tag/v1.3.4)
### Fixed
- Problem logging in with token when the login time has run out.

## [v1.3.3](https://github.com/in2workspace/in2-verifier-api/releases/tag/v1.3.3)
### Fixed
- Problem with issuer serialization

## [v1.3.2](https://github.com/in2workspace/in2-verifier-api/releases/tag/v1.3.2)
### Fixed
- Access token timeout

## [v1.3.1](https://github.com/in2workspace/in2-verifier-api/releases/tag/v1.3.1)
### Fixed
- Error on JsonProperty annotation in the LEARCredential

## [v1.3.0](https://github.com/in2workspace/in2-verifier-api/releases/tag/v1.3.0)
### Added
- Compatibility for LEARCredentialEmployee v2.0

## [v1.2.1](https://github.com/in2workspace/in2-verifier-api/releases/tag/v1.2.1)
### Modified
- Updated DOME Logo

## [v1.2.0](https://github.com/in2workspace/in2-verifier-api/releases/tag/v1.2.0)
### Modified
- Updated Login page UI
- Refactor configuration parameters: removed unnecessary ones and grouped internal ones into frontend/backend categories.

## [v1.1.0](https://github.com/in2workspace/in2-verifier-api/releases/tag/v1.1.0)
### Added
- Add refresh token support for the OpenID Connect flow
- Add nonce support for the OpenID Connect authorization code flow

## [v1.0.17](https://github.com/in2workspace/in2-verifier-api/releases/tag/v1.0.17)
### Added
- Add documentation for OIDC client registration and interaction with the verifier.

## [v1.0.16](https://github.com/in2workspace/in2-verifier-api/releases/tag/v1.0.16)
### Fixed
- Add time window validation for the credential in the Verifiable Presentation

## [v1.0.15](https://github.com/in2workspace/in2-verifier-api/releases/tag/v1.0.15)
### Fixed
- Fix token serialization issue
- Add cors config for registered clients

## [v1.0.14](https://github.com/in2workspace/in2-verifier-api/releases/tag/v1.0.14)
### Fixed
- Rename the verifiableCredential claim of the access token to vc

## [v1.0.13](https://github.com/in2workspace/in2-verifier-api/releases/tag/v1.0.13)
### Fixed
- Fix contact us link not working

## [v1.0.12](https://github.com/in2workspace/in2-verifier-api/releases/tag/v1.0.12)
### Fixed
- Unauthorized Http response code for failed validation of VP token

## [v1.0.11](https://github.com/in2workspace/in2-verifier-api/releases/tag/v1.0.11)
### Fixed
- Add cors configuration to allow requests from external wallets, on the endpoints the wallet use.

## [v1.0.10](https://github.com/in2workspace/in2-verifier-api/releases/tag/v1.0.10)
### Fixed
- Add an error page for errors during the client authentication request.

## [v1.0.9](https://github.com/in2workspace/in2-verifier-api/releases/tag/v1.0.9)
### Fixed
- Fix images url
- Fix spacing between navbar and content for tablets width range

## [v1.0.8](https://github.com/in2workspace/in2-verifier-api/releases/tag/v1.0.8)
### Fixed
- Fix color contrast 
- Use brand colors, font and favicon
- Fix layout responsiveness

## [v1.0.7](https://github.com/in2workspace/in2-verifier-api/releases/tag/v1.0.7)
### Fixed
- Fix the JWKS endpoint response to use the claim `use` with `sig` value.

## [v1.0.6](https://github.com/in2workspace/in2-verifier-api/releases/tag/v1.0.6)
### Fixed
- Authentication request fix to comply with the OpenID Connect Core standard.

## [v1.0.5](https://github.com/in2workspace/in2-verifier-api/releases/tag/v1.0.5)
### Fixed
- Token response fix to comply with the OpenID Connect Core standard.

## [v1.0.4](https://github.com/in2workspace/in2-verifier-api/releases/tag/v1.0.4)
### Fixed
- Fix security issue with the signature verification.

## [v1.0.3](https://github.com/in2workspace/in2-verifier-api/releases/tag/v1.0.3)
### Added
- Support for OpenID Connect.
  - Only uses Authentication using the Authorization Code Flow (without PKCE).
  - Only uses Claims with Requesting Claims using Scope Values (openid learcredential)
  - Only uses Passing Request Parameters as JWTs (Passing a Request Object by Reference).
  - Only use Client Authentication method with Private Key JWT.
  - Only uses for P-256 ECDSA keys for Signing Access Token.
- Support for OpenID for Verifiable Presentations (OID4VP).
  - Implement VP Proof of Possession verification.
  - Implement Issuers, Participants and Services verification against the DOME Trust Framework.
  - Implement VC verification against the DOME Revoked Credentials List.
- Support FAPI
  - Only use request_uri as a REQUIRED claim in the Authentication Request Object.
- Implement DOME Human-To-Machine (H2M) authentication.
  - Implement Login page with QR code.
- Implement DOME Machine-To-Machine (M2M) authentication.
- Integrate with the DOME Trust Framework.

### Fixed
- Fix the issue with Login page not showing Wallet URL.
- Fix the issue with Login page not valid Registration URL.
- Fix the issue with Login page not redirecting to the Relying Party after expiration of the QR code.
