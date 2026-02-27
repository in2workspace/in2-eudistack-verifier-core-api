****# Changelog
All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [v2.1.0] - 2026-02-27

### Added
- **Hexagonal architecture**: Reorganized entire codebase into 2 bounded contexts (`verifier/`, `oauth2/`) + `shared/` module with ports & adapters pattern.
- **Application workflows**: Extracted business logic from OAuth2 filters into testable workflow classes (AuthorizationRequestBuildWorkflow, TokenGenerationWorkflow, ClientCredentialsValidationWorkflow, VerifyPresentationWorkflow).
- **External file injection**: Clients YAML, trusted issuers YAML, and JSON Schemas can now be injected via Docker volumes or Kubernetes ConfigMaps without rebuilding the image (`VERIFIER_BACKEND_LOCALFILES_CLIENTSPATH`, `VERIFIER_BACKEND_LOCALFILES_TRUSTEDISSUERSPATH`, `VERIFIER_BACKEND_LOCALFILES_SCHEMASDIR`).
- **ArchUnit enforcement**: 17 architecture rules validating hexagonal layers, bounded context isolation, naming conventions, and dependency constraints.
- **Deployment guide**: Comprehensive deployment documentation at `.claude/docs/deployment.md`.

### Changed
- **Java 17 -> 25**: Updated to Java 25 with Eclipse Temurin runtime.
- **Gradle 8.8 -> 9.1.0**: Updated build tool and wrapper.
- **Spring Boot 3.3.2 -> 3.5.11**: Major framework upgrade.
- **Dockerfile**: `gradle:9.1.0-jdk25` build stage + `eclipse-temurin:25-jre-alpine` runtime.
- **OAuth2 filters slimmed down**: CustomAuthorizationRequestConverter (524->250 lines), CustomAuthenticationProvider (392->200 lines), CustomTokenRequestConverter (229->150 lines) — all delegate to application workflows.
- **ArchUnit 1.3.0 -> 1.4.1**: Java 25 bytecode support.
- **OWASP dependency-check 9.1.0 -> 12.2.0**, SonarQube plugin 5.1.0 -> 6.0.1, Swagger 2.2.22 -> 2.2.28.

## [v2.0.12](https://github.com/in2workspace/in2-verifier-api/releases/tag/v2.0.12)

### Changed

- Read bitstring-encoded lists using MSB-first ordering.

## [v2.0.11](https://github.com/in2workspace/in2-verifier-api/releases/tag/v2.0.11)

### Added

- Add support for BitstringStatusListEntry credential status type.

## [v2.0.10](https://github.com/in2workspace/in2-verifier-api/releases/tag/v2.0.10)
### Added
- Added support for cryptographic binding

## [v2.0.9](https://github.com/in2workspace/in2-verifier-api/releases/tag/v2.0.9)
### Changed
- In login template, enhance logo responsiveness.

## [v2.0.8](https://github.com/in2workspace/in2-verifier-api/releases/tag/v2.0.8)
### Changed
- In login template, change 'dark-primary' variable name to 'secondary', and remove QR padding.

## [v2.0.7](https://github.com/in2workspace/in2-verifier-api/releases/tag/v2.0.7)
### Changed
- - Resolve logo and favicon URLs dynamically using a configurable images base URL and paths.

## [v2.0.6](https://github.com/in2workspace/in2-verifier-api/releases/tag/v2.0.6)
### Added
- Altia and ISBE favicons.

### Changed
- Rename DOME favicon.

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
