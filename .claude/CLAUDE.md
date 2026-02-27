# CLAUDE.md - Verifier Core API

## Project Overview

Spring Boot 3.3.2 (Authorization Server) implementation of an OpenID4VP Verifier.
Package: `es.in2.vcverifier`, version 2.1.0. Java 17, Gradle 8.8.

Acts as OAuth 2.0 Authorization Server: receives Verifiable Presentations from EUDI wallets, validates credentials, emits OIDC access_tokens/id_tokens to Relying Parties.

## Architecture

Flat package structure with SPI patterns. Key areas:

- **component/** - CryptoComponent (EC P-256 key management, auto-generation)
- **config/** - BackendConfig, ClientLoaderConfig, HttpClientConfig, SPI configs (TrustedIssuersConfig, ClientRegistryConfig, CredentialValidationConfig)
- **controller/** - LoginQR, OID4VP, DID resolver
- **security/** - SecurityConfig, AuthorizationServerConfig, custom OAuth2 filters
- **service/** - Interfaces: TrustFrameworkService, VpService, JWTService, DIDService, SdJwtVerificationService, TrustedIssuersProvider, ClientRegistryProvider, CredentialSchemaResolver, CredentialValidator, ClaimsExtractor
- **service/impl/** - Implementations: EbsiV4/Local TrustedIssuersProvider, Remote/Local ClientRegistryProvider, JsonSchemaCredentialValidator, LearCredentialClaimsExtractor, LocalSchemaResolver, SdJwtVerificationServiceImpl
- **model/** - Credential POJOs (LEARCredential Employee/Machine V1-V3, to be deprecated), ValidationResult, ExtractedClaims, issuer models, SD-JWT (SdJwt, Disclosure, SdJwtVerificationResult), DCQL (DcqlQuery, CredentialQuery, ClaimQuery)

## Documentation

All design & implementation documents are in `.claude/docs/`:

- [srs.md](docs/srs.md) - Complete SRS (source of truth). Read before any change, update after each step.

## Key Technical Decisions

- **Blocking stack**: Spring MVC + java.net.HttpClient (singleton with timeouts)
- **Credential format**: `jwt_vc_json` (W3C VCDM) + `dc+sd-jwt` (SD-JWT VC). Format detection via `~` separator.
- **Credential validation**: JSON Schema 2020-12 via `networknt:json-schema-validator:1.5.6`. Schemas in `resources/schemas/`.
- **Claims extraction**: `ClaimsExtractor` SPI with JSON path + coalesce (replaces instanceof chains)
- **Identity**: ES256 (P-256) via nimbus-jose-jwt + BouncyCastle. Auto-generates ephemeral key if not configured.
- **Trust framework**: SPI with `EbsiV4TrustedIssuersProvider` (remote) and `LocalTrustedIssuersProvider` (YAML, wildcard). Selected via `@ConditionalOnProperty`.
- **Client registry**: SPI with `RemoteClientRegistryProvider` (YAML + refresh 30min) and `LocalClientRegistryProvider` (YAML local). Selected via `@ConditionalOnProperty`.
- **Revocation**: BitstringStatusList only (legacy YAML removed). Credentials without `credentialStatus` skip revocation check.

## Build & Test

```bash
./gradlew build          # Build + tests + checkstyle + jacoco
./gradlew test           # 351 tests, 0 failures
./gradlew bootRun        # Run (auto-configures with dev defaults, no env vars needed)
make help                # Show Makefile targets
make up                  # Docker Compose up
```

## Local Development

No external services required for development. The application auto-configures:
- **Identity**: Generates ephemeral P-256 key + did:key if `privateKey` is empty
- **Trust framework**: Uses `local/trusted-issuers.yaml` (wildcard: trust all) if `trustedIssuersListUrl` is empty
- **Client registry**: Uses `local/clients.yaml` if `trustedServicesListUrl` is empty

```bash
# Option 1: Run from IDE (zero config)
./gradlew bootRun

# Option 2: Docker Compose
cd docker && cp .env.example .env
make up
```

## Test Stack

| Category | Tests | Files |
|----------|-------|-------|
| Unit tests | ~290 | 41 |
| Security tests | 22 | 1 (VpSecurityTest) |
| Architecture (ArchUnit) | 13 | 1 (ArchitectureRulesTest) |
| SD-JWT + DCQL tests | ~26 | 4 |
| **Total** | **351** | **47** |

JaCoCo exclusions: 1 class (AuthorizationServerConfig). Sonar exclusions: 2 classes.

## Critical Paths (do not break)

1. Authorization Code flow: /authorize -> QR -> wallet VP -> /oid4vp/direct_post -> token
2. VP/VC validation pipeline (signature, trust, revocation, holder binding) — both JWT VP and SD-JWT VC
3. Token generation with VC claims (access_token + id_token) — format-agnostic via ExtractedClaims SPI
4. SPI provider selection (TrustedIssuers, ClientRegistry, CredentialValidator)
5. JSON Schema validation of credentials
6. did:key resolution for DID verification
7. SD-JWT VC verification (signature, disclosure digests, KB-JWT, claim resolution)
8. DCQL query in authorization request (dual format: dc+sd-jwt + jwt_vc_json)

## SD-JWT VC Support

- **Format detection**: `token.contains("~")` in `AuthorizationResponseProcessorServiceImpl`
- **Verification service**: `SdJwtVerificationServiceImpl` — full pipeline (signature, disclosures, KB-JWT, trust)
- **Model**: `SdJwt`, `Disclosure`, `SdJwtVerificationResult` in `model.sdjwt`
- **Claims extraction**: `LearCredentialClaimsExtractor` + `CustomAuthenticationProvider` support both `type` (W3C VCDM) and `vct` (SD-JWT)
- **Issuer resolution**: Supports `issuer` (W3C), `issuer.id`, and `iss` (SD-JWT) fields

## DCQL Support

- **Model**: `DcqlQuery`, `CredentialQuery`, `ClaimQuery` in `model.dcql`
- **Authorization request**: `buildDcqlQuery()` in `CustomAuthorizationRequestConverter` — dual format query
- **Backward compat**: `scope` claim kept alongside `dcql_query` for wallets without DCQL support

## Refactoring Completed (v2.1.0)

All 10 steps from SRS Section 7 are complete:

- P0 security fixes (HttpClient singleton, aud validation, nonce, assert removal)
- Legacy revocation removal (RevokedCredentialIds, CredentialStatusResponse deleted)
- Auto-generation of P-256 identity keys (CryptoComponent)
- SPI for Trusted Issuers (EbsiV4 + Local with wildcard)
- SPI for Client Registry (Remote + Local)
- JSON Schema-driven credential validation (5 schemas, 3-layer resolver)
- Claims extraction via JSON path + coalesce (replaces instanceof chains)
- Single application.yaml with dev defaults (no profiles needed)
- Docker Compose + Makefile
- Full test stack (351 tests, ArchUnit, security tests)
- SD-JWT VC (`dc+sd-jwt`) format support with full verification pipeline
- DCQL query support in authorization requests (dual format)
