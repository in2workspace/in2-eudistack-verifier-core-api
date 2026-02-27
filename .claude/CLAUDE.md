# CLAUDE.md - Verifier Core API

## Project Overview

Spring Boot 3.5.11 (Authorization Server) implementation of an OpenID4VP Verifier.
Package: `es.in2.vcverifier`, version 2.1.0. Java 25, Gradle 9.1.0.

Acts as OAuth 2.0 Authorization Server: receives Verifiable Presentations from EUDI wallets, validates credentials, emits OIDC access_tokens/id_tokens to Relying Parties.

## Architecture

Hexagonal (Ports & Adapters) + 2 Bounded Contexts (`verifier/`, `oauth2/`) + `shared/` module.

Each context follows: `domain/` (model, service, exception) -> `application/` (workflow) -> `infrastructure/` (controller, config, adapter).

- **verifier/** - OID4VP verification, credential validation, trust framework, claims extraction
- **oauth2/** - OAuth2 Authorization Server filters, token generation, SSE login, client registry
- **shared/** - Crypto (JWT, DID, SD-JWT, x5c), config, properties, exceptions, constants

## Frontend Architecture

The frontend is a **separate Angular SPA** (`eudistack-portal-acceso-ui`), not embedded in the backend.

- **Login flow**: Backend redirects to `{portalUrl}/login?authRequest=...&state=...&homeUri=...`
- **QR code**: Generated client-side by Angular (`angularx-qrcode`)
- **Login notification**: SSE via `GET /api/login/events?state=...` (Spring MVC `SseEmitter`)
- **White-label**: `theme.json` mounted as Docker volume (branding, links, i18n)
- **Error page**: Backend redirects to `{portalUrl}/error?errorCode=...&errorMessage=...`

Key backend config: `VERIFIER_FRONTEND_PORTALURL` (default: `http://localhost:4200`)

## Documentation

All design & implementation documents are in `.claude/docs/`:

- [srs.md](docs/srs.md) - Complete SRS (source of truth). Read before any change, update after each step.
- [deployment.md](docs/deployment.md) - Deployment guide for implementers.

## Key Technical Decisions

- **Blocking stack**: Spring MVC + java.net.HttpClient (singleton with timeouts)
- **SSE for login**: `SseEmitterStore` (ConcurrentHashMap<String, SseEmitter>) replaces WebSocket/SockJS/STOMP
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
./gradlew test           # Tests
./gradlew bootRun        # Run (auto-configures with dev defaults, no env vars needed)
```

## Local Development

No external services required for development. The application auto-configures:
- **Identity**: Generates ephemeral P-256 key + did:key if `privateKey` is empty
- **Trust framework**: Uses `local/trusted-issuers.yaml` (wildcard: trust all) if `trustedIssuersListUrl` is empty
- **Client registry**: Uses `local/clients.yaml` if `trustedServicesListUrl` is empty

```bash
# Option 1: Run from IDE (zero config)
./gradlew bootRun

# Option 2: Docker Compose (backend + Angular portal)
cd docker && cp .env.example .env
docker compose up -d
```

## Critical Paths (do not break)

1. Authorization Code flow: /authorize -> redirect to Angular SPA -> QR -> wallet VP -> /oid4vp/auth-response -> SSE redirect -> token
2. VP/VC validation pipeline (signature, trust, revocation, holder binding) — both JWT VP and SD-JWT VC
3. Token generation with VC claims (access_token + id_token) — format-agnostic via ExtractedClaims SPI
4. SSE login notification: `SseEmitterStore.send(state, redirectUrl)` triggered by `AuthorizationResponseProcessorServiceImpl`
5. SPI provider selection (TrustedIssuers, ClientRegistry, CredentialValidator)
6. JSON Schema validation of credentials
7. SD-JWT VC verification (signature, disclosure digests, KB-JWT, claim resolution)
8. DCQL query in authorization request (dual format: dc+sd-jwt + jwt_vc_json)
