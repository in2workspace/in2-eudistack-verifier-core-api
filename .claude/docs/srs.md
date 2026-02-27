# SRS: Verifier Core API

> **Este documento es la fuente de verdad del componente.** Debe mantenerse actualizado con cada desarrollo. La IA lo lee antes de cada cambio y lo actualiza al completar cada paso.

**Proyecto**: `in2-eudistack-verifier-core-api`
**Rama de trabajo**: `feature/refactor-ai`
**Version actual**: 2.1.0
**Stack**: Spring Boot 3.3.2 (Authorization Server) | Java 17 | Gradle 8.8
**Ultima actualizacion**: 2026-02-27

---

## 1. Descripcion del sistema

### 1.1 Proposito

El Verifier Core API es un **OpenID4VP Verifier** construido sobre Spring Authorization Server. Actua como OAuth 2.0 Authorization Server que:

1. Recibe Verifiable Presentations (VP) de wallets EUDI
2. Valida las Verifiable Credentials (VC) contenidas
3. Emite access_tokens e id_tokens estandar OIDC para Relying Parties

### 1.2 Flujo principal

```
Wallet                    Verifier                    Relying Party (RP)
  |                          |                              |
  |    <-- Auth Request -----|<---- /authorize -------------|
  |         (QR code)        |                              |
  |                          |                              |
  |-- VP Token (direct_post)->|                              |
  |                          |-- Validate VP --|            |
  |                          |   Validate VC   |            |
  |                          |   Check trust   |            |
  |                          |   Check revoc.  |            |
  |                          |<----------------|            |
  |                          |                              |
  |                          |-- access_token + id_token -->|
  |                          |   (with VC claims)           |
```

### 1.3 Componentes funcionales

| Componente | Descripcion | Estado |
| --- | --- | --- |
| OAuth2/OIDC Authorization Server | Authorization Code flow con Spring Auth Server | Implementado |
| OpenID4VP | Recepcion de VP Token via `direct_post` | Implementado |
| QR Login | WebSocket para login via QR con wallet | Implementado |
| Credential Validation | Validacion estructura + firma + trust + revocacion | Implementado (hardcoded) |
| Token Generation | Emision access_token/id_token con claims del VC | Implementado |
| Client Registry | Registro de Relying Parties (OIDC clients) | Implementado (remoto) |
| Trust Framework | Validacion de issuers contra Trusted Issuers List | Implementado (DOME only) |
| Revocation | BitstringStatusList + legacy YAML | Implementado (parcial) |
| did:key Resolver | Resolucion de DID keys para verificacion | Implementado |

---

## 2. Arquitectura actual

### 2.1 Estructura de paquetes

```
es.in2.vcverifier/
├── VCVerifierApplication.java
├── component/
│   └── CryptoComponent.java              # EC key management (P-256)
├── config/
│   ├── BackendConfig.java                 # Backend properties accessor
│   ├── CacheStoreConfig.java              # Guava cache beans
│   ├── ClientLoaderConfig.java            # OIDC client loading + refresh
│   ├── I18nConfig.java                    # i18n (en, es, ca)
│   ├── WebSocketConfig.java               # WS for QR login
│   └── properties/
│       ├── BackendProperties.java         # @ConfigurationProperties
│       └── FrontendProperties.java
├── controller/
│   ├── LoginQrController.java             # QR generation endpoints
│   ├── Oid4vpController.java              # /oid4vp/* endpoints
│   ├── ResolverController.java            # did:key resolver
│   └── ClientErrorController.java
├── security/
│   ├── SecurityConfig.java                # Spring Security filter chain
│   ├── AuthorizationServerConfig.java     # OAuth2 server config
│   └── filters/
│       ├── CustomAuthorizationRequestConverter.java  # Auth request handling
│       ├── CustomAuthenticationProvider.java          # Token generation
│       └── CustomTokenRequestConverter.java           # Token request handling
├── service/
│   ├── TrustFrameworkService.java         # Trust framework interface
│   ├── VpService.java                     # VP validation interface
│   ├── JWTService.java                    # JWT operations interface
│   ├── DIDService.java                    # DID resolution interface
│   └── impl/
│       ├── TrustFrameworkServiceImpl.java # All external HTTP calls
│       ├── VpServiceImpl.java             # VP/VC validation logic
│       ├── JWTServiceImpl.java            # JWT sign/verify
│       └── DIDServiceImpl.java            # did:key resolution
├── model/
│   ├── credentials/lear/
│   │   ├── LEARCredential.java            # Base interface
│   │   ├── employee/
│   │   │   ├── LEARCredentialEmployee.java
│   │   │   ├── LEARCredentialEmployeeV1.java
│   │   │   ├── LEARCredentialEmployeeV2.java
│   │   │   └── LEARCredentialEmployeeV3.java
│   │   └── machine/
│   │       ├── LEARCredentialMachine.java
│   │       ├── LEARCredentialMachineV1.java
│   │       └── LEARCredentialMachineV2.java
│   ├── issuer/                            # EBSI issuer response models
│   ├── ExternalTrustedListYamlData.java   # Client registry YAML model
│   ├── RevokedCredentialIds.java          # Legacy revocation model
│   └── ...
├── exception/                             # Custom exceptions
└── util/
    └── Constants.java                     # Hardcoded contexts, timeouts
```

### 2.2 Dependencias externas

| Servicio | URL config property | Protocolo | Obligatorio |
| --- | --- | --- | --- |
| Trusted Issuers List | `trustedIssuersListUrl` | EBSI v4 REST API | No (usa LocalTrustedIssuersProvider si vacio) |
| Client Registry | `trustedServicesListUrl` | YAML via HTTP | No (usa LocalClientRegistryProvider si vacio) |
| Issuer Status Lists | URL en el propio VC | HTTP + JWT | No (self-contained) |

### 2.3 Identidad criptografica

- **Algoritmo**: ES256 (ECDSA P-256)
- **Key ID**: `verifier.backend.identity.didKey` (did:key format)
- **Private key**: `verifier.backend.identity.privateKey` (hex, optional 0x prefix)
- **Uso**: Firma access_tokens, id_tokens, authorization request JWTs
- **Auto-generacion**: Si `privateKey` vacio, CryptoComponent genera par P-256 efimero + deriva did:key

---

## 3. Auditoria de problemas

### 3.1 Seguridad (P0 - Criticos)

| ID | Problema | Fichero | Linea | Estado |
| --- | --- | --- | --- | --- |
| P0-1 | HttpClient instanciado por request (leak de recursos) | TrustFrameworkServiceImpl, CustomAuthorizationRequestConverter | Multiples | **HECHO** (HttpClientConfig singleton) |
| P0-2 | `assert` en validacion de grantType (deshabilitado en prod) | CustomTokenRequestConverter | 61 | **HECHO** (validacion explicita) |
| P0-3 | Sin timeout en HTTP (resource exhaustion) | Todos los HttpClient | Multiples | **HECHO** (connect 10s, read 30s) |
| P0-4 | Validacion `aud` del VP comentada (replay attack) | AuthorizationResponseProcessorServiceImpl | 184-189 | **HECHO** (descomentado + tests) |
| P0-5 | Nonce FAPI deshabilitado | Constants.java | 33 | **HECHO** (`IS_NONCE_REQUIRED = true`) |
| P0-6 | `@Scheduled` + `@Bean` en ClientLoaderConfig (refresh no funciona) | ClientLoaderConfig | 36-40 | **HECHO** (separado @Bean de @Scheduled) |

### 3.2 Arquitectura (P1 - Altos)

| ID | Problema | Estado |
| --- | --- | --- |
| P1-1 | Sin rate limiting en token endpoint | PENDIENTE |
| P1-2 | Token storage in-memory (no distribuido) | PENDIENTE |
| P1-3 | Error handler devuelve campos vacios | PENDIENTE |
| P1-4 | Propiedad muerta `verifiableCredential` | **HECHO** (eliminada de BackendProperties) |

### 3.3 Mantenibilidad (P2 - Medios)

| ID | Problema | Estado |
| --- | --- | --- |
| P2-1 | Normalizacion credenciales con FIXME | **HECHO** (LearCredentialClaimsExtractor con JSON path + coalesce) |
| P2-2 | Sin HealthIndicators para dependencias | PENDIENTE |
| P2-3 | Exclusiones de cobertura de tests para clases criticas | **HECHO** (reducidas de 5 a 1, 318 tests, ratio 1.19:1) |
| P2-4 | 5 POJOs hardcodeados para credenciales (~10 ficheros por nueva credencial) | **HECHO** (JSON Schema + CredentialValidator SPI) |
| P2-5 | instanceof chain en 5 sitios para tipo de credencial | **HECHO** (ClaimsExtractor.supports()) |
| P2-6 | @context URLs hardcodeadas en Constants.java | **HECHO** (schemas JSON + LocalSchemaResolver) |

---

## 4. Compliance con especificaciones

### 4.1 Separacion de roles en HAIP (critico)

HAIP 1.0 Final (aprobado 24/12/2025) separa requisitos por rol:

- **Section 4** = OID4VCI -> aplica a **Issuer + Wallet** (DPoP, PAR, PKCE, WIA, FAPI2)
- **Section 5** = OID4VP -> aplica a **Verifier + Wallet** (DCQL, encryption, x509_hash, JAR)
- **Sections 6-8** = Cross-cutting (todos los roles)

**DPoP, PAR, PKCE y WIA NO son requisitos del Verifier.** Son requisitos del Issuer (Section 4).

### 4.2 OID4VP 1.0 Final -- Estado

| Req | Descripcion | Estado | Prioridad |
| --- | --- | --- | --- |
| VP-1 | VP Token format: JWT_VP | OK | - |
| VP-2 | Response mode: `direct_post` | OK (falta `.jwt` para HAIP) | - |
| VP-3 | Nonce validation | COMENTADO (P0-5) | Critica |
| VP-4 | Audience (`aud`) validation | COMENTADO (P0-4) | Critica |
| VP-5 | Holder binding (PoP) verification | OK | - |
| VP-6 | DCQL query support | OK (dual format: dc+sd-jwt + jwt_vc_json) | Critica |
| VP-7 | Replay prevention (state + nonce) | Parcial | Alta |
| VP-8 | Error responses format | Parcial | Media |

### 4.3 HAIP 1.0 Final -- Requisitos del Verifier (Section 5)

#### Formatos de credencial (S5)

> "The Wallet and Verifier MUST support at least one of: IETF SD-JWT VC or ISO mdoc. Ecosystems SHOULD clearly indicate which are required."

| Req | Descripcion | Nivel | Estado |
| --- | --- | --- | --- |
| HAIP-V1 | Soportar al menos `dc+sd-jwt` o `mso_mdoc` | MUST | OK (`dc+sd-jwt` + `jwt_vc_json`) |

No es obligatorio soportar ambos. El ecosistema define cual(es).

#### Modos de invocacion

**Redirect-based (S5.1):**

| Req | Descripcion | Nivel | Estado |
| --- | --- | --- | --- |
| HAIP-V2 | JAR con `request_uri` (Auth Request firmada) | MUST | PARCIAL |
| HAIP-V3 | Response mode `direct_post.jwt` (con cifrado) | MUST | FALTA |
| HAIP-V4 | Same-device: `redirect_uri` en respuesta HTTP | MUST | Por verificar |

**W3C Digital Credentials API (S5.2):**

| Req | Descripcion | Nivel | Estado |
| --- | --- | --- | --- |
| HAIP-V5 | Response mode `dc_api.jwt` | MUST | FALTA |
| HAIP-V6 | Al menos uno de: unsigned/signed/multi-signed | MUST | FALTA |

> El Verifier no esta obligado a soportar ambos flujos. Depende del ecosistema.

#### Client Identifier (S5)

| Req | Descripcion | Nivel | Estado |
| --- | --- | --- | --- |
| HAIP-V7 | Client ID Prefix `x509_hash` (requests firmadas) | MUST | FALTA (usa `did:key`) |
| HAIP-V8 | Certificado NO auto-firmado | MUST | FALTA |
| HAIP-V9 | Trust anchor NO en header `x5c` | MUST | FALTA |

> `x509_hash` es el unico scheme especificado para requests firmadas. `did` no se menciona.

#### Cifrado de respuesta (S5 -- obligatorio para TODOS los flujos)

| Req | Descripcion | Nivel | Estado |
| --- | --- | --- | --- |
| HAIP-V10 | JWE `alg`: `ECDH-ES` con P-256 | MUST | FALTA |
| HAIP-V11 | JWE `enc`: soportar `A128GCM` Y `A256GCM` | MUST | FALTA |
| HAIP-V12 | Listar ambos en metadata `encrypted_response_enc_values_supported` | MUST | FALTA |
| HAIP-V13 | Claves de cifrado efimeras por cada request | MUST | FALTA |

#### Queries (S5)

| Req | Descripcion | Nivel | Estado |
| --- | --- | --- | --- |
| HAIP-V14 | DCQL query y response | MUST | OK (query dual format dc+sd-jwt + jwt_vc_json) |
| HAIP-V15 | `trusted_authorities` con AKI en DCQL | MUST | FALTA |

#### Criptografia y validacion (S6, S7, S8)

| Req | Descripcion | Nivel | Estado |
| --- | --- | --- | --- |
| HAIP-V16 | ES256 como minimo para validar firmas | MUST | OK |
| HAIP-V17 | Validar KB-JWT para SD-JWT VC | MUST | OK (aud, nonce, sd_hash, iat, cnf.jwk) |
| HAIP-V18 | Validar `deviceSignature` para mdoc | MUST | FALTA |
| HAIP-V19 | Status via IETF Token Status List (`status_list`) | MUST | FALTA (usa W3C Bitstring) |
| HAIP-V20 | Issuer key via `x5c` JOSE header (SD-JWT VC) | MUST | PARCIAL (soportado en SdJwtVerificationServiceImpl, falta test e2e con cert real) |
| HAIP-V21 | SHA-256 para digests | MUST | OK |

### 4.4 Lo que NO aplica al Verifier

| Requisito | Aplica? | Donde aplica realmente |
| --- | --- | --- |
| DPoP (RFC 9449) | **NO** | S4 -- Issuer + Wallet |
| PAR (RFC 9126) | **NO** | S4 -- Issuer + Wallet |
| PKCE S256 | **NO** | S4 -- Issuer + Wallet |
| Wallet Instance Attestation | **NO** | S4.4.1 -- Issuer + Wallet |
| Key Attestation validation | **NO** | S4.5.1 -- Issuer + Wallet |
| FAPI2 Security Profile | **NO** | S4 -- Issuer + Wallet |

### 4.5 Quick wins

1. Descomentar validacion `aud` en `AuthorizationResponseProcessorServiceImpl:184-189`
2. `IS_NONCE_REQUIRED_ON_FAPI_PROFILE = true` en `Constants.java:33`

### 4.6 Nota: policy vs protocol

Segun OID4VP 1.0 Final, la validacion de **issuer trust** y **revocacion** son **policy-level** (paso 5 VP Token Validation), no protocol-mandated. El protocolo exige: formato VP, firma VC, holder binding, replay prevention. Los SPIs de trust framework son opcionales/configurables.

---

## 5. Diseno de refactorizacion

### 5.1 Configuracion: un solo YAML con env vars

**Principio**: 12-Factor App. Un solo `application.yaml` con defaults de desarrollo. Override via environment variables en Docker. No multiples `application-{profile}.yaml`.

Spring Boot relaxed binding: `verifier.backend.identity.privateKey` <-> `VERIFIER_BACKEND_IDENTITY_PRIVATEKEY`

**Patron Docker:**

```yaml
# docker-compose.yml -- solo overrides
services:
  verifier:
    env_file: .env
    environment:
      SERVER_PORT: 8082
```

```env
# .env (nunca se commitea)
VERIFIER_BACKEND_IDENTITY_PRIVATEKEY=0x73e509...
```

### 5.2 Auto-generacion de identidad criptografica

**Patron**: `@ConditionalOnMissingBean` style.

- Si `privateKey` tiene valor: comportamiento actual (retrocompatible)
- Si `privateKey` vacio: generar par P-256 efimero + derivar `did:key` + log WARNING

**Derivacion did:key P-256:** KeyPair EC P-256 -> compressed pubkey (33 bytes) -> multicodec `0x1200` (varint `[0x80, 0x24]`) -> base58btc con prefijo `z` -> `did:key:z{encoded}`

### 5.3 SPI: Trusted Issuers

```java
public interface TrustedIssuersProvider {
    List<IssuerCredentialsCapabilities> getIssuerCapabilities(String issuerId);
}
```

| Implementacion | Activacion | Comportamiento |
| --- | --- | --- |
| `EbsiV4TrustedIssuersProvider` | `trustedIssuersListUrl` con valor | HTTP GET EBSI v4 (actual) |
| `LocalTrustedIssuersProvider` | `trustedIssuersListUrl` vacio | YAML local. Wildcard `*` = confiar en todos |

Nombrado `EbsiV4` para dejar espacio a `EbsiV5`, `LOTL`.

### 5.4 SPI: Client Registry

```java
public interface ClientRegistryProvider {
    ExternalTrustedListYamlData loadClients();
}
```

| Implementacion | Activacion | Comportamiento |
| --- | --- | --- |
| `RemoteClientRegistryProvider` | `trustedServicesListUrl` con valor | YAML remoto + refresh 30min (actual) |
| `LocalClientRegistryProvider` | `trustedServicesListUrl` vacio | YAML local, carga una vez al startup |

### 5.5 Eliminacion de revocacion legacy

**Decision**: Credenciales sin `credentialStatus` = skip revocation. Solo `BitstringStatusListEntry` se valida (URL en la propia credencial). Se elimina:

- `getRevokedCredentialIds()` / `getCredentialStatusListData()` de `TrustFrameworkService`
- Branch `PlainListEntity` de `VpServiceImpl`
- Modelos `RevokedCredentialIds`, `CredentialStatusResponse`
- Property `revokedCredentialListUrl` pasa a opcional

### 5.6 Validacion dinamica de credenciales (JSON Schema)

#### 5.6.1 Problema actual

5 POJOs hardcodeados (3 Employee + 2 Machine). Deteccion por `@context` URL exacta. Normalizacion con FIXMEs. `instanceof` chain en 5 sitios. **~10 ficheros por cada nueva credencial/version.**

#### 5.6.2 Specs relevantes

| Spec | Mecanismo |
| --- | --- |
| W3C VCDM 2.0 | `credentialSchema: { type: "JsonSchema", id: "https://..." }` en el VC |
| SD-JWT VC (draft-15) | `vct` claim -> Type Metadata -> `schema`/`schema_uri` (JSON Schema 2020-12) |
| OID4VCI | `.well-known` metadata: `credential_configurations_supported` (NO incluye schema) |

Si schema presente en VC o Type Metadata, el Verifier **MUST** validar contra el.

#### 5.6.3 Arquitectura en 3 capas SPI

```
Capa 1: CredentialSchemaResolver (de donde obtengo el schema?)
  |-- EmbeddedSchemaResolver (order=10)    -> credentialSchema.id del propio VC
  |-- LocalSchemaResolver (order=20)       -> classpath:schemas/{type}.json
  |-- IssuerMetadataSchemaResolver (order=30) -> .well-known del issuer
  +-- (futuro) RegistrySchemaResolver      -> registro externo

Capa 2: CredentialValidator (es estructuralmente valido?)
  -> JSON Schema 2020-12 via networknt/json-schema-validator
  -> Retorna ValidationResult { valid, credentialType, version, errors }

Capa 3: ClaimsExtractor (que datos extraigo para el token?)
  |-- LearCredentialClaimsExtractor -> JSON path navigation, coalesce v1/v2/v3
  +-- (futuro) PidClaimsExtractor, GenericClaimsExtractor
```

#### 5.6.4 Interfaces

```java
public interface CredentialSchemaResolver {
    int order();
    Optional<JsonSchema> resolve(String credentialType, List<String> context, JsonNode credential);
}

public interface CredentialValidator {
    ValidationResult validate(JsonNode credential);
}

public record ValidationResult(
    boolean valid, String credentialType, String version,
    JsonNode credential, List<String> errors
) {}

public interface ClaimsExtractor {
    boolean supports(String credentialType, String version);
    ExtractedClaims extract(JsonNode credential);
}

public record ExtractedClaims(
    String subjectDid, String mandatorOrgId, String issuerDid,
    Map<String, Object> idTokenClaims, Map<String, Object> accessTokenClaims,
    String scope
) {}
```

#### 5.6.5 LearCredentialClaimsExtractor (reemplaza toda la logica actual)

En lugar de `instanceof`, usa JSON path con coalesce:

```java
// Antes (5 instanceof checks):
if (credential instanceof LEARCredentialEmployeeV3 emp) {
    return emp.credentialSubjectV3().mandate().mandatee().firstName();
}
// Despues (1 JSON path):
JsonNode mandatee = credential.at("/credentialSubject/mandate/mandatee");
String firstName = coalesce(
    mandatee.path("firstName").asText(null),
    mandatee.path("first_name").asText(null)
);
```

**Reemplaza:**

- `VpServiceImpl.mapToSpecificCredential()` (if/else de @context)
- `CustomAuthenticationProvider.normalizeLearCredentialEmployeeV2()` (FIXME)
- `CustomAuthenticationProvider.resolveCredentialSubjectDid()` (3-layer fallback)
- `CustomAuthenticationProvider.getAudience()` (instanceof chain)
- `CustomAuthenticationProvider.getScope()` (instanceof chain)
- `CustomAuthenticationProvider.generateAccessTokenWithVc/IdToken()` (credential -> claims)

#### 5.6.6 Schemas locales

```
resources/schemas/
  LEARCredentialEmployee.v1.json
  LEARCredentialEmployee.v2.json
  LEARCredentialEmployee.v3.json
  LEARCredentialMachine.v1.json
  LEARCredentialMachine.v2.json
```

Generados desde los POJOs actuales. La fuente de verdad migra de POJOs a schemas.

#### 5.6.7 Flujo refactorizado

```
VP Token JWT
  |-- 1. Parse VP, extract VC JWT(s)
  |-- 2. Verify VC signature (x5c / did:key)
  |-- 3. credentialValidator.validate(vcJson)         <- JSON Schema
  |-- 4. Validate time window (validFrom/validUntil)
  |-- 5. Validate revocation (BitstringStatusList si presente)
  |-- 6. claimsExtractor.extract(vcJson)              <- JSON path
  |-- 7. trustedIssuersProvider.validate(issuerDid)   <- SPI
  |-- 8. trustedIssuersProvider.validate(mandatorOrgId)
  |-- 9. Verify VP holder binding (PoP)
  +-- 10. Verify cryptographic binding (VP holder == VC subject)
```

#### 5.6.8 Retrocompatibilidad

- **Fase 1 (esta iteracion)**: POJOs legacy se mantienen para tests. Nueva pipeline en paralelo.
- **Fase 2 (siguiente)**: Eliminar POJOs, interfaces LEARCredential*, records versionados. Fuente de verdad = JSON + schema.

#### 5.6.9 Impacto

| Antes | Despues |
| --- | --- |
| ~10 ficheros por nueva credencial | 1 JSON Schema + (opcionalmente) 1 ClaimsExtractor |
| instanceof chain en 5 sitios | ClaimsExtractor.supports() |
| Normalizacion FIXME | JSON path con coalesce |
| Solo jwt_vc_json | Preparado para dc+sd-jwt (anadir VctSchemaResolver) |
| @context hardcodeado | Schema-driven |

---

## 6. Dependencia nueva

```gradle
implementation 'com.networknt:json-schema-validator:1.5.6'
```

JSON Schema 2020-12, Jackson-nativo, custom schema loading via ResourceLoader.

---

## 7. Plan de ejecucion

### Paso 0: Setup ✅

- [x] Crear rama `feature/refactor-ai` desde `main`
- [x] Crear `.claude/docs/srs.md` (este documento)
- [x] Crear `.claude/CLAUDE.md`

### Paso 1: Fixes P0 ✅

- [x] `HttpClient` como `@Bean` singleton con timeouts (connect: 10s, read: 30s)
- [x] `assert` -> validacion explicita en `CustomTokenRequestConverter:61`
- [x] Descomentar validacion `aud` en `AuthorizationResponseProcessorServiceImpl:184-189`
- [x] `IS_NONCE_REQUIRED_ON_FAPI_PROFILE = true`
- [x] Separar `@Bean` de `@Scheduled` en `ClientLoaderConfig`

**Ficheros**: `TrustFrameworkServiceImpl`, `CustomAuthorizationRequestConverter`, `CustomTokenRequestConverter`, `AuthorizationResponseProcessorServiceImpl`, `Constants`, `ClientLoaderConfig`, nuevo `HttpClientConfig`

### Paso 2: Eliminar revocacion legacy ✅

- [x] Eliminar `validateOldCredentialNotRevoked()` y branch `PlainListEntity` de `VpServiceImpl`
- [x] Eliminar `getRevokedCredentialIds()`, `getCredentialStatusListData()` de interfaces e impl
- [x] Eliminar `RevokedCredentialIds`, `CredentialStatusResponse`
- [x] `revokedCredentialListUrl` opcional, eliminar `getRevocationListUri()`

### Paso 3: Auto-generacion de identidad ✅

- [x] `didKey`/`privateKey` opcionales en `BackendProperties`. Eliminar `verifiableCredential`
- [x] `CryptoComponent`: generar P-256 efimero + derivar did:key si privateKey vacio

### Paso 4: SPI Trusted Issuers ✅

- [x] Crear `TrustedIssuersProvider` interfaz
- [x] Crear `EbsiV4TrustedIssuersProvider` (extraer de TrustFrameworkServiceImpl)
- [x] Crear `LocalTrustedIssuersProvider` (YAML con wildcard)
- [x] Crear `TrustedIssuersConfig` (bean selection via @ConditionalOnProperty)
- [x] Crear `local/trusted-issuers.yaml`
- [x] Delegar en TrustFrameworkServiceImpl

### Paso 5: SPI Client Registry ✅

- [x] Crear `ClientRegistryProvider` interfaz
- [x] Crear `RemoteClientRegistryProvider` (extraer logica)
- [x] Crear `LocalClientRegistryProvider` (YAML local)
- [x] Crear `ClientRegistryConfig` (bean selection)
- [x] Crear `local/clients.yaml`
- [x] Condicionar `@Scheduled` en ClientLoaderConfig

### Paso 6: Validacion dinamica (JSON Schema) ✅

- [x] Anadir `networknt:json-schema-validator:1.5.6` a build.gradle
- [x] Crear `CredentialSchemaResolver` interfaz SPI
- [x] Crear `LocalSchemaResolver`
- [x] Crear `CredentialValidator` interfaz + `JsonSchemaCredentialValidator`
- [x] Crear `ValidationResult` record
- [x] Crear `ClaimsExtractor` interfaz SPI + `ExtractedClaims` record
- [x] Crear `LearCredentialClaimsExtractor` (JSON path, coalesce v1/v2/v3)
- [x] Generar JSON Schemas para las 5 credenciales actuales
- [x] Refactorizar `CustomAuthenticationProvider`: eliminar instanceof chains, usar `ExtractedClaims`

### Paso 7: application.yaml con defaults ✅

- [x] Reescribir con defaults de desarrollo (port 8082, URLs localhost, identity vacia)
- [x] Eliminar necesidad de SPRING_PROFILES_ACTIVE

### Paso 8: Docker Compose ✅

- [x] Crear `docker/docker-compose.yml` minimo
- [x] Crear `docker/.env.example`
- [x] Crear `Makefile` con targets: help, up, down, rebuild, logs, test, build, run, clean

### Paso 9: Tests ✅

- [x] Verificar tests existentes pasan
- [x] `CryptoComponentTest` - auto-generacion P-256 + did:key
- [x] `LocalTrustedIssuersProviderTest` - YAML + wildcard
- [x] `LocalClientRegistryProviderTest` - YAML local
- [x] `JsonSchemaCredentialValidatorTest` - validacion contra schemas
- [x] `LearCredentialClaimsExtractorTest` - extraccion v1/v2/v3
- [x] `VpServiceImplTest` - flujo refactorizado
- [x] `CacheStoreTest` - TTL, add/get/delete, edge cases
- [x] `JtiTokenCacheTest` - replay prevention
- [x] `LocalSchemaResolverTest` - context URL resolution + caching
- [x] `CertificateValidationServiceImplTest` - x5c header validation
- [x] `TrustFrameworkServiceImpTest` - bitstring status list revocation (14 tests)
- [x] `VpSecurityTest` - malformed VP/VC, payload manipulation, context injection (22 tests)
- [x] `ArchitectureRulesTest` - ArchUnit: layers, naming, dependencies (13 tests)
- [x] Reducir exclusiones JaCoCo de 5 a 1 clase (AuthorizationServerConfig)
- [x] Reducir exclusiones Sonar de 7 a 2 clases

### Metricas finales de tests

| Metrica | Valor |
| --- | --- |
| Tests totales | 318 |
| Failures | 0 |
| Test files | 43 |
| Source files | 154 |
| Test LOC | 8,117 |
| Source LOC | 6,819 |
| Test:codigo ratio | 1.19:1 |
| JaCoCo exclusions | 1 (AuthorizationServerConfig) |

---

## 8. Verificacion end-to-end

1. `./gradlew test` - todos los tests pasan
2. `./gradlew bootRun` - arranca SIN perfiles, SIN env vars, SIN servicios externos
3. Log muestra: `WARNING: Generated ephemeral P-256 key. did:key:z...`
4. `curl http://localhost:8082/health` - OK
5. `docker compose -f docker/docker-compose.yml up` - arranca
6. Con config DOME (env vars) - comportamiento identico al actual
7. VP con LEARCredentialEmployee V1/V2/V3 - validadas via JSON Schema

---

## 9. Roadmap futuro (fuera de scope de esta iteracion)

### HAIP compliance -- Verifier (Section 5 only)

| Item | Req HAIP | Prioridad | Depende de |
| --- | --- | --- | --- |
| ~~Soporte `dc+sd-jwt` (SD-JWT VC)~~ | HAIP-V1 | ~~Critica~~ | **HECHO** |
| `VctSchemaResolver` (SD-JWT VC Type Metadata) | HAIP-V1 | Critica | Paso 6 |
| ~~KB-JWT validation~~ | HAIP-V17 | ~~Critica~~ | **HECHO** |
| Response encryption `direct_post.jwt` | HAIP-V3/V10-V13 | Critica | - |
| ~~DCQL query support~~ | HAIP-V14 | ~~Critica~~ | **HECHO** |
| `x509_hash` Client ID Prefix | HAIP-V7-V9 | Alta | X.509 cert no self-signed |
| `trusted_authorities` / AKI en DCQL | HAIP-V15 | Alta | Paso 4 (SPI) + DCQL |
| IETF Token Status List (`status_list`) | HAIP-V19 | Media | - |
| Issuer key via `x5c` header | HAIP-V20 | Media | PARCIAL (code ready, falta test e2e) |
| DC API flow (`dc_api.jwt`) | HAIP-V5/V6 | Baja (ecosistema) | - |
| `mso_mdoc` + `deviceSignature` | HAIP-V1/V18 | Baja (ecosistema) | - |

### Extensibilidad y limpieza

| Item | Prioridad | Depende de |
| --- | --- | --- |
| `GenericClaimsExtractor` (schema-driven) | Media | Paso 6 |
| Eliminar POJOs legacy (Fase 2) | Media | Paso 6 |
| EbsiV5 / LOTL providers | Baja | Paso 4 (SPI) |
| `RegistrySchemaResolver` (registro externo) | Baja | Paso 6 |
| Distributed token storage | Media | - |

---

## Apendice A: Ficheros clave

| Fichero | Responsabilidad |
| --- | --- |
| `component/CryptoComponent.java` | EC key P-256, firma JWT |
| `config/BackendConfig.java` | Accessor de properties + trust framework selection |
| `config/properties/BackendProperties.java` | @ConfigurationProperties validadas |
| `config/ClientLoaderConfig.java` | Carga + refresh de OIDC clients |
| `security/AuthorizationServerConfig.java` | JWKSource, token customizer, OAuth2 server |
| `security/filters/CustomAuthenticationProvider.java` | Token generation, credential -> claims |
| `security/filters/CustomAuthorizationRequestConverter.java` | Auth request handling, OID4VP |
| `security/filters/CustomTokenRequestConverter.java` | Token request handling |
| `service/impl/VpServiceImpl.java` | VP/VC validation pipeline |
| `service/impl/TrustFrameworkServiceImpl.java` | HTTP calls a EBSI, client registry, revocation |
| `service/impl/JWTServiceImpl.java` | JWT sign/verify operations |
| `util/Constants.java` | @context URLs, timeouts, feature flags |

## Apendice B: Modelo de credenciales actual (a deprecar)

```
LEARCredential (interface)
|-- LEARCredentialEmployee (interface)
|   |-- LEARCredentialEmployeeV1 (record)
|   |   +-- CredentialSubjectV1 -> MandateV1 -> MandateeV1 + PowerV1 + Mandator
|   |-- LEARCredentialEmployeeV2 (record)
|   |   +-- CredentialSubjectV2 -> MandateV2 -> MandateeV2* + PowerV2* + Mandator
|   +-- LEARCredentialEmployeeV3 (record)
|       +-- CredentialSubjectV3 -> MandateV3 -> MandateeV3 + PowerV3 + MandatorV3
+-- LEARCredentialMachine (marker interface)
    |-- LEARCredentialMachineV1 (record)
    +-- LEARCredentialMachineV2 (record)

* V2 tiene campos duplicados para retrocompatibilidad:
  MandateeV2: firstName + first_name, lastName + last_name
  PowerV2: action + tmf_action, domain + tmf_domain, etc.
```
