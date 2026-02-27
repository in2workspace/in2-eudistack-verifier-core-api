# Guia de despliegue: Verifier Core API

> Documento para implementadores. Explica como configurar, personalizar y desplegar el componente mediante Docker Compose.

**Ultima actualizacion**: 2026-02-27

---

## 1. Requisitos

| Requisito | Version minima |
| --- | --- |
| Docker | 20.10+ |
| Docker Compose | v2+ |

No requiere base de datos ni servicios externos para arrancar. Todo es in-memory y auto-configurable.

---

## 2. Arranque rapido

```bash
cd docker
cp .env.example .env
docker compose up -d --build
```

El servicio arranca en `http://localhost:8082` con:
- Identidad criptografica efimera (P-256 auto-generada)
- Trusted issuers: wildcard `*` (confiar en todos)
- Client registry: un `dev-client` local
- Schemas de credenciales embebidos (5 schemas LEAR)

No hace falta editar el `.env` para desarrollo local.

---

## 3. Configuracion

### 3.1 Principio: env vars en el compose

Toda la configuracion se gestiona via **variables de entorno** en el `docker-compose.yml` (directamente o via `.env`). Spring relaxed binding transforma los nombres:

```
verifier.backend.url                                    -> VERIFIER_BACKEND_URL
verifier.backend.identity.privateKey                    -> VERIFIER_BACKEND_IDENTITY_PRIVATEKEY
verifier.backend.trustFrameworks[0].trustedIssuersListUrl -> VERIFIER_BACKEND_TRUSTFRAMEWORKS_0_TRUSTEDISSUERSLISTURL
```

No se usan perfiles de Spring (`application-prod.yaml`, etc.).

### 3.2 Referencia completa de parametros

#### Backend (`verifier.backend.*`)

| Env var | Default | Descripcion |
| --- | --- | --- |
| `VERIFIER_BACKEND_URL` | `http://localhost:8082` | URL publica del Verifier. Se usa como `iss` en los tokens emitidos y como base para endpoints OID4VP. **Obligatorio en produccion.** |
| `VERIFIER_BACKEND_IDENTITY_PRIVATEKEY` | *(vacio)* | Clave privada EC P-256 en hexadecimal (con o sin prefijo `0x`). Si esta vacia, se genera un par efimero al arrancar (ver seccion 4). |
| `VERIFIER_BACKEND_IDENTITY_DIDKEY` | *(vacio)* | `did:key` correspondiente a la clave privada. Si esta vacio pero `privateKey` tiene valor, se deriva automaticamente. |
| `VERIFIER_BACKEND_TRUSTFRAMEWORKS_0_NAME` | `DOME` | Nombre del trust framework. Actualmente solo se soporta `DOME`. |
| `VERIFIER_BACKEND_TRUSTFRAMEWORKS_0_TRUSTEDISSUERSLISTURL` | *(vacio)* | URL de la API EBSI v4 de issuers de confianza. Si esta vacia, se usa la lista local embebida (ver seccion 5). |
| `VERIFIER_BACKEND_TRUSTFRAMEWORKS_0_TRUSTEDSERVICESLISTURL` | *(vacio)* | URL del YAML remoto con la lista de OIDC clients. Si esta vacia, se usa la lista local embebida (ver seccion 6). |
| `VERIFIER_BACKEND_LOCALFILES_CLIENTSPATH` | *(vacio)* | Path filesystem al `clients.yaml` externo. Si esta vacio, se usa el embebido en la imagen (ver seccion 6). |
| `VERIFIER_BACKEND_LOCALFILES_TRUSTEDISSUERSPATH` | *(vacio)* | Path filesystem al `trusted-issuers.yaml` externo. Si esta vacio, se usa el embebido en la imagen (ver seccion 5). |
| `VERIFIER_BACKEND_LOCALFILES_SCHEMASDIR` | *(vacio)* | Directorio filesystem con JSON Schemas externos. Si esta vacio, se usan los embebidos en la imagen (ver seccion 7). |

#### Frontend (`verifier.frontend.*`)

| Env var | Default | Descripcion |
| --- | --- | --- |
| `VERIFIER_FRONTEND_URLS_ONBOARDING` | `http://localhost:4200` | URL de la pagina de onboarding (mostrada en el QR login) |
| `VERIFIER_FRONTEND_URLS_SUPPORT` | `http://localhost:4200` | URL de soporte/ticketing |
| `VERIFIER_FRONTEND_URLS_WALLET` | `http://localhost:4200` | URL de descarga/info de la wallet |
| `VERIFIER_FRONTEND_COLORS_PRIMARY` | `#2D58A7` | Color primario del QR login (hex) |
| `VERIFIER_FRONTEND_COLORS_PRIMARYCONTRAST` | `#ffffff` | Contraste del primario |
| `VERIFIER_FRONTEND_COLORS_SECONDARY` | `#14274A` | Color secundario |
| `VERIFIER_FRONTEND_COLORS_SECONDARYCONTRAST` | `#00ADD3` | Contraste del secundario |
| `VERIFIER_FRONTEND_ASSETS_BASEURL` | `http://localhost:4200/assets` | Base URL para assets estaticos (logo, favicon) |
| `VERIFIER_FRONTEND_ASSETS_LOGOPATH` | `logo.png` | Path relativo al logo (sobre baseUrl) |
| `VERIFIER_FRONTEND_ASSETS_FAVICONPATH` | `favicon.ico` | Path relativo al favicon |
| `VERIFIER_FRONTEND_DEFAULTLANG` | `en` | Idioma por defecto (`en`, `es`, `ca`) |

#### Server

| Env var | Default | Descripcion |
| --- | --- | --- |
| `SERVER_PORT` | `8082` | Puerto HTTP |

#### Constantes hardcodeadas (no configurables via env var)

| Constante | Valor | Descripcion |
| --- | --- | --- |
| Access token TTL | 3600 segundos (1h) | Expiracion del access_token |
| ID token TTL | 60 segundos | Expiracion del id_token |
| Login timeout | 120 segundos | Timeout del flujo QR login (WebSocket) |
| Nonce obligatorio | `true` | Nonce requerido en authorization request |

---

## 4. Identidad criptografica

El Verifier firma los tokens (access_token, id_token, authorization request JWT) con una clave EC P-256.

### Modo desarrollo (sin config)

Si `VERIFIER_BACKEND_IDENTITY_PRIVATEKEY` esta vacia, el componente:
1. Genera un par EC P-256 efimero al arrancar
2. Deriva un `did:key` a partir de la clave publica
3. Emite un WARNING en el log: `Generated ephemeral P-256 key. did:key:z...`

La clave cambia en cada reinicio. No apto para produccion.

### Modo produccion (clave persistente)

```env
VERIFIER_BACKEND_IDENTITY_PRIVATEKEY=0x73e509a5d2d37e8e...  # hex, 32 bytes
# Opcional: si se omite, se deriva automaticamente
VERIFIER_BACKEND_IDENTITY_DIDKEY=did:key:zDnae...
```

Para generar un par P-256:

```bash
openssl ecparam -name prime256v1 -genkey -noout -out key.pem
openssl ec -in key.pem -text -noout 2>/dev/null | grep -A 3 "priv:" | tail -3 | tr -d ' :\n'
```

---

## 5. Trusted Issuers (quien puede emitir credenciales)

El Verifier valida que el issuer de cada VC este en una lista de confianza.

### Modo local (por defecto)

Cuando `VERIFIER_BACKEND_TRUSTFRAMEWORKS_0_TRUSTEDISSUERSLISTURL` esta **vacia**, se usa un fichero YAML embebido en la imagen. El fichero de desarrollo por defecto tiene wildcard `*` (confiar en todos):

```yaml
# Confiar en TODOS los issuers (desarrollo):
trustedIssuers:
  "*": []
```

Para confiar solo en issuers especificos:

```yaml
trustedIssuers:
  "did:elsi:VATES-A12345678":
    - credentialsType: "LEARCredentialEmployee"
  "did:elsi:VATES-B87654321":
    - credentialsType: "LEARCredentialEmployee"
    - credentialsType: "LEARCredentialMachine"
```

El fichero embebido esta en `src/main/resources/local/trusted-issuers.yaml`.

### Modo fichero externo (volumen)

Para inyectar un `trusted-issuers.yaml` personalizado **sin rebuild**, montarlo como volumen y configurar la env var:

```yaml
# docker-compose.yml
services:
  verifier:
    volumes:
      - ./config/trusted-issuers.yaml:/config/trusted-issuers.yaml:ro
    environment:
      VERIFIER_BACKEND_LOCALFILES_TRUSTEDISSUERSPATH: /config/trusted-issuers.yaml
```

El formato es identico al embebido. Si el fichero externo no existe, se usa el embebido como fallback.

En **Kubernetes**, montar un ConfigMap:

```yaml
apiVersion: v1
kind: ConfigMap
metadata:
  name: verifier-trusted-issuers
data:
  trusted-issuers.yaml: |
    trustedIssuers:
      "did:elsi:VATES-A12345678":
        - credentialsType: "LEARCredentialEmployee"
```

### Modo remoto (EBSI v4)

Cuando la env var tiene un valor, se consulta la API EBSI v4 por HTTP:

```env
VERIFIER_BACKEND_TRUSTFRAMEWORKS_0_TRUSTEDISSUERSLISTURL=https://api-pilot.ebsi.eu/trusted-issuers-registry/v4/issuers/
```

El Verifier hace `GET {url}{issuerId}` para cada issuer encontrado en un VC.

---

## 6. Client Registry (Relying Parties)

Los OIDC clients (aplicaciones que usan el Verifier como login) se registran de dos formas:

### Modo local (por defecto)

Cuando `VERIFIER_BACKEND_TRUSTFRAMEWORKS_0_TRUSTEDSERVICESLISTURL` esta **vacia**, se usa el fichero embebido `src/main/resources/local/clients.yaml`. El de desarrollo incluye un unico client:

```yaml
clients:
  - clientId: "dev-client"
    url: "http://localhost:4200"
    clientAuthenticationMethods:
      - "none"
    authorizationGrantTypes:
      - "authorization_code"
    redirectUris:
      - "http://localhost:4200/callback"
    postLogoutRedirectUris:
      - "http://localhost:4200"
    scopes:
      - "openid"
      - "lear"
    requireAuthorizationConsent: false
    requireProofKey: true
```

Para personalizar el fichero embebido, editarlo y hacer rebuild de la imagen. Para evitar rebuild, usar modo fichero externo o modo remoto (ver abajo).

### Modo fichero externo (volumen)

Para inyectar un `clients.yaml` personalizado **sin rebuild**, montarlo como volumen:

```yaml
# docker-compose.yml
services:
  verifier:
    volumes:
      - ./config/clients.yaml:/config/clients.yaml:ro
    environment:
      VERIFIER_BACKEND_LOCALFILES_CLIENTSPATH: /config/clients.yaml
```

El formato es identico al embebido. Si el fichero externo no existe, se usa el embebido como fallback.

#### Ejemplo con multiples clients

```yaml
clients:
  # Client publico (SPA):
  - clientId: "mi-portal"
    url: "https://portal.example.com"
    clientAuthenticationMethods:
      - "none"
    authorizationGrantTypes:
      - "authorization_code"
    redirectUris:
      - "https://portal.example.com/callback"
    postLogoutRedirectUris:
      - "https://portal.example.com"
    scopes:
      - "openid"
      - "lear"
    requireAuthorizationConsent: false
    requireProofKey: true

  # Client confidencial (M2M):
  - clientId: "mi-servicio-backend"
    url: "https://api.example.com"
    clientSecret: "{noop}mi-secreto"
    clientAuthenticationMethods:
      - "private_key_jwt"
    authorizationGrantTypes:
      - "client_credentials"
    redirectUris: []
    postLogoutRedirectUris: []
    scopes:
      - "openid"
      - "lear"
    requireAuthorizationConsent: false
    jwkSetUrl: "https://api.example.com/.well-known/jwks.json"
    tokenEndpointAuthenticationSigningAlgorithm: "ES256"
```

#### Campos de cada client

| Campo | Obligatorio | Descripcion |
| --- | --- | --- |
| `clientId` | Si | Identificador unico del client |
| `url` | Si | URL del client (se usa para CORS y como `clientName`) |
| `clientAuthenticationMethods` | Si | `none` (public), `client_secret_basic`, `client_secret_post`, `private_key_jwt` |
| `authorizationGrantTypes` | Si | `authorization_code`, `client_credentials`, `refresh_token` |
| `redirectUris` | Si | URIs de callback autorizadas |
| `postLogoutRedirectUris` | No | URIs de redireccion post-logout |
| `scopes` | Si | Scopes permitidos (`openid`, `lear`) |
| `requireAuthorizationConsent` | No | `false` por defecto |
| `requireProofKey` | No | `true` = PKCE obligatorio |
| `clientSecret` | No | Solo para clients confidenciales. Prefijo `{noop}` sin encoding, `{bcrypt}` para bcrypt |
| `jwkSetUrl` | No | URL JWKS para `private_key_jwt` |
| `tokenEndpointAuthenticationSigningAlgorithm` | No | Algoritmo de firma del client_assertion (ej: `ES256`) |

### Modo remoto

Cuando la env var tiene un valor, el YAML se descarga por HTTP. Se refresca automaticamente cada 30 minutos.

```env
VERIFIER_BACKEND_TRUSTFRAMEWORKS_0_TRUSTEDSERVICESLISTURL=https://raw.githubusercontent.com/mi-org/config/main/trusted_services_list.yaml
```

El formato del YAML remoto es identico al local.

---

## 7. JSON Schemas de credenciales

El Verifier valida la estructura de las Verifiable Credentials contra JSON Schemas (2020-12). Los schemas estan embebidos en la imagen:

| Schema | Context URL que lo activa |
| --- | --- |
| `LEARCredentialEmployee.v1.json` | `https://trust-framework.dome-marketplace.eu/credentials/learcredentialemployee/v1` |
| `LEARCredentialEmployee.v2.json` | `https://www.dome-marketplace.eu/2025/credentials/learcredentialemployee/v2` |
| `LEARCredentialEmployee.v3.json` | `https://credentials.eudistack.eu/.well-known/credentials/lear_credential_employee/w3c/v3` |
| `LEARCredentialMachine.v1.json` | *(default para LEARCredentialMachine sin context especifico)* |
| `LEARCredentialMachine.v2.json` | `https://credentials.eudistack.eu/.well-known/credentials/lear_credential_machine/w3c/v2` |

### Inyectar schemas via volumen (sin rebuild)

Para anadir o reemplazar schemas **sin rebuild de la imagen**, montar un directorio externo:

```yaml
# docker-compose.yml
services:
  verifier:
    volumes:
      - ./config/schemas:/config/schemas:ro
    environment:
      VERIFIER_BACKEND_LOCALFILES_SCHEMASDIR: /config/schemas
```

El directorio externo debe contener ficheros con el formato `{TipoCredencial}.{version}.json`. Los schemas externos tienen prioridad sobre los embebidos — si un schema existe en el directorio externo y tambien en la imagen, se usa el externo.

En **Kubernetes**, montar un ConfigMap con los JSON Schemas como data keys.

### Anadir un nuevo tipo de schema (requiere codigo)

Si el nuevo schema corresponde a un **context URL nuevo** que no esta mapeado:

1. Crear el JSON Schema (formato JSON Schema 2020-12)
2. Nombrar: `{TipoCredencial}.{version}.json` (ej: `LEARCredentialEmployee.v4.json`)
3. Registrar el mapping en `LocalSchemaResolver.java` — anadir entrada en `CONTEXT_MAP`:

   ```java
   "https://credentials.eudistack.eu/.../lear_credential_employee/w3c/v4",
   new CredentialTypeVersion("LEARCredentialEmployee", "v4"),
   ```

4. Si la credencial necesita extraccion de claims distinta, crear un nuevo `ClaimsExtractor`
5. Rebuild de la imagen: `docker compose up -d --build`

Si el schema corresponde a un context URL **ya mapeado** (ej: actualizar `LEARCredentialEmployee.v3.json`), basta con colocar el fichero actualizado en el directorio externo — no hace falta tocar codigo.

---

## 8. Compose: desarrollo vs produccion

### Desarrollo (docker-compose.yml incluido)

```yaml
services:
  verifier:
    build:
      context: ..
      dockerfile: docker/Dockerfile
      args:
        SKIP_TESTS: "true"
    container_name: verifier
    ports:
      - "8082:8082"
    env_file:
      - .env
    environment:
      SERVER_PORT: 8082
    restart: unless-stopped
```

### Produccion

```yaml
services:
  verifier:
    image: registry.example.com/verifier-core-api:2.1.0
    container_name: verifier
    ports:
      - "8082:8082"
    env_file:
      - .env
    volumes:
      - ./config/clients.yaml:/config/clients.yaml:ro
      - ./config/trusted-issuers.yaml:/config/trusted-issuers.yaml:ro
      - ./config/schemas:/config/schemas:ro
    restart: unless-stopped
    healthcheck:
      test: ["CMD", "wget", "-q", "--spider", "http://localhost:8082/health"]
      interval: 30s
      timeout: 5s
      retries: 3
```

### `.env` de produccion

```env
# --- Obligatorio ---
VERIFIER_BACKEND_URL=https://verifier.midominio.com

# --- Identidad (clave fija, no efimera) ---
VERIFIER_BACKEND_IDENTITY_PRIVATEKEY=0x73e509a5d2d37e8e...

# --- Trust Framework ---
# Trusted Issuers: dejar vacio para usar la lista local embebida,
# o poner URL para consultar EBSI v4:
VERIFIER_BACKEND_TRUSTFRAMEWORKS_0_TRUSTEDISSUERSLISTURL=https://api-pilot.ebsi.eu/trusted-issuers-registry/v4/issuers/

# Client Registry: dejar vacio para usar clients.yaml embebido,
# o poner URL para descargar YAML remoto (refresh cada 30 min):
VERIFIER_BACKEND_TRUSTFRAMEWORKS_0_TRUSTEDSERVICESLISTURL=https://raw.githubusercontent.com/mi-org/config/main/trusted_services_list.yaml

# --- Ficheros locales externos (alternativa a modo remoto y a rebuild) ---
# Si se montan volumenes con config personalizada, indicar los paths:
VERIFIER_BACKEND_LOCALFILES_CLIENTSPATH=/config/clients.yaml
VERIFIER_BACKEND_LOCALFILES_TRUSTEDISSUERSPATH=/config/trusted-issuers.yaml
VERIFIER_BACKEND_LOCALFILES_SCHEMASDIR=/config/schemas

# --- Frontend ---
VERIFIER_FRONTEND_URLS_ONBOARDING=https://portal.midominio.com/onboarding
VERIFIER_FRONTEND_URLS_SUPPORT=https://portal.midominio.com/soporte
VERIFIER_FRONTEND_URLS_WALLET=https://wallet.midominio.com

# --- Branding ---
VERIFIER_FRONTEND_COLORS_PRIMARY=#1A73E8
VERIFIER_FRONTEND_COLORS_PRIMARYCONTRAST=#ffffff
VERIFIER_FRONTEND_ASSETS_BASEURL=https://cdn.midominio.com/assets
VERIFIER_FRONTEND_ASSETS_LOGOPATH=mi-logo.svg
VERIFIER_FRONTEND_ASSETS_FAVICONPATH=mi-favicon.ico
```

---

## 9. Endpoints

| Endpoint | Metodo | Descripcion |
| --- | --- | --- |
| `/health` | GET | Health check |
| `/prometheus` | GET | Metricas Prometheus |
| `/.well-known/openid-configuration` | GET | OIDC Discovery (auto-generado por Spring Auth Server) |
| `/oauth2/authorize` | GET | Authorization endpoint |
| `/oauth2/token` | POST | Token endpoint |
| `/oauth2/jwks` | GET | JWK Set del Verifier |
| `/oid4vp/auth-response` | POST | Endpoint `direct_post` donde la wallet envia el VP Token |
| `/login` | GET | Pagina QR login (Thymeleaf) |
| `/client-error` | GET | Pagina de error de autenticacion del client |
| `/api/v1/resolve-did` | POST | Resolucion did:key -> JWK |

---

## 10. Limitaciones actuales

| Limitacion | Workaround | Solucion propuesta |
| --- | --- | --- |
| TTLs hardcodeados (access_token 1h, id_token 60s, login 120s) | Rebuild | Externalizar a `application.yaml` como properties |
| Solo un trust framework (`DOME`) | - | Soporte multi-trust-framework |
| Client registry refresh solo cada 30 min | Reiniciar contenedor | Endpoint de refresh manual |
| Anadir un context URL nuevo para schemas requiere codigo | Rebuild con nueva entrada en `CONTEXT_MAP` | Registry de context-to-schema configurable via YAML |
