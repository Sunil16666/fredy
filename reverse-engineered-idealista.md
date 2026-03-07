# Reverse Engineered Idealista's Mobile API

## What is Idealista?

Idealista is Spain's largest real estate portal, covering both residential rentals and sales across Spain, Italy, and Portugal. In Spain it dominates the market with millions of monthly visits, listing everything from city-centre flats to rural fincas. Users search by city, neighbourhood, price, size, and dozens of other filters. Idealista is available as a website and as a mobile application for Android and iOS.

## Why do we use the mobile API?

Idealista's web frontend is protected by **DataDome**, a commercial WAF (Web Application Firewall) purpose-built to detect and block automated browser access. DataDome performs real-time fingerprinting of:

1. TLS/JA3 fingerprints (Puppeteer's TLS stack is identifiable)
2. Browser environment signals (navigator properties, WebGL, canvas hashes)
3. Mouse and scroll behaviour analysis
4. IP reputation (datacenter / VPS ranges are blocked immediately)
5. JavaScript challenges that must be solved within a tight time window

Even with the existing `botPrevention.js` stealth configuration — webdriver spoofing, randomised viewport, human-style mouse signals, Chrome fingerprint patching — DataDome reliably blocks Puppeteer access from any non-residential IP. Proxy infrastructure would be required to make web scraping viable, which is impractical for a self-hosted tool.

The **Android mobile app** calls a separate backend (`app.idealista.com`) that has no WAF in front of it, making it accessible from any IP with the correct credentials and a valid HMAC signature.

## Reverse Engineering Approach

The Idealista Android APK (`idealista_14.3.3.xapk`) was decompiled using **jadx** into Java source. The relevant `.dex` file is `classes10.dex`. Most classes were renamed by ProGuard/R8; jadx restores names from Kotlin `@Metadata` annotations where possible.

Key decompiled source files are preserved in [reverse-engineering/idealista/](reverse-engineering/idealista/):

| File | Original source | Role |
| ---- | --------------- | ---- |
| [`eqd.java`](reverse-engineering/idealista/eqd.java) | `SignatureInterceptor.kt` | HMAC-SHA256 request signing |
| [`fqd.java`](reverse-engineering/idealista/fqd.java) | `SignatureInterceptor.kt` (helpers) | Request param extraction for signing |
| [`v5e.java`](reverse-engineering/idealista/v5e.java) | `StringsExtensions.kt` | Runtime string obfuscation (character-by-character) |
| [`fic.java`](reverse-engineering/idealista/fic.java) | `RequestInterceptor.kt` | Adds `k`, `t` query params and common headers |
| [`x8a.java`](reverse-engineering/idealista/x8a.java) | `OAuthService.kt` | OAuth2 token acquisition |
| [`g07.java`](reverse-engineering/idealista/g07.java) | `IdealistaOAuth2.kt` | Retrofit interface for OAuth endpoint |
| [`g6d.java`](reverse-engineering/idealista/g6d.java) | `SearchService.kt` | Retrofit interfaces for search and location endpoints |
| [`w4.java`](reverse-engineering/idealista/w4.java) | `ApiClient.kt` | Main OkHttpClient builder and interceptor chain setup |
| [`AuthConfig.java`](reverse-engineering/idealista/AuthConfig.java) | `AuthConfig.kt` (data class) | Holds `consumerKey` and `consumerSecret` |
| [`ApiClientConfig.java`](reverse-engineering/idealista/ApiClientConfig.java) | `ApiClient.kt` (data class) | Full client configuration |
| [`OAuthEntity.java`](reverse-engineering/idealista/OAuthEntity.java) | `OAuthEntity.kt` (data class) | OAuth token response model |
| [`Cfor.java`](reverse-engineering/idealista/Cfor.java) | `AppDependencyInjector.kt` | Wires credentials at startup |
| [`en6.java`](reverse-engineering/idealista/en6.java) | `GsonConverterFactory.kt` | Gson/JSON converter factory |
| [`ilc.java`](reverse-engineering/idealista/ilc.java) | `Retrofit.kt` | Retrofit builder |
| [`ps.java`](reverse-engineering/idealista/ps.java) | `ApiKey.kt` (data class) | API key wrapper |
| [`nkc.java`](reverse-engineering/idealista/nkc.java) | `Call.kt` | Retrofit Call wrapper |
| [`ly0.java`](reverse-engineering/idealista/ly0.java) | `Observable.kt` | RxJava observable wrapper |

Retrofit annotations were obfuscated; the mapping is:

| Obfuscated | Retrofit original |
| ---------- | ----------------- |
| `@xra` | `@POST` |
| `@oo5` | `@GET` |
| `@cj5` | `@FormUrlEncoded` |
| `@cva` | `@Path` |
| `@m85` | `@FieldMap` |
| `@j4c` | `@Query` |
| `@d85` | `@Field` |
| `@co0` | `@Body` |

### Credential Extraction

API credentials are stored in `resources.arsc` (compiled Android string resources). They were extracted by parsing the binary with `androguard`:

```python
from androguard.core.axml import ARSCParser
with open("resources.arsc", "rb") as f:
    parser = ARSCParser(f.read())
xml_bytes = parser.get_strings_resources("com.idealista.android")
# parse xml_bytes for <string name="apiKey"> and <string name="secretKey">
```

Extracted values:

| Resource | Value |
| -------- | ----- |
| `R.string.apiKey` | `5b85c03c16bbb85d96e232b112ee85dc` |
| `R.string.secretKey` | `idea;andr01d` |
| `url_idealista_secure_es` | `https://app.idealista.com` |

The HMAC signing key is **not** stored as a string resource. It is constructed at runtime by `v5e.java` (StringsExtensions.kt), which builds strings by chaining method calls that each append exactly one character. The mapping of method name → appended character is:

```text
abstract→U  break→=  case→D  catch→g  class→h  const→H
continue→W  default→R  else→e  extends→S  final→i  finally→t
for→B  goto→E  import→N  interface→a  native→O  new→c
package→T  private→u  protected→A  public→2  return→5  static→6
strictfp→X  super→K  switch→Q  this→F  throw→m  throws→r
try→d  volatile→y  while→n
```

Decoding the `f26999try` constant (innermost call first):

```text
for→b  while→X  for→B  continue→W  continue→W  while→n  static→6
native→O  default→R  class→h  super→K  try→d  this→F  class→h
goto→E  import→N  throw→m  switch→Q  volatile→y
default→R  switch→Q  break→=  break→=
→ "bXBUUW5TODhKdFhENmQyRQ=="
```

The resulting string **`bXBUUW5TODhKdFhENmQyRQ==`** is used as UTF-8 bytes directly as the HMAC-SHA256 key — it is **not** base64-decoded before use.

---

## Authentication

Idealista uses OAuth2 with the **client_credentials** grant. The OAuth endpoint uses its own `OkHttpClient` (see `x8a.java`) **without** the HMAC SignatureInterceptor — no `Signature` or `seed` headers are needed on the token request.

```http
POST https://app.idealista.com/api/oauth/token
Authorization: Basic <credentials>
Content-Type: application/x-www-form-urlencoded
app_version: 14.3.3
device_identifier: <any_stable_device_id>
User-Agent: idealista/14.3.3 (Android)

grant_type=client_credentials&scope=write
```

The `<credentials>` value is:

```text
base64( URLEncode(consumerKey) + ":" + URLEncode(consumerSecret) )
```

where `URLEncode` follows **Java's `URLEncoder.encode(..., "UTF-8")`** semantics: spaces become `+`, and characters outside `A-Z a-z 0-9 - _ . *` are percent-encoded. Since the secret `idea;andr01d` contains a semicolon, the encoded form is `idea%3Bandr01d`.

```bash
curl -X POST https://app.idealista.com/api/oauth/token \
  -H "Authorization: Basic NWI4NWMwM2MxNmJiYjg1ZDk2ZTIzMmIxMTJlZTg1ZGM6aWRlYSUzQmFuZHIwMWQ=" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -H "app_version: 14.3.3" \
  -H "device_identifier: deadbeefdeadbeef" \
  -d "grant_type=client_credentials&scope=write"
```

Response:

```json
{
  "access_token": "<token>",
  "token_type": "bearer",
  "expires_in": 3600,
  "scope": "write"
}
```

Tokens should be cached and reused until ~60 seconds before expiry.

---

## Request Signing (HMAC-SHA256)

Every API request **except** the OAuth token endpoint must include two additional headers:

- `Signature`: hex-encoded lowercase HMAC-SHA256 digest
- `seed`: the UUID nonce used in the message

This is implemented in `eqd.java` (SignatureInterceptor.kt). The request interceptor chain runs in this order:

1. **`fic.java`** (RequestInterceptor): appends `k=<apiKey>` and `t=<deviceId>` as URL query parameters, and adds `app_version`, `device_identifier`, `User-Agent` headers.
2. **`eqd.java`** (SignatureInterceptor): computes HMAC over the fully-built request (including `k` and `t`).

The `k` and `t` query parameters must therefore be included in the signing input.

### Message Construction

**For GET requests:**

```text
message = UUID + "GET" + sortedQueryString
```

**For form-encoded POST requests (`Content-Type: application/x-www-form-urlencoded`):**

```text
message = UUID + "POST" + sortedQueryString + sortedBodyString
```

**For JSON POST requests (`Content-Type: application/json`):**

```text
message = UUID + "POST" + sortedQueryString + rawJsonBody
```

Where `sortedQueryString` and `sortedBodyString` are constructed as follows:

1. Take all key/value pairs (URL-decoded from the wire format)
2. Sort entries alphabetically by key (`String.localeCompare`)
3. Re-encode each key and value with **Java URLEncoder** semantics (see below)
4. Join with `&`

**Java URLEncoder semantics in JavaScript:**

```javascript
function javaUrlEncode(s) {
  return encodeURIComponent(String(s))
    .replace(/%20/g, '+')
    .replace(/[!'()*]/g, (c) => '%' + c.charCodeAt(0).toString(16).toUpperCase());
}
```

**HMAC computation:**

```javascript
import { createHmac, randomUUID } from 'crypto';

const nonce = randomUUID();
const sig = createHmac('sha256', Buffer.from('bXBUUW5TODhKdFhENmQyRQ==', 'utf8'))
  .update(message, 'utf8')
  .digest('hex');

// Add to request:
// Signature: sig
// seed: nonce
```

---

## API Endpoints

All endpoints are on `https://app.idealista.com`. All non-OAuth requests require:

- `Authorization: Bearer <access_token>`
- `Signature: <hmac_hex>`
- `seed: <uuid_nonce>`
- `app_version: 14.3.3`
- `device_identifier: <device_id>`
- Query params `k=<apiKey>&t=<deviceId>` (included in HMAC signing)

---

### 1. Get OAuth Token

`POST /api/oauth/token`

See [Authentication](#authentication) above. No HMAC signing required.

---

### 2. Location Prefix Search

`GET /api/3/{country}/locations`

Translates a human-readable location slug (from the web URL) into a numeric `locationId` required by the search endpoint.

**Path parameters:**

- `{country}`: `es` (Spain), `it` (Italy), `pt` (Portugal)

**Query parameters** (in addition to `k` and `t`):

| Parameter | Example | Description |
| --------- | ------- | ----------- |
| `prefix` | `madrid` | First word of the location slug to search |
| `propertyType` | `homes` | Property type (see search params table) |
| `operation` | `rent` | `rent` or `sale` |

```bash
curl "https://app.idealista.com/api/3/es/locations?k=5b85c03c16bbb85d96e232b112ee85dc&t=deadbeefdeadbeef&prefix=madrid&propertyType=homes&operation=rent" \
  -H "Authorization: Bearer <token>" \
  -H "Signature: <sig>" \
  -H "seed: <nonce>" \
  -H "app_version: 14.3.3" \
  -H "device_identifier: deadbeefdeadbeef"
```

Response contains an array of location objects. The most relevant field is `locationId`:

```json
[
  {
    "locationId": "0-EU-ES-28-07-001-079",
    "name": "Madrid",
    "subTypeText": "Capital"
  }
]
```

The `locationId` uses a hierarchical format: `0-EU-{ISO_COUNTRY}-{province}-{region}-{municipality}`.

---

### 3. Search Listings

`POST /api/3.5/{country}/search`

Returns a paginated list of property listings. Body is **form-encoded** (`@FieldMap`).

**Path parameters:**

- `{country}`: `es`, `it`, `pt`

**Body parameters** (form-encoded, all included in HMAC signing):

| Parameter | Example | Description |
| --------- | ------- | ----------- |
| `operation` | `rent` | `rent` or `sale` |
| `propertyType` | `homes` | `homes`, `offices`, `premises`, `garages`, `bedrooms`, `newDevelopments`, `land` |
| `locationId` | `0-EU-ES-28-07-001-079` | From location endpoint |
| `numPage` | `1` | Page number (1-based) |
| `maxItems` | `40` | Results per page (max 40) |
| `order` | `publicationDate` | Sort field — use camelCase |
| `sort` | `desc` | `asc` or `desc` |

```bash
curl -X POST "https://app.idealista.com/api/3.5/es/search?k=5b85c03c16bbb85d96e232b112ee85dc&t=deadbeefdeadbeef" \
  -H "Authorization: Bearer <token>" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -H "Signature: <sig>" \
  -H "seed: <nonce>" \
  -H "app_version: 14.3.3" \
  -H "device_identifier: deadbeefdeadbeef" \
  -d "operation=rent&propertyType=homes&locationId=0-EU-ES-28-07-001-079&numPage=1&maxItems=40&order=publicationDate&sort=desc"
```

Response structure:

```json
{
  "elementList": [
    {
      "propertyCode": 110842942,
      "price": 1200.0,
      "size": 75.0,
      "address": "Calle Mayor, Madrid Centro",
      "url": "https://www.idealista.com/inmueble/110842942/",
      "thumbnail": "https://img4.idealista.com/blur/WEB_LISTING/0/id.pro.es.image.master/...",
      "suggestedTexts": {
        "title": "Piso en alquiler en Calle Mayor",
        "subtitle": "3 hab. · 75 m² · 3ª planta"
      },
      "rooms": 3,
      "bathrooms": 1,
      "floor": "3",
      "hasLift": true
    }
  ],
  "total": 1842,
  "totalPages": 47,
  "actualPage": 1,
  "itemsPerPage": 40
}
```

**Field mapping to fredy's listing schema:**

| API field | Fredy field | Notes |
| --------- | ----------- | ----- |
| `propertyCode` | `id` | Cast to string |
| `price` | `price` | Numeric EUR, cast to string |
| `size` | `size` | Numeric m², formatted as `"75 m²"` |
| `suggestedTexts.title` | `title` | Falls back to `address` |
| `suggestedTexts.subtitle` | `description` | Room/floor summary |
| `url` | `link` | Full `https://www.idealista.com/inmueble/...` URL |
| `address` | `address` | Street + district |
| `thumbnail` | `image` | CDN image URL |

---

## URL Translation (Web → API)

The fredy provider accepts standard Idealista web search URLs and translates them to API parameters.

**Web URL format:**

```text
https://www.idealista.com/{operation}-{propertyType}/{location-slug}/
```

**Translation rules:**

| URL segment | API parameter | Mapping |
| ----------- | ------------- | ------- |
| `alquiler-*` | `operation` | `rent` |
| `venta-*` | `operation` | `sale` |
| `*-viviendas`, `*-pisos`, `*-casas` | `propertyType` | `homes` |
| `*-oficinas` | `propertyType` | `offices` |
| `*-locales-comerciales` | `propertyType` | `premises` |
| `{location-slug}` | `locationId` | Resolved via location prefix endpoint; first word used as `prefix` |

**Examples:**

| Web URL | API parameters |
| ------- | -------------- |
| `.../alquiler-viviendas/madrid-madrid/` | `operation=rent, propertyType=homes, locationId=0-EU-ES-28-07-001-079` |
| `.../venta-viviendas/barcelona/` | `operation=sale, propertyType=homes, locationId=0-EU-ES-08-19-900-8019` |
| `.../alquiler-pisos/valencia-valencia/` | `operation=rent, propertyType=homes, locationId=...` |

---

## Known Limitations and Gotchas

### `filter` parameter on location endpoint

The location endpoint Retrofit signature in `g6d.java` includes a `@j4c("filter")` parameter, but passing any value (`rent`, `sale`, `location`, etc.) results in a `400 Invalid value for filter` error. The parameter should be omitted entirely — the endpoint works correctly without it.

### `order` parameter must be camelCase

The search endpoint rejects `publication-date` or `publication_date`. The correct value is `publicationDate`. Other known accepted values: `price`, `rooms`, `size`.

### HMAC key is NOT base64-decoded

The string `bXBUUW5TODhKdFhENmQyRQ==` looks like base64, but it is used **as-is** as UTF-8 bytes for the HMAC key. Decoding it first produces an incorrect signature and `400` / `401` errors.

### Java URLEncoder vs encodeURIComponent

JavaScript's `encodeURIComponent` does not encode `!`, `'`, `(`, `)`, `*`. Java's `URLEncoder.encode` does encode these. The mismatch causes invalid signatures if any parameter value contains these characters. Always use the `javaUrlEncode` wrapper shown above.

### OAuth uses Java URLEncoder on credentials

Both `consumerKey` and `consumerSecret` are passed through `URLEncoder.encode` before base64 encoding. For the current secret `idea;andr01d`, the semicolon becomes `%3B`, giving `idea%3Bandr01d` as the encoded secret.

### Token caching

Tokens expire in 3600 seconds. The implementation caches the token in memory and re-requests 60 seconds before expiry. A fredy restart will always fetch a fresh token.

### Device ID

`t` (the `device_identifier` / `android_id`) can be any stable string — the API does not validate it against a device registry. `deadbeefdeadbeef` works in practice.

---

## Implementation Reference

See [lib/provider/idealista.js](lib/provider/idealista.js) for the complete fredy provider implementation.
