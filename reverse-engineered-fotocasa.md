# Reverse Engineered Fotocasa's Mobile API

## What is Fotocasa?

Fotocasa is one of Spain's largest real estate portals, operated by Adevinta Spain. It covers residential rentals, sales, room shares, and new construction across all of Spain. The platform is available as a website and as a mobile application (package `com.adevinta.fotocasa`) for Android and iOS.

## Why do we use the mobile API?

Fotocasa's web frontend uses **Imperva** (Incapsula) as its WAF, combined with certificate pinning on the mobile side. The existing `botPrevention.js` stealth configuration (webdriver spoofing, randomised viewport, human-style mouse signals, Chrome fingerprint patching) is not sufficient to bypass Imperva reliably from non-residential IPs.

The **Android mobile app** calls a separate backend (`search.gw.fotocasa.es`) using AES-128-CBC request signatures — no user OAuth is required for public property search. This makes it accessible from any IP with a valid signature.

## Reverse Engineering Approach

The Fotocasa Android APK (`fotocasa_7.318.1.xapk`) was decompiled using **jadx** into Java source. Key source files (with Kotlin metadata preserved by jadx) are in `reverse-engineering/photocasa/`.

Key decompiled source files:

| File | Role |
| ---- | ---- |
| `com/adevinta/fotocasa/data/interceptors/HeaderRequestFotocasaInterceptor.java` | Adds all API request headers |
| `com/adevinta/fotocasa/data/signature/RequestSignatureApi.java` | Computes the `Signature` header value |
| `com/adevinta/fotocasa/data/signature/RequestEncryptionApi.java` | AES-128-CBC encryption implementation |
| `com/adevinta/realestate/core/constants/ConstantsWs.java` | Contains `PWD_WS = "ftcipanuntis2009"` |
| `com/adevinta/fotocasa/data/infraestructure/di/FotocasaNetworkModuleKt.java` | Defines all base URLs |
| `com/scm/fotocasa/properties/data/datasource/api/PropertiesApiInterface.java` | Retrofit interface for search endpoints |
| `com/scm/fotocasa/properties/data/datasource/api/PropertiesApiClient.java` | Shows `mediaSizes` value construction |
| `com/adevinta/fotocasa/data/datasource/api/model/MediaSizeType.java` | `MediaSizeType.list = [LARGE, EXTRA_SMALL, LARGE_LEGACY]` |
| `com/scm/fotocasa/properties/common/data/api/model/PlaceholdersSearcherPropertiesListDto.java` | Top-level search response model |
| `com/scm/fotocasa/properties/common/data/api/model/PlaceholdersSearchDto.java` | Per-item wrapper (`type` + `property`) |
| `com/scm/fotocasa/properties/common/data/api/model/SearcherPropertyDto.java` | Listing data model (all fields) |
| `com/scm/fotocasa/properties/common/data/api/model/PlaceholderType.java` | `"PROPERTY"`, `"SUPER_TOP"`, `"ENTRY_POINT"`, `"SAITAMA"` |
| `com/scm/fotocasa/properties/data/datasource/api/model/PlaceholdersSearchByUrlResponseDto.java` | `searchByUrl` response wrapper |

---

## Request Signing (AES-128-CBC)

Every request must include the following headers (added by `HeaderRequestFotocasaInterceptor`):

| Header | Value |
| ------ | ----- |
| `X-Source` | `android-fc--app` |
| `Device-Token` | Stable UUID identifying the device |
| `Timestamp` | Current epoch milliseconds as a string |
| `Signature` | AES-128-CBC ciphertext (see below) |
| `Accept-Language` | `es` |
| `Authentication-Token` | User OAuth token — **not required** for public search |

### Signature Computation

From `RequestSignatureApi.java` and `RequestEncryptionApi.java`:

```text
key   = MD5("ftcipanuntis2009") as raw bytes  [16 bytes]
iv    = 0x00000000000000000000000000000000  [16 zero bytes]
input = (deviceId + timestamp) as UTF-8 bytes
cipher = AES/CBC/PKCS7Padding
output = lowercase hex of ciphertext
```

**JavaScript implementation:**

```javascript
import { createCipheriv, createHash } from 'crypto';

function computeSignature(deviceId, timestamp) {
  const key = createHash('md5').update('ftcipanuntis2009', 'utf8').digest();
  const iv = Buffer.alloc(16, 0);
  const input = Buffer.from(deviceId + String(timestamp), 'utf8');
  const cipher = createCipheriv('aes-128-cbc', key, iv);
  return Buffer.concat([cipher.update(input), cipher.final()]).toString('hex');
}
```

The `Device-Token` header and the `deviceId` used as AES input must be the same value.

---

## Base URLs

From `FotocasaNetworkModuleKt.java`:

| Service | Base URL |
| ------- | -------- |
| API Gateway (unqualified `CommonRetrofit`) | `https://apps.gw.fotocasa.es` |
| Search (`searchRetrofit` qualifier) | `https://search.gw.fotocasa.es` |
| Privacy & Auth | `https://privacyandauth.gw.fotocasa.es` |
| Alerts | `https://savedsearch.alerts.gw.fotocasa.es` |

`PropertiesApiInterface` (and thus `PropertiesApiClient`) is bound to the unqualified `CommonRetrofit`, which uses the **API Gateway** base URL. The fredy provider calls `https://apps.gw.fotocasa.es/placeholders/searchByUrl`.

---

## API Endpoints

### Search by Web URL

```
GET https://apps.gw.fotocasa.es/placeholders/searchByUrl
```

**Query parameters:**

| Parameter | Example | Description |
| --------- | ------- | ----------- |
| `urlValue` | `https://www.fotocasa.es/es/alquiler/...` | Standard fotocasa web search URL |
| `uid` | _(omit)_ | Optional user ID — omit for unauthenticated search |
| `mediaSizes` | `LARGE,EXTRA_SMALL,LARGE_LEGACY` | Image size variants to include |

The `mediaSizes` value is derived from `MediaSizeType.Companion.getList()` which returns `[LARGE, EXTRA_SMALL, LARGE_LEGACY]` joined with commas. This is constructed in `PropertiesApiClient.placeholdersSearchByUrl()`.

**Example:**

```bash
curl "https://apps.gw.fotocasa.es/placeholders/searchByUrl?urlValue=https%3A%2F%2Fwww.fotocasa.es%2Fes%2Falquiler%2Fviviendas%2Fmadrid-capital%2Ftodas-las-zonas%2Fl&mediaSizes=LARGE%2CEXTRA_SMALL%2CLARGE_LEGACY" \
  -H "X-Source: android-fc--app" \
  -H "Device-Token: c4a3f2e1-b0d9-4e87-a562-f1c3e7d29b40" \
  -H "Timestamp: 1735000000000" \
  -H "Signature: <aes_hex>" \
  -H "Accept-Language: es" \
  -H "Accept: application/json"
```

**Response structure:**

```json
{
  "searcherPlaceholdersListDto": {
    "placeholders": [
      {
        "type": "PROPERTY",
        "property": {
          "propertyId": 12345678,
          "price": 1200,
          "surface": 75,
          "rooms": 3,
          "bathrooms": 1,
          "title": "Piso en alquiler",
          "addressLine": "Calle Mayor, Madrid",
          "urlMarketplace": "https://www.fotocasa.es/es/alquiler/vivienda/madrid-capital/...",
          "photo": "https://fotocasa.es/...",
          "photoLarge": "https://fotocasa.es/...",
          "latitude": 40.41650,
          "longitude": -3.70379,
          "comments": "Luminoso piso de 3 habitaciones..."
        }
      },
      {
        "type": "SUPER_TOP",
        "property": { ... }
      },
      {
        "type": "SAITAMA",
        "advertisingSaitamaDto": { ... }
      }
    ],
    "info": {
      "count": "1523",
      "query": "...",
      "recommendationId": "..."
    }
  }
}
```

**Placeholder types** (from `PlaceholderType.java`):

| JSON value | Description |
| ---------- | ----------- |
| `PROPERTY` | Regular listing — contains a `property` object |
| `SUPER_TOP` | Featured/paid listing — also contains `property` |
| `ENTRY_POINT` | UI navigation element — no `property` |
| `SAITAMA` | Advertisement — no `property` |

The fredy provider filters for `type === 'PROPERTY'` only.

---

## Field Mapping

**`SearcherPropertyDto` → fredy listing schema:**

| API field | JSON name | Fredy field | Notes |
| --------- | --------- | ----------- | ----- |
| `propertyId` | `propertyId` | `id` | Cast to string |
| `price` | `price` | `price` | Integer EUR, cast to string |
| `surface` | `surface` | `size` | Integer m², formatted as `"75 m²"` |
| `title` | `title` | `title` | Falls back to `addressLine` |
| `comments` | `comments` | `description` | Free-text listing description |
| `urlMarketplace` | `urlMarketplace` | `link` | Full fotocasa.es URL |
| `addressLine` | `addressLine` | `address` | Street + neighbourhood |
| `photoLarge` | `photoLarge` | `image` | Falls back to `photo` |
| `latitude` | `latitude` | `latitude` | Direct — skips Nominatim geocoding |
| `longitude` | `longitude` | `longitude` | Direct — skips Nominatim geocoding |

---

## Known Limitations and Gotchas

### Single page per call

The `searchByUrl` endpoint returns one page of results (approximately 30 listings) per API call. Unlike the idealista API which exposes explicit pagination params, fotocasa's `searchByUrl` endpoint does not expose a `page` parameter in the Retrofit interface. The fredy provider fetches one page per run; since fredy tracks seen listings across runs and only notifies for new ones, new listings will be caught on the next scheduled run.

### Device ID stability

The `Device-Token` header and AES input use the same `deviceId`. A stable hardcoded UUID is used (`c4a3f2e1-b0d9-4e87-a562-f1c3e7d29b40`). The API does not validate device IDs against a registry.

### Authentication-Token not required

Public property searches work without an `Authentication-Token`. The header is included in the interceptor for authenticated (logged-in) sessions only.

### `urlValue` URL format

The `urlValue` parameter accepts standard fotocasa web search URLs. The API backend parses the URL to extract search parameters, making the fredy integration very clean — users configure a search URL from the fotocasa website directly. Example URL format:

```text
https://www.fotocasa.es/es/alquiler/viviendas/madrid-capital/todas-las-zonas/l
```

---

## Imperva Mobile Protect — X-D-Token

### How the token is generated

The app uses the **Imperva Mobile Protect SDK** (formerly Distil Networks), shipped as:

- Java wrapper: `com.distil.protection.android.Protection` (decompiled from `classes3.dex`)
- Native library: `libbf93.so` (1.2 MB, ARM64, heavily obfuscated)
- Obfuscated Java glue: `app.tango.o.*` package

Flow (`ProtectionModuleKt` → `FotocasaImpervaSdkWrapper` → `Protection`):

1. The SDK is initialized with the challenge URL hardcoded in `ProtectionModuleKt`:

   ```text
   https://www.fotocasa.es/rSa9Vzy3KajA9f9m/v1/challenge
   ```

2. It runs a background `ProtectionService` in a **separate Android process** (IPC via `Messenger`/`Binder`).
3. It collects device fingerprints:
   - Network interfaces (display names, IP addresses, MTU) via `NetworkInterface`
   - Sensor data (accelerometer / rotation vector) via `SensorManager`
   - Process identity, biometrics flag
4. The native library (`libbf93.so`) signs the fingerprint payload and submits it to the challenge URL.
5. The server returns an **opaque token** that is sent as the `X-D-Token` request header on every protected API call.

### URL patterns protected by Imperva

From `ProtectionModuleKt.protectionModule$lambda$0$3()` (regex list):

```text
https://apps\.gw\.\.?.*fotocasa\.es/.*
https://api\.\.?.*fotocasa\.es/messaging/cc_proxy/.*
https://ptaformbuilder-classifiedads\.\.?.*spain\.advgo\.net/.*
https://ptaphotouploader-classifiedads\.\.?.*spain\.advgo\.net/.*
https://ptaadinsertion-classifiedads\.\.?.*spain\.advgo\.net/.*
https://privacyandauth\.gw\.\.?.*fotocasa\.es/.*
```

Both `apps.gw.fotocasa.es` (used by fredy) and `privacyandauth.gw.fotocasa.es` are in this list, so **every API call requires a valid `X-D-Token`**.

### Why it cannot be replicated in Node.js

The token generation requires:

- Android-specific APIs (`SensorManager`, `NetworkInterface` with hardware-level data)
- The obfuscated native library `libbf93.so` (ARM64 only)
- A registered Android device identity that the Imperva backend can validate

There is no public specification for the challenge protocol; the native library is too obfuscated to reverse practically.

### How to obtain a valid X-D-Token

#### Option A — mitmproxy (simplest, no root required)

1. Install the fotocasa Android app on a physical device or emulator.
2. Configure [mitmproxy](https://mitmproxy.org/) as the device's HTTP proxy and install its CA certificate.
3. Open the app and perform any property search.
4. In mitmproxy, filter requests to `apps.gw.fotocasa.es` and copy the `X-D-Token` header value.
5. Set it in fredy via `sourceConfig.xDToken` or the `FOTOCASA_X_D_TOKEN` environment variable.

Note: the app uses certificate pinning for some endpoints, so you may need to disable it. On a non-rooted device, use an **Android 6–9 emulator** (AVD) which trusts user-installed CAs without pinning bypass.

#### Option B — Frida hook (extracts tokens automatically, requires root/emulator)

On a rooted device or Android emulator with Frida server running:

```javascript
// frida -U -n com.anuntis.fotocasa -l extract_token.js
Java.perform(() => {
  const Wrapper = Java.use('com.adevinta.fotocasa.data.imperva.FotocasaImpervaSdkWrapper');
  Wrapper.getToken.implementation = function () {
    const token = this.getToken();
    console.log('[X-D-Token]', token);
    return token;
  };
});
```

Run the script, trigger a search in the app, and the token prints to the Frida console.

#### Option C — Emulator with mitmproxy (no physical device)

Use Android Studio's AVD (API level 28 or lower) which accepts user-installed certificates without root:

```bash
# Start emulator with writable system image
emulator -avd Pixel_4_API_28 -writable-system
# Proxy all traffic through mitmproxy on port 8080
adb shell settings put global http_proxy 192.168.1.x:8080
```

Install the fotocasa APK (`com.anuntis.fotocasa.apk` from the extracted XAPK), open it, and capture tokens via mitmproxy.

### Token lifetime

The token is session-scoped. Based on typical Imperva Mobile Protect deployments, tokens expire after **several minutes to a few hours**. The fredy provider accepts the token via:

- `sourceConfig.xDToken` (job config)
- `db/fotocasa-x-d-token.txt` (file, re-read each run)
- `FOTOCASA_X_D_TOKEN` environment variable

Using the file approach (`db/fotocasa-x-d-token.txt`) combined with a periodic Frida/mitmproxy extraction script is the most practical long-term solution.

---

## Implementation Reference

See [lib/provider/fotocasa.js](lib/provider/fotocasa.js) for the complete fredy provider implementation.
