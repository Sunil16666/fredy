# Immobiliare.it mobile transport

Investigated 30–31 October 2026. All development remains in the fork; no upstream changes or PR.

## Evidence and choice

The website's Next.js cache contains `real-estate-list` results, but filtered pages and its XHR
endpoint `/api-next/search-list/listings/` were challenged on this connection. Real Chrome,
CloakBrowser, Italian locale and homepage warm-up did not resolve that challenge. Next.js data
routes resolved filters/geography but omitted the listing cache, so HTTP 200 alone was not proof
of a working scraper.

The Android package was acquired from the [APKPure package page](https://apkpure.net/immobiliare-it-indomio/it.immobiliare.android/download).
The installed split set reported version 26.18.0, code 414, package `it.immobiliare.android`.
`apksigner verify` succeeded. Its certificate MD5 was `2d15c1097ab594fd4a993ce196130960`, matching
the distribution listing; certificate SHA-256 was
`32a4e11ffa67b794e6ed853b2274af6882a0d8b94c6ac70892433f8695154824`.
Base APK SHA-256: `e8e6a01772aacffa91eb5d3bc1b9311ed1f5162d6b52bad94a37afb626708bc0`.
These are ordinary shell/JADX observations: the REA Android adapter was unavailable because its
JADX bridge was not configured. Standalone JADX decompiled the client, with failed methods traced
through focused fallbacks and Frida runtime capture. APKs, hooks, cookies and raw captures are
private investigation artifacts, not repository fixtures or runtime dependencies.

## Native requests

Origin: `https://android-imm-v4.ws-app.com`. Calls are GETs:

| Path | Meaning |
| --- | --- |
| `/b2c/v1/resolver/url?url=...` | Website URL to `{type: "search", params: {...}}` |
| `/b2c/v1/properties?...` | `{list, offset, count, totalActive, ...}` |
| `/b2c/v1/properties/<id>` | Single advert, including `description.content` |

Observed native parameters: `c=6737` is Rome, `cat=1` residential, `t=a` rent, `t=v` sale;
`pm/px` are price bounds, `sm/sx` surface bounds, `lm/lx` room bounds. Pagination is `start=<offset>`;
newest first is `of=d&od=d`. The provider uses the portal's resolver rather than copying this table
into a local filter translator. Unsupported structured resolver parameters are refused, not dropped.

Headers: the client's `WSCommand3<Furious>|...` user agent, `Accept-Language`, `X-Currency: EUR`,
`X-Measurement-Unit: meters`, and `immo-id` (an installation UUID). The app sends no bearer token
for anonymous searches. Its DataDome SDK adds a `datadome` cookie and refreshes it from responses.
The cookie belongs to its user agent/IP context; copying an unverified SDK cookie did not unlock
access.

Static trace anchors in the inspected build: `su.a` defines the property API; `bx.m.z1` maps
pagination/sort; `ut.f9` defines newest-first order; `l1.v` maps geography; `c20.h` supplies headers;
`c20.g` persists the installation UUID; `fk0.f1.l` constructs the v4 client; `gf0.a` conditionally
adds account authentication. `BaseApplication.onCreate` constructs the user agent. Class names are
obfuscated build artifacts, not supported interfaces.

## DataDome verification and limits

The official app was challenged too. After an approved verification gesture in the Android
emulator, the app returned real listings. The resulting native requests then worked from Node:
first page and offset 20 both returned twenty adverts, and a later request with a new device UUID
and no imported cookie also succeeded. The website still returned 403. No emulator is needed for
normal Fredy runs after access is available.

This establishes an effective native transport on the verified connection, not a universal
CAPTCHA bypass. A new IP or a later refusal may need another verification. Production code does
not embed an operator's cookie, depend on an APK, solve CAPTCHAs, or treat a challenge as an empty
search. It serializes requests with a 500 ms gap and honors refusal cooldowns/Retry-After.
`immobiliare_session` is persisted using the existing settings store and excluded at the settings
serialization boundary. Detail failures preserve the original search card and its price/hash.

The three-advert search fixture and one detail fixture were captured from the live native API.
Advertiser/contact blocks, tracking data and translation tokens were removed. Refresh with
`yarn test:download-fixtures immobiliare` after access to the API is available.

## Reproducing verification

Try Fredy’s native API first: the independent runner validation below succeeded without an app
verification step. If the native API is refused, the following describes the development workaround.
Use the official Android app on the same network as Fredy, select Italy, and run a property search.
Complete the verification if DataDome asks for one. Retry Fredy after its cooldown; restarting
the process retains that deadline. On the tested connection, no app cookie or account token needed to
be copied into Fredy: the native API then granted its own fresh anonymous sessions. This observed
network/session behavior may change; a different IP must be validated independently.

## Final validation, 31 October 2026

- Production provider, with both emulators stopped: 77 unique Rome rentals, every known price at
  or below €600, all result pages read, and a full description fetched from the detail endpoint.
- Fresh Node process: reused the persisted device identity and read a Milan sale search with
  `px=200000` and `lm=2`; twenty live adverts returned with the sale/price constraints respected.
- Live Fredy provider pipeline test: two assertions passed.
- Full offline regression run: 5,052 passed, 33 skipped, zero failures. Lint, changed-file format
  checks, and `git diff --check` passed. The session is absent from public/admin settings responses.

## Lifecycle review

Live rent, sale, localized, generic-form and empty searches passed. Offline tests exercise cookie
expiry, restart persistence, refusal recovery, pagination bounds and repeated pipeline deduplication.
Both providers use per-request timeouts so a stalled host releases the request queue, and pace concurrent jobs. This
validation includes simulated elapsed time and fresh-process reads, not a multi-day production soak.

## Independent network validation

On 31 October 2026, [this fork-only GitHub Actions run](https://github.com/Sunil16666/fredy/actions/runs/41218427150)
passed on a fresh hosted Ubuntu runner with Node 22.23.4. No browser, emulator, imported cookie or
app verification was used. Its first API request sent no cookie. The API supplied anonymous session
state; a fresh second Node process reused its saved identity and cookie after a sixty-second pause.
The workflow lived on a temporary validation branch, not upstream or the fork’s default branch.

| Environment | Fresh-process rounds | Requests | HTTP results | Identity reused after restart |
| --- | ---: | ---: | --- | --- |
| Local development network, Node 26.0.0 | 3 | 48 | All 200 | Both restarts |
| GitHub-hosted Ubuntu, Node 22.23.4 | 2 | 32 | All 200 | Yes |

Every round read all 76 Rome rentals at or below €600 with unique canonical links and enriched one
advert without changing its price, link or hash. It then concurrently resolved and read the first
page of five independent searches: Milan sale (≤€200,000, ≥2 rooms, ≥40 m²), Turin rent (≤€500,
≥3 rooms), English-localized Bologna sale (≤€80,000), a generic Rome search URL, and a legitimate
empty search. Resolver parameters and all available numeric constraints were checked. The nominal
500 ms request gap measured at least 499 ms, allowing for timer resolution. Full Rome searches took
about 2.1 seconds locally and 2.2 seconds on the hosted runner; each complete round took about eight
seconds. The broad Milan search’s 1,291 total results were not all downloaded.

This materially improves the fresh-deployment evidence: prior app verification was not required on
that independent runner. It does not establish universal IP acceptance, all future app/API versions,
or a multi-day production soak. The local observation lasted about 2 minutes 24 seconds; the hosted
observation lasted about 1 minute 16 seconds.

The focused transport tests also cover HTTP-date `Retry-After`, queued requests after refusal,
Max-Age precedence, invalid cookie replacements, five successive cookie rotations, profile recovery,
and a thirty-second timeout during either headers or body parsing releasing the request lane.
The full offline suite passed: 5,103 tests, 33 skipped. Lint and formatting passed.

To reproduce explicitly, outside routine offline CI:

```sh
node tools/validateImmobiliare.js --output /tmp/immobiliare-report.json --rounds 3 --interval-ms 60000
```

Each round runs the production provider and transport in a new process against a disposable SQLite
database, which is reused across rounds and deleted afterwards. The running installation’s database
is never used. The report contains counts, request paths without advert IDs, status codes, timings
and booleans; cookies, device IDs, challenge bodies and full listing payloads are not written to it.
A refusal stops further rounds rather than creating another identity to retry. Internal worker mode accepts only marked disposable validation directories.
