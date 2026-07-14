<!-- Copyright (c) 2026 - opx -->
# Opx.Api.Web

Shared ASP.NET Core web helpers for OPX APIs.

`Opx.Api.Web` provides:

- OPX response wrapper: `result`, `data`, `statusCode`
- `OpxApiController` helper methods: `OkAsync`, `OkOrFailAsync`, `FailAsync`, `OkContentAsync`
- automatic `AppResult` success/error mapping from service to endpoint response
- uncaught status-code response wrapper for 400, 401, 403, 404, 405, 415, 500, and other status codes
- endpoint execution logging with curl, request body, response body, masking, and file output
- generated endpoint docs in JSON and Markdown
- wrapped binary/file content through `ApiContentData`
- JWT bearer setup helper
- optional API protection middleware for security headers, rate limiting, suspicious traffic, authorization guard, and access log

## Install

Add the package:

```xml
<PackageReference Include="Opx.Api.Web" Version="1.0.5" />
```

If the application uses `AppService` and `AppResult`, also reference:

```xml
<PackageReference Include="Opx.Api.Infrastructure" Version="1.0.3" />
```

## Program Setup

Register controllers and OPX web API behavior:

```csharp
builder.Services.AddControllers();
builder.Services.UseOpxWebApi();
```

Register all OPX API web services with configuration:

```csharp
builder.Services.AddOpxApiWeb(builder.Configuration);
```

Enable generated endpoint docs:

```csharp
builder.Services.UseOpxWebApi(options => options.GenerateDocs());
```

Recommended middleware order:

```csharp
app.UseHttpsRedirection();
app.UseRouting();
app.UseOpxApiProtection();
app.UseOpxEndpointLog();
app.UseAuthentication();
app.UseAuthorization();
app.UseOpxWebApiHandler();
app.UseOpxWebApiStatusCodePages();
app.MapControllers();
```

If the API does not explicitly call `UseRouting()`, add it so endpoint metadata can be resolved by the endpoint logger.

## API Protection

`UseOpxApiProtection()` enables the protection middlewares in this order:

```csharp
app.UseOpxSecurityHeaders();
app.UseOpxRateLimiting();
app.UseOpxSuspiciousTrafficGuard();
app.UseOpxAuthorizationGuard();
app.UseOpxAccessLog();
```

Shortcut:

```csharp
app.UseOpxApiProtection();
```

Fast core shortcut:

```csharp
app.UseOpxApiProtectionFast();
```

`UseOpxApiProtectionFast()` composes security headers, rate limiting, suspicious traffic guard, and authorization guard behind one middleware registration. Keep access/endpoint logging separate when request logging is required.

Default behavior:

- security headers are enabled by default
- rate limiting is disabled until `OpxApiProtection:RateLimiting:Enabled` is `true`
- suspicious traffic guard is disabled until `OpxApiProtection:SuspiciousTraffic:Enabled` is `true`
- authorization guard is disabled until `OpxApiProtection:AuthorizationGuard:Enabled` is `true`
- access log is disabled until `OpxApiProtection:AccessLog:Enabled` is `true`

Configuration:

```json
{
  "OpxApiProtection": {
    "SecurityHeaders": {
      "Enabled": true,
      "ReferrerPolicy": "no-referrer",
      "FrameOptions": "DENY"
    },
    "RateLimiting": {
      "Enabled": true,
      "Algorithm": "FixedWindow",
      "Limit": 60,
      "WindowSeconds": 60,
      "CleanupIntervalSeconds": 60,
      "WriteHeadersOnSuccess": false,
      "PathPrefixes": [
        "/api",
        "/artists"
      ]
    },
    "SuspiciousTraffic": {
      "Enabled": true,
      "Block": true,
      "StatusCode": 400,
      "BlockedResponseMode": "WrappedFast",
      "ResponseStatusCodes": [],
      "SlowRequestMilliseconds": 0,
      "MaxPathLength": 0,
      "MaxQueryLength": 0,
      "RegexTimeoutMilliseconds": 100,
      "ExcludedPathPrefixes": [
        "/health",
        "/openapi",
        "/swagger",
        "/favicon.ico",
        "/assets",
        "/static"
      ],
      "AllowedIpAddresses": [
        "127.0.0.1",
        "10.0.0.0/8",
        "192.168.1.0/24"
      ],
      "DeniedIpAddresses": [],
      "Patterns": [
        "sqlmap",
        ".env",
        ".git",
        "union select",
        "information_schema",
        "<script",
        "../",
        "xp_cmdshell",
        "or 1=1",
        "drop table"
      ]
    },
    "AuthorizationGuard": {
      "Enabled": false,
      "ExcludedPathPrefixes": [
        "/health",
        "/swagger",
        "/openapi"
      ],
      "WhitelistedPathPrefixes": [
        "/public",
        "/callback"
      ]
    },
    "AccessLog": {
      "Enabled": true,
      "Output": "Logger",
      "FilePath": "logs/access-log-{date}.log",
      "QueueCapacity": 8192,
      "BatchSize": 100,
      "FlushIntervalMilliseconds": 250
    },
    "SecurityIssueLog": {
      "Enabled": true,
      "Output": "File",
      "FilePath": "logs/security-issue-log-{date}.log",
      "Format": "JsonLines",
      "SampleRate": 10,
      "MaxPathLength": 512,
      "MaxQueryLength": 512,
      "MaxHeaderLength": 512,
      "MaxReasonLength": 256,
      "QueueCapacity": 8192,
      "BatchSize": 100,
      "FlushIntervalMilliseconds": 250
    },
    "LogApi": {
      "Enabled": false,
      "RequireAuthorization": true,
      "RequiredRole": "Admin",
      "RequiredPolicy": "OpxLogViewer"
    },
    "MetricsApi": {
      "Enabled": false,
      "RequireAuthorization": true,
      "RequiredRole": "Admin",
      "RequiredPolicy": "OpxLogViewer"
    },
    "Validation": {
      "FailFast": false
    },
    "Policies": [
      {
        "PathPrefix": "/public",
        "SkipAuthorization": true,
        "SkipRateLimiting": true,
        "SkipSuspiciousTraffic": false
      },
      {
        "PathPrefix": "/api/heavy",
        "RateLimit": 500,
        "RateLimitWindowSeconds": 60
      }
    ]
  },
  "OpxEndpointProxy": {
    "Enabled": true,
    "Mode": "Rewrite",
    "RouteMapPath": "App_Data/opx-endpoint-routes.json",
    "AllowedAliasPrefixes": [
      "/gw",
      "/_sys"
    ],
    "FailOnConflict": true
  }
}
```

Security headers:

- `X-Content-Type-Options: nosniff`
- `Referrer-Policy`
- `X-Frame-Options`
- removes `Server`
- removes `X-Powered-By`

Rate limiting:

- limits by client IP and path prefix
- supports `SlidingWindow` and faster `FixedWindow` algorithms
- caches rate-limit settings until configuration reload
- cleans expired in-memory buckets based on `CleanupIntervalSeconds`
- can skip `RateLimit-*` headers for allowed requests with `WriteHeadersOnSuccess: false`
- writes `RateLimit-*` and `X-RateLimit-*` headers
- returns OPX error response with body `statusCode: "429"` when exceeded

Suspicious traffic guard:

- detects common scanner and attack tokens such as `sqlmap`, `.env`, `.git`, SQL tokens, and script tokens
- supports IP/CIDR allowlist and denylist through `AllowedIpAddresses` and `DeniedIpAddresses`
- stores the matched reason in `HttpContext.Items["OpxSuspiciousReason"]`
- can log only or block request based on `Block`
- can monitor selected downstream response codes with `ResponseStatusCodes`
- can flag slow downstream responses with `SlowRequestMilliseconds`
- can flag oversized paths and queries with `MaxPathLength` and `MaxQueryLength`; `0` disables each limit
- caches pattern/regex settings until configuration reload
- compiles regex patterns and applies a regex timeout
- skips excluded path prefixes before scanning
- supports `BlockedResponseMode: "Minimal"` for the lightest blocked responses
- uses `BlockedResponseMode: "WrappedFast"` by default for cached OPX-style wrapped blocked responses
- supports `SecurityIssueLog:SampleRate` to reduce high-volume attack log writes
- writes file security issue logs through a background batch writer when registered by `AddOpxApiWeb`
- sanitizes CR/LF/TAB in log fields and truncates long path, query, header, and reason values
- drains queued security issue logs during graceful shutdown
- supports `QueueCapacity`, `BatchSize`, and `FlushIntervalMilliseconds` for file log batching
- supports `SecurityIssueLog:Format: "GatewayText"` for the gateway access-log format used by the suspicious HTML report generator

Authorization guard:

- validates Bearer JWT using ASP.NET Core authentication
- does not only check whether an `Authorization` header exists
- caches enabled/excluded/whitelisted path settings until configuration reload
- can exclude public path prefixes
- can whitelist public URL prefixes through `WhitelistedPathPrefixes`
- `[AllowAnonymous]` endpoints are skipped

Use `[Authorize]` on controllers/actions for the main authorization contract. `AuthorizationGuard` is intended as a quick global protection layer.

Access log:

- request path
- status
- elapsed time
- IP
- host
- user-agent
- suspicious reason
- file output is written through an async batch writer when `Output` is `File` or `Both`

Security issue log:

- written when suspicious traffic is detected
- default file path is `logs/security-issue-log-{date}.log`
- can write to `Logger`, `File`, or `Both`
- supports `SampleRate` plus `MaxPathLength`, `MaxQueryLength`, `MaxHeaderLength`, and `MaxReasonLength`
- supports `QueueCapacity`, `BatchSize`, and `FlushIntervalMilliseconds`
- tracks dropped entries when the queue is full and writes a warning summary on shutdown
- supports `Format: "JsonLines"` for structured file log output

Log API:

- disabled by default through `OpxApiProtection:LogApi:Enabled`
- reads access log and security issue log files
- can require an authenticated user through `OpxApiProtection:LogApi:RequireAuthorization`
- can require a role through `OpxApiProtection:LogApi:RequiredRole`
- can require an authorization policy through `OpxApiProtection:LogApi:RequiredPolicy`

Metrics and health API:

- disabled by default through `OpxApiProtection:MetricsApi:Enabled`
- exposes protection counters at `GET /opx/protection/metrics`
- exposes protection health/config state at `GET /opx/protection/health`
- supports the same `RequireAuthorization`, `RequiredRole`, and `RequiredPolicy` style as Log API

Protection policies:

- configure per-path behavior through `OpxApiProtection:Policies`
- can skip authorization, skip rate limiting, skip suspicious traffic scan, or override rate-limit settings per path prefix

Configuration validation:

- validates IP/CIDR lists, log format/output, blocked response mode, regex patterns, and policy values during startup
- set `OpxApiProtection:Validation:FailFast` to `true` to stop startup when config is invalid
- returns OPX response wrapper
- use authentication/authorization or a private network when enabling it

```http
GET /opx/logs/access?date=20260712&take=100
GET /opx/logs/security-issues?date=20260712&take=100
```

Endpoint proxy:

- disabled by default through `OpxEndpointProxy:Enabled`
- route map can be kept outside `appsettings.json` through `RouteMapPath`
- legacy `OpxApiProtection:EndpointProxy` config is still supported for backward compatibility
- creates simple local alias routes from `EndpointProxy:Routes`
- supports route templates such as `{id}` and constrained target routes such as `{id:int}`
- supports `Redirect` and `Rewrite` mode
- supports global HTTP methods through `EndpointProxy:Methods`
- keeps query string when redirecting or rewriting to the target path
- can require an authenticated user with `RequireAuthorization`
- can require an API key with `ApiKey` and `ApiKeyHeaderName`
- accepts only local paths that start with `/`
- validates duplicate aliases, allowed alias prefixes, and existing endpoint route conflicts when `FailOnConflict` is `true`

```http
GET /_sys/audit/a1?take=10
```

With `Mode: "Rewrite"`, the request is handled by the target endpoint without returning a `Location` header to the client.
Rewrite target endpoint lookup is cached after the first request for each target path.
Rewrite target endpoint lookup is cached per HTTP method and target path.
Rewrite mode enforces authorization metadata on the target endpoint before invoking it.
API key comparison uses fixed-time hashed comparison.

Route map file:

```json
{
  "Routes": [
    {
      "Enabled": true,
      "Alias": "/_sys/audit/a1",
      "Target": "/opx/logs/access",
      "Methods": [ "GET" ]
    },
    {
      "Enabled": true,
      "Alias": "/gw/music/artists/{id}",
      "Target": "/api/artists/{id}",
      "Methods": [ "GET" ]
    }
  ]
}
```

Gateway alias for controller routes:

```json
{
  "OpxEndpointProxy": {
    "Enabled": true,
    "Mode": "Rewrite",
    "RouteMapPath": "App_Data/opx-endpoint-routes.json",
    "AllowedAliasPrefixes": [ "/gw", "/_sys" ],
    "FailOnConflict": true
  }
}
```

Example requests:

```http
GET /gw/music/artists
GET /gw/music/artists/1
GET /gw/music/artists/with-albums
```

Enable proxy API key:

```json
{
  "OpxEndpointProxy": {
    "Enabled": true,
    "Mode": "Rewrite",
    "RouteMapPath": "App_Data/opx-endpoint-routes.json",
    "ApiKeyHeaderName": "X-Opx-Proxy-Key",
    "ApiKey": "change-this-secret"
  }
}
```

Request with API key:

```http
GET /_sys/audit/a1?take=10
X-Opx-Proxy-Key: change-this-secret
```

Enable authenticated user/JWT guard:

```json
{
  "OpxEndpointProxy": {
    "Enabled": true,
    "Mode": "Rewrite",
    "RouteMapPath": "App_Data/opx-endpoint-routes.json",
    "RequireAuthorization": true
  }
}
```

Example output:

```json
{
  "result": true,
  "data": {
    "FilePath": "logs/access-log-20260712.log",
    "Date": "20260712",
    "Lines": [
      "2026-07-12 17:57:58.123 Access GET /artists => 200 in 12 ms | IP=127.0.0.1 | Host=localhost:5141 | UserAgent=curl | Suspicious=-"
    ]
  },
  "statusCode": "200"
}
```

## Benchmark Smoke Test

These smoke tests run in the NUnit test project and are intended to catch obvious performance regressions in core response/protection paths.

Command:

```powershell
dotnet test .\api-web\test\Opx.Api.Web.Tests.csproj --filter "FullyQualifiedName~FiveHundredConcurrentRequests" --no-build --verbosity normal
```

Test machine:

| Spec | Value |
| --- | --- |
| Device | ASUS Vivobook 14 X1404VAP_A1404VA |
| CPU | Intel(R) Core(TM) 7 150U |
| Cores / logical processors | 10 / 12 |
| Max clock | 1800 MHz |
| RAM | 25.37 GB |
| OS | Microsoft Windows 11 Home Single Language 64-bit, version 10.0.26200 |
| .NET SDK | 10.0.301 |

Result:

```text
OkOrFailAsync 500 concurrent: Passed, 131 ms
AuthorizationGuard whitelisted 5000 concurrent: Passed, 91 ms
EndpointLogWriter 5000 file logs: Passed, 201 ms
RateLimiting 500 concurrent: Passed, 156 ms
RateLimiting policy-skipped 5000 concurrent: Passed, 33 ms
SecurityIssueLogWriter 5000 file logs: Passed, 138 ms
SuspiciousTrafficGuard clean 500 concurrent: Passed, 58 ms
SuspiciousTrafficGuard clean 5000 concurrent: Passed, 39 ms
SuspiciousTrafficGuard default wrapped-fast blocked 500 concurrent: Passed, 599 ms
SuspiciousTrafficGuard minimal sampled blocked 500 concurrent: Passed, 105 ms
SuspiciousTrafficGuard wrapped-fast sampled blocked 500 concurrent: Passed, 75 ms
```

These numbers are local smoke-test results, not a guaranteed benchmark for every machine or deployment.

## BenchmarkDotNet

Run focused proxy benchmarks:

```powershell
dotnet run -c Release --project .\api-web\benchmark\Opx.Api.Web.Benchmarks\Opx.Api.Web.Benchmarks.csproj
```

Run only middleware benchmarks:

```powershell
dotnet run -c Release --project .\api-web\benchmark\Opx.Api.Web.Benchmarks\Opx.Api.Web.Benchmarks.csproj --filter "*OpxMiddlewareBenchmarks*"
```

Current benchmarks:

- endpoint proxy redirect
- endpoint proxy rewrite
- direct target endpoint
- authorization guard whitelisted request
- fixed-window rate limit allowed request
- suspicious traffic clean request

Latest middleware BenchmarkDotNet result:

```text
AuthorizationWhitelisted:    Mean 649.6 ns, Allocated 1.13 KB
RateLimitFixedWindowAllowed: Mean 2.319 us, Allocated 3.41 KB
SuspiciousClean:             Mean 956.1 ns, Allocated 1.23 KB
```

## Response Contract

Successful response:

```json
{
  "result": true,
  "data": {
    "Id": 1,
    "Name": "DeadSquad"
  },
  "statusCode": "200"
}
```

Array response:

```json
{
  "result": true,
  "data": [
    {
      "Id": 1,
      "Name": "DeadSquad"
    },
    {
      "Id": 2,
      "Name": "Burgerkill"
    }
  ],
  "statusCode": "200"
}
```

Error response:

```json
{
  "result": false,
  "data": {
    "message": "Not found",
    "id": "Get",
    "objectName": "Artists"
  },
  "statusCode": "404"
}
```

HTTP response status is kept as `200` for application-level responses. The original logical status is written to body field `statusCode`.

## Controller Usage

Inherit from `OpxApiController` to use the OPX response helpers:

```csharp
[ApiController]
[Route("artists")]
public class ArtistsController : OpxApiController
{
    private readonly ArtistService _artistService;

    public ArtistsController(ArtistService artistService)
    {
        _artistService = artistService;
    }

    [HttpGet]
    public async Task Get(CancellationToken cancellationToken)
    {
        await OkAsync(_artistService.GetArtistsAsync(cancellationToken));
    }

    [HttpGet("{id:int}")]
    public async Task GetById(int id, CancellationToken cancellationToken)
    {
        await OkAsync(_artistService.GetArtistAsync(id, cancellationToken));
    }
}
```

`OkAsync(Task<AppResult>)` automatically calls success or fail behavior:

- `AppResult.Result = true` writes `result: true` and `data`
- `AppResult.Result = false` writes `result: false`, error data, and body `statusCode`
- `AppResult.ValidationErrorSource` maps to body `statusCode: "400"`
- `AppResult.ExceptionErrorSource` maps to body `statusCode: "500"`

## Service Usage

Use `AppService.ExecuteAsync` to wrap service code into `AppResult`.

```csharp
public sealed class ArtistService : AppService
{
    private readonly DbContext _dbContext;

    public ArtistService(DbContext dbContext)
    {
        _dbContext = dbContext;
    }

    public Task<AppResult> GetArtistsAsync(CancellationToken cancellationToken)
    {
        return ExecuteAsync(async token =>
        {
            token.ThrowIfCancellationRequested();

            var artists = await _dbContext.Artist
                .OrderBy(artist => artist.Name)
                .ToListAsync(token);

            return Success(artists);
        }, cancellationToken);
    }
}
```

Validation error:

```csharp
return ValidationError("Artist is required");
```

Exception error:

```csharp
return ExceptionError(exception);
```

Custom success data:

```csharp
return Success(new { Id = 1, Name = "DeadSquad" });
```

## Cancellation Token

When the token is cancelled before main code runs, `ExecuteAsync` returns:

```csharp
ValidationError("Request cancelled")
```

Endpoint output:

```json
{
  "result": false,
  "data": {
    "message": "Request cancelled",
    "id": "Get",
    "objectName": "Artists"
  },
  "statusCode": "400"
}
```

Recommended pattern:

```csharp
return await ExecuteAsync(async token =>
{
    token.ThrowIfCancellationRequested();

    var data = await query.ToListAsync(token);
    return Success(data);
}, cancellationToken);
```

You do not need to call `token.ThrowIfCancellationRequested()` on every line. Check once before main work, pass the token to async calls, and add manual checks around long loops, batch processing, or important side effects.

## Status Code Wrapper

`UseOpxWebApiHandler()` and `UseOpxWebApiStatusCodePages()` convert unhandled status pages into OPX response format.

Example not found response:

```json
{
  "result": false,
  "data": {
    "message": "Not found",
    "id": "StatusCodePages",
    "objectName": "/missing-page"
  },
  "statusCode": "404"
}
```

Handled status messages:

| Status | Message |
| --- | --- |
| `400` | `Bad request` |
| `401` | `Unauthorized` |
| `403` | `Forbidden` |
| `404` | `Not found` |
| `405` | `HTTP Method not allowed` |
| `415` | `Unsupported Media Type` |
| `500` | `Internal server error` |
| `503` | `Unavailable` |

## API Docs

Generate controller endpoint docs automatically when the application starts:

```csharp
builder.Services.AddControllers();
builder.Services.UseOpxWebApi(options => options.GenerateDocs());
```

Default output:

```text
<project-root>/docs/opx-api-docs.json
<project-root>/docs/opx-api-docs.md
```

Relative output paths are resolved from the application project root, not from `bin/Debug` or `bin/Release`.

Custom output:

```csharp
builder.Services.UseOpxWebApi(options => options.GenerateDocs(
    outputDirectory: "docs/api",
    fileName: "endpoint-docs"));
```

Generate only JSON:

```csharp
builder.Services.UseOpxWebApi(options => options.GenerateDocs(
    outputDirectory: "docs",
    fileName: "opx-api-docs",
    json: true,
    markdown: false));
```

Generate docs manually after controllers are mapped:

```csharp
var app = builder.Build();

app.MapControllers();

var docs = app.GenerateOpxApiDocs(options =>
{
    options.OutputDirectory = "docs";
    options.FileName = "opx-api-docs";
    options.GenerateJson = true;
    options.GenerateMarkdown = true;
});
```

The returned `docs` object contains endpoint, parameter, and result metadata:

```csharp
foreach (var endpoint in docs.Endpoints)
{
    Console.WriteLine($"{endpoint.Method} {endpoint.Route}");

    foreach (var parameter in endpoint.Parameters)
    {
        Console.WriteLine($"{parameter.Name} {parameter.Source} {parameter.Type}");
    }

    foreach (var output in endpoint.Output)
    {
        Console.WriteLine($"{output.StatusCode} {output.Type}");
    }
}
```

Generated docs include:

- controller
- action
- HTTP method
- route
- parameter name, source, type, and required flag
- complex parameter properties
- output type and status code from `ProducesResponseType`

## Endpoint Log

`UseOpxEndpointLog()` records executed endpoints.

The log can include:

- method, path, and query string
- route/controller/action
- route values
- authenticated user
- status code
- elapsed time
- request body
- response/output body
- executable curl format
- daily file output

For better throughput, keep `IncludeRequestBody` and `IncludeResponseBody` disabled unless debugging a specific endpoint. When response body capture is disabled, the middleware does not replace or buffer the response stream.

Configuration:

```json
{
  "EndpointLog": {
    "Enabled": true,
    "IncludeQueryString": true,
    "IncludeRouteValues": true,
    "IncludeRequestBody": false,
    "IncludeResponseBody": false,
    "IncludeCurl": true,
    "Output": "Logger",
    "FilePath": "logs/endpoint-log-{date}.log",
    "ResponseBodyMode": "Auto",
    "TextResponseContentTypes": [
      "application/json",
      "application/problem+json",
      "application/xml",
      "text/"
    ],
    "MaskSensitiveValues": true,
    "MaxBodyLength": 4000,
    "SensitiveKeys": [
      "password",
      "token",
      "secret",
      "authorization"
    ]
  }
}
```

`Output` controls where endpoint logs are written:

| Value | Description |
| --- | --- |
| `File` | Write only to file |
| `Logger` | Write to ASP.NET Core logger |
| `Both` | Write to both file and logger |

Recommended high-throughput value:

```json
"Output": "Logger"
```

Use `File` or `Both` only when the file sink is acceptable for the traffic level.

Use `{date}` in `FilePath` to create one file per day:

```json
"FilePath": "logs/endpoint-log-{date}.log"
```

Example files:

```text
logs/endpoint-log-20260708.log
logs/endpoint-log-20260709.log
```

If `FilePath` is relative, it is resolved from the application `ContentRootPath`.

## Response Body Logging

`ResponseBodyMode` controls how response bodies are recorded.

| Value | Description |
| --- | --- |
| `Auto` | Log JSON/text as text, log binary as metadata |
| `Text` | Force response body to be read as UTF-8 text |
| `Base64` | Write response body as base64 |
| `Skip` / `None` | Do not write the body, write metadata only |

Recommended value:

```json
"ResponseBodyMode": "Auto"
```

With `Auto`, responses such as `application/json` are logged as body text, while binary files such as images, PDFs, or octet-streams are not written directly into the log.

Response logging behavior:

| Response Type | Logging Behavior |
| --- | --- |
| `application/json` | Write the JSON body as-is |
| `application/problem+json` | Write the JSON error body as-is |
| `application/xml` | Write the XML body as text |
| `text/*` | Write the text body as-is |
| `image/*` | Skip raw body and write metadata only |
| `application/pdf` | Skip raw body and write metadata only |
| `application/octet-stream` | Skip raw body and write metadata only |
| file download | Skip raw body and write metadata only |

Example JSON output:

```text
Output={"result":true,"data":{"Id":1,"Name":"DeadSquad"},"statusCode":"200"}
```

Example array output:

```text
Output={"result":true,"data":[{"Id":1,"Name":"DeadSquad"},{"Id":2,"Name":"Burgerkill"}],"statusCode":"200"}
```

Example binary metadata:

```text
Output=[binary content skipped: contentType=application/pdf; bytes=251904; sha256=2B7...]
```

## Sensitive Data Masking

When `MaskSensitiveValues` is enabled, values for configured sensitive keys are masked:

```json
"SensitiveKeys": [
  "password",
  "token",
  "secret",
  "authorization"
]
```

Example:

```text
Curl=curl -X POST "http://localhost:5141/authentication/authenticate" -H "Content-Type: application/json" --data "{\"UserId\":\"opx\",\"Password\":\"***\"}"
```

If you need the logged curl command to be directly executable, set:

```json
"MaskSensitiveValues": false
```

Use this only for local debugging because tokens and passwords will be written to log files.

## File Content Response

If an endpoint must return a file, image, or document while still following the OPX response wrapper, use `OkContentAsync` or `ApiContentData`.

Controller example:

```csharp
[HttpGet("{id:int}/photo")]
public async Task GetPhoto(int id, CancellationToken cancellationToken)
{
    var photo = await _artistService.GetPhotoAsync(id, cancellationToken);
    await OkContentAsync(photo.Bytes, photo.ContentType, photo.FileName);
}
```

Service example:

```csharp
return Success(ApiContentData.FromBytes(bytes, "application/pdf", "report.pdf"));
```

Response format:

```json
{
  "result": true,
  "data": {
    "type": "file",
    "contentType": "image/png",
    "fileName": "photo.png",
    "length": 12345,
    "encoding": "base64",
    "rawData": "iVBORw0KGgoAAA..."
  },
  "statusCode": "200"
}
```

Fields:

| Field | Description |
| --- | --- |
| `type` | Data marker, defaults to `file` |
| `contentType` | MIME type such as `image/png`, `application/pdf`, or `application/octet-stream` |
| `fileName` | Optional file name |
| `length` | Raw data length in bytes |
| `encoding` | Payload encoding, currently `base64` |
| `rawData` | Raw bytes serialized by JSON as base64 |

Clients should decode `data.rawData` from base64 according to `data.contentType`.

## JWT Bearer Helper

Register JWT bearer authentication:

```csharp
builder.Services.UseOpxJwtBearerTokenAuth(new JwtTokenValidationSetting
{
    SecretKey = "your-secret-key",
    Issuer = "opx",
    Audience = "opx-api",
    ExpirationSeconds = 3600,
    Algorithm = SecurityAlgorithms.HmacSha256
});
```

Then enable authentication middleware:

```csharp
app.UseAuthentication();
app.UseAuthorization();
```

## Example Endpoint Log

```text
2026-07-08 12:53:43.611 Endpoint executed GET /artists => 200 in 211 ms | Endpoint=Artists.Get | Route=artists | RouteValues=action=Get, controller=Artists | User=opx | Curl=curl -X GET "http://localhost:5141/artists" -H "Authorization: ***" | Output={"result":true,"data":[{"Id":1,"Name":"DeadSquad"},{"Id":2,"Name":"Burgerkill"}],"statusCode":"200"}
```
