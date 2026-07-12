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
      "Limit": 60,
      "WindowSeconds": 60,
      "PathPrefixes": [
        "/api",
        "/artists"
      ]
    },
    "SuspiciousTraffic": {
      "Enabled": true,
      "Block": true,
      "StatusCode": 400,
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
      ]
    },
    "AccessLog": {
      "Enabled": true,
      "Output": "Logger",
      "FilePath": "logs/access-log-{date}.log"
    },
    "SecurityIssueLog": {
      "Enabled": true,
      "Output": "File",
      "FilePath": "logs/security-issue-log-{date}.log"
    },
    "LogApi": {
      "Enabled": false
    }
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
- writes `RateLimit-*` and `X-RateLimit-*` headers
- returns OPX error response with body `statusCode: "429"` when exceeded

Suspicious traffic guard:

- detects common scanner and attack tokens such as `sqlmap`, `.env`, `.git`, SQL tokens, and script tokens
- stores the matched reason in `HttpContext.Items["OpxSuspiciousReason"]`
- can log only or block request based on `Block`

Authorization guard:

- validates Bearer JWT using ASP.NET Core authentication
- does not only check whether an `Authorization` header exists
- can exclude public path prefixes
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

Security issue log:

- written when suspicious traffic is detected
- default file path is `logs/security-issue-log-{date}.log`
- can write to `Logger`, `File`, or `Both`

Log API:

- disabled by default through `OpxApiProtection:LogApi:Enabled`
- reads access log and security issue log files
- returns OPX response wrapper
- use authentication/authorization or a private network when enabling it

```http
GET /opx/logs/access?date=20260712&take=100
GET /opx/logs/security-issues?date=20260712&take=100
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
OkOrFailAsync 500 concurrent: Passed, 126 ms
RateLimiting 500 concurrent: Passed, 46 ms
SuspiciousTrafficGuard 500 concurrent: Passed, 249 ms
```

These numbers are local smoke-test results, not a guaranteed benchmark for every machine or deployment.

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

Configuration:

```json
{
  "EndpointLog": {
    "Enabled": true,
    "IncludeQueryString": true,
    "IncludeRouteValues": true,
    "IncludeRequestBody": true,
    "IncludeResponseBody": true,
    "IncludeCurl": true,
    "Output": "File",
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

Recommended production value:

```json
"Output": "File"
```

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
