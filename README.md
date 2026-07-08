<!-- Copyright (c) 2026 - opx -->
# Opx.Api.Web

Shared ASP.NET Core web helpers for OPX APIs.

## Endpoint Log

`Opx.Api.Web` provides `UseOpxEndpointLog()` middleware to record executed endpoints.

The log can include:

- method, path, and query string
- route/controller/action
- route values
- authenticated user
- status code
- elapsed time
- request body
- response/output body
- executable `curl` format
- daily file output

## Setup

Add the package:

```xml
<PackageReference Include="Opx.Api.Web" Version="1.0.1" />
```

Register the middleware after `UseRouting()` and before `UseAuthentication()`:

```csharp
app.UseHttpsRedirection();
app.UseRouting();
app.UseOpxEndpointLog();
app.UseAuthentication();
app.UseAuthorization();
```

If the API does not explicitly call `UseRouting()`, add it as shown above so endpoint metadata can be resolved.

## Controller Usage

Inherit from `OpxApiController` to use the OPX response wrapper helpers:

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

When the service returns `AppResult` with `Result = true`, the endpoint writes:

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

When the service returns `AppResult` with `Result = false`, the endpoint automatically writes the fail response:

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

File response:

```csharp
[HttpGet("{id:int}/photo")]
public async Task GetPhoto(int id, CancellationToken cancellationToken)
{
    var photo = await _artistService.GetPhotoAsync(id, cancellationToken);
    await OkContentAsync(photo.Bytes, photo.ContentType, photo.FileName);
}
```

## API Docs

Generate controller endpoint docs when the application starts:

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

## Appsettings

Example configuration:

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

## Output

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

## Daily Log File

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

## Response Body Mode

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

Example binary metadata:

```text
[binary content skipped: contentType=image/png; bytes=12345; sha256=F4A...]
```

## Dynamic API Output

API output does not need to have a fixed DTO or schema.

The middleware records responses dynamically based on `Content-Type`:

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

Example dynamic JSON output:

```text
Output={"result":true,"data":{"Id":1,"Name":"DeadSquad"},"statusCode":"200"}
```

Example array output:

```text
Output={"result":true,"data":[{"Id":1,"Name":"DeadSquad"},{"Id":2,"Name":"Burgerkill"}],"statusCode":"200"}
```

Example binary output:

```text
Output=[binary content skipped: contentType=application/pdf; bytes=251904; sha256=2B7...]
```

Any endpoint can therefore be logged without endpoint-specific mapping.

## Wrapped File Content

If an endpoint must return a file, image, or document while still following the OPX response wrapper, use `ApiContentData`.

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

Controller example:

```csharp
[HttpGet("{id}/photo")]
public async Task GetPhoto(string id)
{
    var bytes = await File.ReadAllBytesAsync("photo.png");
    await OkContentAsync(bytes, "image/png", "photo.png");
}
```

Service example:

```csharp
return Success(ApiContentData.FromBytes(bytes, "application/pdf", "report.pdf"));
```

Clients should decode `data.rawData` from base64 according to `data.contentType`.

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

If you need the logged `curl` command to be directly executable, set:

```json
"MaskSensitiveValues": false
```

Use this only for local debugging because tokens and passwords will be written to log files.

## Example Log

```text
2026-07-08 12:53:43.611 Endpoint executed GET /artists => 200 in 211 ms | Endpoint=Artists.Get | Route=artists | RouteValues=action=Get, controller=Artists | User=opx | Curl=curl -X GET "http://localhost:5141/artists" -H "Authorization: ***" | Output={"result":true,"data":[{"Id":1,"Name":"DeadSquad"},{"Id":2,"Name":"Burgerkill"}],"statusCode":"200"}
```
