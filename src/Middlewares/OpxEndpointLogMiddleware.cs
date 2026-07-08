using System.Diagnostics;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Microsoft.AspNetCore.Mvc.Controllers;

namespace Opx.Api.Web.Middlewares;

public sealed class OpxEndpointLogMiddleware
{
    private readonly RequestDelegate _next;
    private readonly ILogger<OpxEndpointLogMiddleware> _logger;
    private readonly IConfiguration _configuration;
    private readonly IWebHostEnvironment _environment;

    public OpxEndpointLogMiddleware(
        RequestDelegate next,
        ILogger<OpxEndpointLogMiddleware> logger,
        IConfiguration configuration,
        IWebHostEnvironment environment)
    {
        _next = next;
        _logger = logger;
        _configuration = configuration;
        _environment = environment;
    }

    public async Task InvokeAsync(HttpContext context)
    {
        if (!_configuration.GetValue<bool>("EndpointLog:Enabled"))
        {
            await _next(context);
            return;
        }

        var requestBody = await ReadRequestBodyAsync(context);
        var originalResponseBody = context.Response.Body;
        await using var responseBody = new MemoryStream();
        if (_configuration.GetValue<bool>("EndpointLog:IncludeResponseBody"))
        {
            context.Response.Body = responseBody;
        }

        var stopwatch = Stopwatch.StartNew();
        Exception? exception = null;

        try
        {
            await _next(context);
        }
        catch (Exception ex)
        {
            exception = ex;
            throw;
        }
        finally
        {
            stopwatch.Stop();
            var responseText = await ReadResponseBodyAsync(context, responseBody, originalResponseBody);
            WriteLog(context, stopwatch.ElapsedMilliseconds, requestBody, responseText, exception);
        }
    }

    private void WriteLog(
        HttpContext context,
        long elapsedMilliseconds,
        string? requestBody,
        string? responseBody,
        Exception? exception)
    {
        var endpoint = context.GetEndpoint();
        var action = endpoint?.Metadata.GetMetadata<ControllerActionDescriptor>();
        var endpointName = action is null
            ? endpoint?.DisplayName ?? "-"
            : $"{action.ControllerName}.{action.ActionName}";
        var route = action?.AttributeRouteInfo?.Template ?? endpoint?.DisplayName ?? "-";
        var user = context.User?.Identity?.IsAuthenticated == true
            ? context.User.Identity.Name ?? context.User.FindFirst("uid")?.Value ?? "-"
            : "-";
        var path = GetPath(context);
        var routeValues = GetRouteValues(context);
        var curl = BuildCurl(context, requestBody);
        var message = exception is null
            ? $"Endpoint executed {context.Request.Method} {path} => {context.Response.StatusCode} in {elapsedMilliseconds} ms | Endpoint={endpointName} | Route={route} | RouteValues={routeValues} | User={user} | Curl={curl} | Output={responseBody ?? "-"}"
            : $"Endpoint failed {context.Request.Method} {path} => {context.Response.StatusCode} in {elapsedMilliseconds} ms | Endpoint={endpointName} | Route={route} | RouteValues={routeValues} | User={user} | Curl={curl} | Output={responseBody ?? "-"} | Error={exception.Message}";

        if (UseLoggerOutput())
        {
            if (exception is null)
            {
                _logger.LogInformation("{Message}", message);
            }
            else
            {
                _logger.LogError(exception, "{Message}", message);
            }
        }

        WriteFileLog(message);
    }

    private string GetPath(HttpContext context)
    {
        var includeQueryString = _configuration.GetValue("EndpointLog:IncludeQueryString", true);
        return includeQueryString
            ? $"{context.Request.Path}{context.Request.QueryString}"
            : context.Request.Path.ToString();
    }

    private string GetRouteValues(HttpContext context)
    {
        if (!_configuration.GetValue("EndpointLog:IncludeRouteValues", true))
        {
            return "-";
        }

        var values = context.Request.RouteValues
            .Where(value => value.Value is not null)
            .Select(value => $"{value.Key}={MaskIfSensitive(value.Key, value.Value?.ToString() ?? string.Empty)}");

        var result = string.Join(", ", values);
        return string.IsNullOrWhiteSpace(result) ? "-" : result;
    }

    private async Task<string?> ReadRequestBodyAsync(HttpContext context)
    {
        if (!_configuration.GetValue<bool>("EndpointLog:IncludeRequestBody"))
        {
            return null;
        }

        if (context.Request.ContentLength is null or 0 || !context.Request.Body.CanRead)
        {
            return null;
        }

        context.Request.EnableBuffering();
        using var reader = new StreamReader(
            context.Request.Body,
            Encoding.UTF8,
            detectEncodingFromByteOrderMarks: false,
            bufferSize: 1024,
            leaveOpen: true);

        var body = await reader.ReadToEndAsync();
        context.Request.Body.Position = 0;
        return LimitText(MaskSensitiveJson(body));
    }

    private async Task<string?> ReadResponseBodyAsync(
        HttpContext context,
        MemoryStream responseBody,
        Stream originalResponseBody)
    {
        if (!_configuration.GetValue<bool>("EndpointLog:IncludeResponseBody"))
        {
            return null;
        }

        context.Response.Body = originalResponseBody;
        responseBody.Position = 0;
        var bytes = responseBody.ToArray();
        await responseBody.CopyToAsync(originalResponseBody);
        return FormatResponseBody(context, bytes);
    }

    private string BuildCurl(HttpContext context, string? requestBody)
    {
        if (!_configuration.GetValue("EndpointLog:IncludeCurl", true))
        {
            return "-";
        }

        var url = $"{context.Request.Scheme}://{context.Request.Host}{context.Request.Path}{context.Request.QueryString}";
        var command = new StringBuilder();
        command.Append("curl -X ");
        command.Append(context.Request.Method);
        command.Append(" \"");
        command.Append(url);
        command.Append('"');

        if (!string.IsNullOrWhiteSpace(context.Request.ContentType))
        {
            command.Append(" -H \"Content-Type: ");
            command.Append(context.Request.ContentType);
            command.Append('"');
        }

        if (context.Request.Headers.Authorization.Count > 0)
        {
            command.Append(" -H \"Authorization: ");
            command.Append(MaskIfSensitive("Authorization", context.Request.Headers.Authorization.ToString()));
            command.Append('"');
        }

        if (!string.IsNullOrWhiteSpace(requestBody))
        {
            command.Append(" --data ");
            command.Append('"');
            command.Append(EscapeCurlValue(requestBody));
            command.Append('"');
        }

        return command.ToString();
    }

    private string MaskSensitiveJson(string value)
    {
        if (!_configuration.GetValue("EndpointLog:MaskSensitiveValues", true))
        {
            return value;
        }

        var sensitiveKeys = GetSensitiveKeys();
        var result = value;
        foreach (var key in sensitiveKeys)
        {
            result = System.Text.RegularExpressions.Regex.Replace(
                result,
                $"(\"{System.Text.RegularExpressions.Regex.Escape(key)}\"\\s*:\\s*\")([^\"]*)(\")",
                "$1***$3",
                System.Text.RegularExpressions.RegexOptions.IgnoreCase);
        }

        return result;
    }

    private string MaskIfSensitive(string key, string value)
    {
        if (!_configuration.GetValue("EndpointLog:MaskSensitiveValues", true))
        {
            return value;
        }

        return GetSensitiveKeys().Any(item => key.Contains(item, StringComparison.OrdinalIgnoreCase))
            ? "***"
            : value;
    }

    private string[] GetSensitiveKeys()
    {
        return _configuration
            .GetSection("EndpointLog:SensitiveKeys")
            .Get<string[]>()
            ?? ["password", "token", "secret", "authorization"];
    }

    private string LimitText(string value)
    {
        var maxLength = _configuration.GetValue("EndpointLog:MaxBodyLength", 4000);
        return value.Length <= maxLength
            ? value
            : string.Concat(value.AsSpan(0, maxLength), "...[truncated]");
    }

    private string FormatResponseBody(HttpContext context, byte[] bytes)
    {
        if (bytes.Length == 0)
        {
            return string.Empty;
        }

        var contentType = context.Response.ContentType ?? string.Empty;
        var responseBodyMode = _configuration.GetValue("EndpointLog:ResponseBodyMode", "Auto");

        if (responseBodyMode.Equals("None", StringComparison.OrdinalIgnoreCase)
            || responseBodyMode.Equals("Skip", StringComparison.OrdinalIgnoreCase))
        {
            return GetBodyMetadata(contentType, bytes);
        }

        if (responseBodyMode.Equals("Base64", StringComparison.OrdinalIgnoreCase))
        {
            return LimitText(Convert.ToBase64String(bytes));
        }

        if (responseBodyMode.Equals("Text", StringComparison.OrdinalIgnoreCase)
            || IsTextResponse(contentType))
        {
            var text = Encoding.UTF8.GetString(bytes);
            return LimitText(MaskSensitiveJson(ApplyJsonDataScope(text, contentType)));
        }

        return GetBodyMetadata(contentType, bytes);
    }

    private bool IsTextResponse(string contentType)
    {
        var contentTypes = _configuration
            .GetSection("EndpointLog:TextResponseContentTypes")
            .Get<string[]>()
            ?? [
                "application/json",
                "application/problem+json",
                "application/xml",
                "text/"
            ];

        return contentTypes.Any(item => contentType.StartsWith(item, StringComparison.OrdinalIgnoreCase));
    }

    private string ApplyJsonDataScope(string text, string contentType)
    {
        var dataScope = _configuration.GetValue("EndpointLog:JsonDataScope", string.Empty);
        if (string.IsNullOrWhiteSpace(dataScope)
            || !contentType.StartsWith("application/json", StringComparison.OrdinalIgnoreCase))
        {
            return text;
        }

        try
        {
            using var document = JsonDocument.Parse(text);
            if (document.RootElement.ValueKind != JsonValueKind.Object)
            {
                return text;
            }

            if (!document.RootElement.TryGetProperty(dataScope, out var dataElement))
            {
                return text;
            }

            return dataElement.GetRawText();
        }
        catch (JsonException)
        {
            return text;
        }
    }

    private static string GetBodyMetadata(string contentType, byte[] bytes)
    {
        var hash = Convert.ToHexString(SHA256.HashData(bytes));
        return $"[binary content skipped: contentType={contentType}; bytes={bytes.Length}; sha256={hash}]";
    }

    private bool UseLoggerOutput()
    {
        var output = _configuration.GetValue("EndpointLog:Output", "Logger");
        return output.Equals("Logger", StringComparison.OrdinalIgnoreCase)
            || output.Equals("Both", StringComparison.OrdinalIgnoreCase);
    }

    private bool UseFileOutput()
    {
        var output = _configuration.GetValue("EndpointLog:Output", "Logger");
        return output.Equals("File", StringComparison.OrdinalIgnoreCase)
            || output.Equals("Both", StringComparison.OrdinalIgnoreCase);
    }

    private void WriteFileLog(string message)
    {
        if (!UseFileOutput())
        {
            return;
        }

        var configuredPath = _configuration.GetValue("EndpointLog:FilePath", "logs/endpoint-log-{date}.log");
        var filePath = configuredPath.Replace("{date}", DateTime.Now.ToString("yyyyMMdd"), StringComparison.OrdinalIgnoreCase);
        if (!Path.IsPathRooted(filePath))
        {
            filePath = Path.Combine(_environment.ContentRootPath, filePath);
        }

        var directory = Path.GetDirectoryName(filePath);
        if (!string.IsNullOrWhiteSpace(directory))
        {
            Directory.CreateDirectory(directory);
        }

        File.AppendAllText(filePath, $"{DateTime.Now:yyyy-MM-dd HH:mm:ss.fff} {message}{Environment.NewLine}");
    }

    private static string EscapeCurlValue(string value)
    {
        return value
            .Replace("\\", "\\\\", StringComparison.Ordinal)
            .Replace("\"", "\\\"", StringComparison.Ordinal)
            .Replace("\r", "\\r", StringComparison.Ordinal)
            .Replace("\n", "\\n", StringComparison.Ordinal);
    }
}
