// Copyright (c) 2026 - opx
using System.Diagnostics;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Microsoft.AspNetCore.Mvc.Controllers;
using Opx.Api.Web.Logs;

namespace Opx.Api.Web.Middlewares;

public sealed class OpxEndpointLogMiddleware
{
    private readonly RequestDelegate _next;
    private readonly ILogger<OpxEndpointLogMiddleware> _logger;
    private readonly IConfiguration _configuration;
    private readonly IWebHostEnvironment _environment;
    private readonly OpxEndpointLogWriter? _endpointLogWriter;

    public OpxEndpointLogMiddleware(
        RequestDelegate next,
        ILogger<OpxEndpointLogMiddleware> logger,
        IConfiguration configuration,
        IWebHostEnvironment environment,
        OpxEndpointLogWriter? endpointLogWriter = null)
    {
        _next = next;
        _logger = logger;
        _configuration = configuration;
        _environment = environment;
        _endpointLogWriter = endpointLogWriter;
    }

    public async Task InvokeAsync(HttpContext context)
    {
        var settings = ReadSettings();
        if (!settings.Enabled)
        {
            await _next(context);
            return;
        }

        var requestBody = await ReadRequestBodyAsync(context, settings);
        var originalResponseBody = context.Response.Body;
        MemoryStream? responseBody = null;
        if (settings.IncludeResponseBody)
        {
            responseBody = new MemoryStream();
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
            var responseText = await ReadResponseBodyAsync(context, responseBody, originalResponseBody, settings);
            WriteLog(context, stopwatch.ElapsedMilliseconds, requestBody, responseText, exception, settings);
        }
    }

    private void WriteLog(
        HttpContext context,
        long elapsedMilliseconds,
        string? requestBody,
        string? responseBody,
        Exception? exception,
        EndpointLogSettings settings)
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
        var path = GetPath(context, settings);
        var routeValues = GetRouteValues(context, settings);
        var curl = BuildCurl(context, requestBody, settings);
        var message = exception is null
            ? $"Endpoint executed {context.Request.Method} {path} => {context.Response.StatusCode} in {elapsedMilliseconds} ms | Endpoint={endpointName} | Route={route} | RouteValues={routeValues} | User={user} | Curl={curl} | Output={responseBody ?? "-"}"
            : $"Endpoint failed {context.Request.Method} {path} => {context.Response.StatusCode} in {elapsedMilliseconds} ms | Endpoint={endpointName} | Route={route} | RouteValues={routeValues} | User={user} | Curl={curl} | Output={responseBody ?? "-"} | Error={exception.Message}";

        if (UseLoggerOutput(settings))
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

        WriteFileLog(message, settings);
    }

    private string GetPath(HttpContext context, EndpointLogSettings settings)
    {
        return settings.IncludeQueryString
            ? $"{context.Request.Path}{context.Request.QueryString}"
            : context.Request.Path.ToString();
    }

    private string GetRouteValues(HttpContext context, EndpointLogSettings settings)
    {
        if (!settings.IncludeRouteValues)
        {
            return "-";
        }

        var values = context.Request.RouteValues
            .Where(value => value.Value is not null)
            .Select(value => $"{value.Key}={MaskIfSensitive(value.Key, value.Value?.ToString() ?? string.Empty, settings)}");

        var result = string.Join(", ", values);
        return string.IsNullOrWhiteSpace(result) ? "-" : result;
    }

    private async Task<string?> ReadRequestBodyAsync(HttpContext context, EndpointLogSettings settings)
    {
        if (!settings.IncludeRequestBody)
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
        return LimitText(MaskSensitiveJson(body, settings), settings);
    }

    private async Task<string?> ReadResponseBodyAsync(
        HttpContext context,
        MemoryStream? responseBody,
        Stream originalResponseBody,
        EndpointLogSettings settings)
    {
        if (!settings.IncludeResponseBody || responseBody is null)
        {
            return null;
        }

        context.Response.Body = originalResponseBody;
        responseBody.Position = 0;
        var bytes = responseBody.ToArray();
        await responseBody.CopyToAsync(originalResponseBody);
        return FormatResponseBody(context, bytes, settings);
    }

    private string BuildCurl(HttpContext context, string? requestBody, EndpointLogSettings settings)
    {
        if (!settings.IncludeCurl)
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
            command.Append(MaskIfSensitive("Authorization", context.Request.Headers.Authorization.ToString(), settings));
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

    private string MaskSensitiveJson(string value, EndpointLogSettings settings)
    {
        if (!settings.MaskSensitiveValues)
        {
            return value;
        }

        var sensitiveKeys = settings.SensitiveKeys;
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

    private string MaskIfSensitive(string key, string value, EndpointLogSettings settings)
    {
        if (!settings.MaskSensitiveValues)
        {
            return value;
        }

        return settings.SensitiveKeys.Any(item => key.Contains(item, StringComparison.OrdinalIgnoreCase))
            ? "***"
            : value;
    }

    private static string LimitText(string value, EndpointLogSettings settings)
    {
        return value.Length <= settings.MaxBodyLength
            ? value
            : string.Concat(value.AsSpan(0, settings.MaxBodyLength), "...[truncated]");
    }

    private string FormatResponseBody(HttpContext context, byte[] bytes, EndpointLogSettings settings)
    {
        if (bytes.Length == 0)
        {
            return string.Empty;
        }

        var contentType = context.Response.ContentType ?? string.Empty;
        var responseBodyMode = settings.ResponseBodyMode;

        if (responseBodyMode.Equals("None", StringComparison.OrdinalIgnoreCase)
            || responseBodyMode.Equals("Skip", StringComparison.OrdinalIgnoreCase))
        {
            return GetBodyMetadata(contentType, bytes);
        }

        if (responseBodyMode.Equals("Base64", StringComparison.OrdinalIgnoreCase))
        {
            return LimitText(Convert.ToBase64String(bytes), settings);
        }

        if (responseBodyMode.Equals("Text", StringComparison.OrdinalIgnoreCase)
            || IsTextResponse(contentType, settings))
        {
            var text = Encoding.UTF8.GetString(bytes);
            return LimitText(MaskSensitiveJson(ApplyJsonDataScope(text, contentType, settings), settings), settings);
        }

        return GetBodyMetadata(contentType, bytes);
    }

    private bool IsTextResponse(string contentType, EndpointLogSettings settings)
    {
        return settings.TextResponseContentTypes.Any(item => contentType.StartsWith(item, StringComparison.OrdinalIgnoreCase));
    }

    private string ApplyJsonDataScope(string text, string contentType, EndpointLogSettings settings)
    {
        if (string.IsNullOrWhiteSpace(settings.JsonDataScope)
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

            if (!document.RootElement.TryGetProperty(settings.JsonDataScope, out var dataElement))
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

    private static bool UseLoggerOutput(EndpointLogSettings settings)
    {
        return settings.Output.Equals("Logger", StringComparison.OrdinalIgnoreCase)
            || settings.Output.Equals("Both", StringComparison.OrdinalIgnoreCase);
    }

    private static bool UseFileOutput(EndpointLogSettings settings)
    {
        return settings.Output.Equals("File", StringComparison.OrdinalIgnoreCase)
            || settings.Output.Equals("Both", StringComparison.OrdinalIgnoreCase);
    }

    private void WriteFileLog(string message, EndpointLogSettings settings)
    {
        if (!UseFileOutput(settings))
        {
            return;
        }

        var filePath = ResolveFilePath(settings);
        if (_endpointLogWriter is not null)
        {
            if (!_endpointLogWriter.TryWrite(EndpointLogEntry.Create(message, filePath)))
            {
                _logger.LogWarning("Endpoint log queue is full. Dropped: {Message}", message);
            }

            return;
        }

        var directory = Path.GetDirectoryName(filePath);
        if (!string.IsNullOrWhiteSpace(directory))
        {
            Directory.CreateDirectory(directory);
        }

        File.AppendAllText(filePath, $"{DateTime.Now:yyyy-MM-dd HH:mm:ss.fff} {message}{Environment.NewLine}");
    }

    private string ResolveFilePath(EndpointLogSettings settings)
    {
        var filePath = settings.FilePath.Replace("{date}", DateTime.Now.ToString("yyyyMMdd"), StringComparison.OrdinalIgnoreCase);
        if (!Path.IsPathRooted(filePath))
        {
            filePath = Path.Combine(_environment.ContentRootPath, filePath);
        }

        return filePath;
    }

    private static string EscapeCurlValue(string value)
    {
        return value
            .Replace("\\", "\\\\", StringComparison.Ordinal)
            .Replace("\"", "\\\"", StringComparison.Ordinal)
            .Replace("\r", "\\r", StringComparison.Ordinal)
            .Replace("\n", "\\n", StringComparison.Ordinal);
    }

    private EndpointLogSettings ReadSettings()
    {
        return new EndpointLogSettings(
            _configuration.GetValue<bool>("EndpointLog:Enabled"),
            _configuration.GetValue("EndpointLog:IncludeQueryString", true),
            _configuration.GetValue("EndpointLog:IncludeRouteValues", true),
            _configuration.GetValue("EndpointLog:IncludeRequestBody", false),
            _configuration.GetValue("EndpointLog:IncludeResponseBody", false),
            _configuration.GetValue("EndpointLog:IncludeCurl", true),
            _configuration.GetValue("EndpointLog:Output", "Logger") ?? "Logger",
            _configuration.GetValue("EndpointLog:ResponseBodyMode", "Auto") ?? "Auto",
            _configuration.GetValue("EndpointLog:MaskSensitiveValues", true),
            Math.Max(1, _configuration.GetValue("EndpointLog:MaxBodyLength", 4000)),
            _configuration.GetValue("EndpointLog:JsonDataScope", string.Empty) ?? string.Empty,
            _configuration.GetValue("EndpointLog:FilePath", "logs/endpoint-log-{date}.log") ?? "logs/endpoint-log-{date}.log",
            _configuration.GetSection("EndpointLog:SensitiveKeys").Get<string[]>() ?? ["password", "token", "secret", "authorization"],
            _configuration.GetSection("EndpointLog:TextResponseContentTypes").Get<string[]>() ??
            [
                "application/json",
                "application/problem+json",
                "application/xml",
                "text/"
            ]);
    }

    private sealed record EndpointLogSettings(
        bool Enabled,
        bool IncludeQueryString,
        bool IncludeRouteValues,
        bool IncludeRequestBody,
        bool IncludeResponseBody,
        bool IncludeCurl,
        string Output,
        string ResponseBodyMode,
        bool MaskSensitiveValues,
        int MaxBodyLength,
        string JsonDataScope,
        string FilePath,
        string[] SensitiveKeys,
        string[] TextResponseContentTypes);
}
