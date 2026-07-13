// Copyright (c) 2026 - opx
using System.Net;
using System.Text.Json;
using System.Text.RegularExpressions;
using Microsoft.Extensions.Primitives;
using Opx.Api.Web.Common;
using Opx.Api.Web.Logs;
using Opx.Api.Web.Protection;

namespace Opx.Api.Web.Middlewares;

public sealed class OpxSuspiciousTrafficGuardMiddleware
{
	private static readonly string[] DefaultPatterns =
	[
		"sqlmap",
		".env",
		".git",
		"union select",
		"information_schema",
		"<script",
		"../",
		"..\\",
		"xp_cmdshell",
		"or 1=1",
		"drop table"
	];

	private readonly IConfiguration _configuration;
	private readonly IWebHostEnvironment _environment;
	private readonly ILogger<OpxSuspiciousTrafficGuardMiddleware> _logger;
	private readonly RequestDelegate _next;
	private readonly OpxSecurityIssueLogWriter? _securityIssueLogWriter;
	private readonly OpxProtectionMetrics? _metrics;
	private readonly OpxProtectionPolicyProvider? _policyProvider;
	private readonly object _settingsLock = new();
	private SuspiciousTrafficSettings? _settings;
	private IChangeToken? _changeToken;
	private long _securityIssueLogCounter;

	public OpxSuspiciousTrafficGuardMiddleware(
		RequestDelegate next,
		IConfiguration configuration,
		IWebHostEnvironment environment,
		ILogger<OpxSuspiciousTrafficGuardMiddleware> logger,
		OpxSecurityIssueLogWriter? securityIssueLogWriter = null,
		OpxProtectionMetrics? metrics = null,
		OpxProtectionPolicyProvider? policyProvider = null)
	{
		_next = next;
		_configuration = configuration;
		_environment = environment;
		_logger = logger;
		_securityIssueLogWriter = securityIssueLogWriter;
		_metrics = metrics;
		_policyProvider = policyProvider;
	}

	public async Task InvokeAsync(HttpContext context)
	{
		var settings = GetSettings();
		var policy = _policyProvider?.GetPolicy(context.Request.Path) ?? OpxProtectionPolicy.Empty;
		if (!settings.Enabled || policy.SkipSuspiciousTraffic || IsExcluded(context.Request.Path, settings.ExcludedPaths))
		{
			await _next(context);
			return;
		}

		var (ipAddress, parsedIpAddress) = GetClientIpAddress(context);
		if (parsedIpAddress is not null
			? settings.AllowedIpMatcher.IsMatch(parsedIpAddress)
			: settings.AllowedIpMatcher.IsMatch(ipAddress))
		{
			await _next(context);
			return;
		}

		var deniedIp = parsedIpAddress is not null
			? settings.DeniedIpMatcher.IsMatch(parsedIpAddress)
			: settings.DeniedIpMatcher.IsMatch(ipAddress);
		var reason = deniedIp
			? $"Denied IP {ipAddress}"
			: FindSuspiciousReason(context, settings);

		if (reason is null)
		{
			await _next(context);
			return;
		}

		_metrics?.IncrementSuspiciousDetected();
		context.Items["OpxSuspiciousReason"] = reason;
		WriteSecurityIssueLog(context, reason);

		if (!settings.Block)
		{
			await _next(context);
			return;
		}

		_metrics?.IncrementSuspiciousBlocked();
		if (settings.BlockedResponseMode.Equals("Minimal", StringComparison.OrdinalIgnoreCase))
		{
			await WriteMinimalBlockedResponseAsync(context, settings);
			return;
		}

		if (settings.BlockedResponseMode.Equals("WrappedFast", StringComparison.OrdinalIgnoreCase))
		{
			await WriteWrappedFastBlockedResponseAsync(context, settings);
			return;
		}

		await ApiResponseObjectValue.ShowErrorResponseAsync(context, settings.StatusCode, new ApiErrorValue
		{
			Message = "Suspicious traffic detected",
			Id = reason,
			ObjectName = context.Request.Path.ToString()
		});
	}

	private string? FindSuspiciousReason(HttpContext context, SuspiciousTrafficSettings settings)
	{
		var path = context.Request.Path.ToString();
		var query = context.Request.QueryString.ToString();
		var userAgent = context.Request.Headers.UserAgent.ToString();
		var referer = context.Request.Headers.Referer.ToString();

		foreach (var pattern in settings.Patterns)
		{
			if (path.Contains(pattern, StringComparison.OrdinalIgnoreCase)
				|| query.Contains(pattern, StringComparison.OrdinalIgnoreCase)
				|| userAgent.Contains(pattern, StringComparison.OrdinalIgnoreCase)
				|| referer.Contains(pattern, StringComparison.OrdinalIgnoreCase))
			{
				return pattern;
			}
		}

		if (settings.RegexPatterns.Length == 0)
		{
			return null;
		}

		var target = string.Concat(path, " ", query, " ", userAgent, " ", referer);
		foreach (var regex in settings.RegexPatterns)
		{
			if (regex.IsMatch(target))
			{
				return regex.ToString();
			}
		}

		return null;
	}

	private void WriteSecurityIssueLog(HttpContext context, string reason)
	{
		var settings = GetSettings();
		if (!settings.SecurityIssueLogEnabled || !ShouldWriteSecurityIssueLog(settings))
		{
			return;
		}

		var message = BuildSecurityIssueMessage(context, reason, settings);
		var writeLogger = settings.SecurityIssueLogOutput.Equals("Logger", StringComparison.OrdinalIgnoreCase)
			|| settings.SecurityIssueLogOutput.Equals("Both", StringComparison.OrdinalIgnoreCase);
		var writeFile = settings.SecurityIssueLogOutput.Equals("File", StringComparison.OrdinalIgnoreCase)
			|| settings.SecurityIssueLogOutput.Equals("Both", StringComparison.OrdinalIgnoreCase);
		var filePath = writeFile ? ResolveSecurityIssueLogFilePath(settings) : null;

		if (_securityIssueLogWriter is not null)
		{
			if (!_securityIssueLogWriter.TryWrite(SecurityIssueLogEntry.Create(message, writeLogger, writeFile, filePath, settings.SecurityIssueLogFormat)))
			{
				_logger.LogWarning("Security issue log queue is full. Dropped: {Message}", message);
			}

			return;
		}

		if (writeLogger)
		{
			_logger.LogWarning("{Message}", message);
		}

		if (!writeFile || string.IsNullOrWhiteSpace(filePath))
		{
			return;
		}

		var directory = Path.GetDirectoryName(filePath);
		if (!string.IsNullOrWhiteSpace(directory))
		{
			Directory.CreateDirectory(directory);
		}

		File.AppendAllText(filePath, $"{DateTime.Now:yyyy-MM-dd HH:mm:ss.fff} {message}{Environment.NewLine}");
	}

	private string ResolveSecurityIssueLogFilePath(SuspiciousTrafficSettings settings)
	{
		var filePath = settings.SecurityIssueLogFilePath.Replace("{date}", DateTime.Now.ToString("yyyyMMdd"), StringComparison.OrdinalIgnoreCase);
		if (!Path.IsPathRooted(filePath))
		{
			filePath = Path.Combine(_environment.ContentRootPath, filePath);
		}

		return filePath;
	}

	private bool ShouldWriteSecurityIssueLog(SuspiciousTrafficSettings settings)
	{
		var sampleRate = Math.Max(1, settings.SecurityIssueLogSampleRate);
		if (sampleRate == 1)
		{
			return true;
		}

		var count = Interlocked.Increment(ref _securityIssueLogCounter);
		return count == 1 || count % sampleRate == 0;
	}

	private SuspiciousTrafficSettings GetSettings()
	{
		var currentToken = _configuration.GetReloadToken();
		if (_settings is not null && ReferenceEquals(_changeToken, currentToken) && !currentToken.HasChanged)
		{
			return _settings;
		}

		lock (_settingsLock)
		{
			currentToken = _configuration.GetReloadToken();
			if (_settings is not null && ReferenceEquals(_changeToken, currentToken) && !currentToken.HasChanged)
			{
				return _settings;
			}

			_settings = ReadSettings();
			_changeToken = currentToken;
			return _settings;
		}
	}

	private SuspiciousTrafficSettings ReadSettings()
	{
		var regexTimeoutMs = Math.Max(1, _configuration.GetValue("OpxApiProtection:SuspiciousTraffic:RegexTimeoutMilliseconds", 100));
		var regexTimeout = TimeSpan.FromMilliseconds(regexTimeoutMs);
		var regexPatterns = _configuration
			.GetSection("OpxApiProtection:SuspiciousTraffic:RegexPatterns")
			.Get<string[]>()
			?? [];

		return new SuspiciousTrafficSettings(
			_configuration.GetValue("OpxApiProtection:SuspiciousTraffic:Enabled", false),
			_configuration.GetValue("OpxApiProtection:SuspiciousTraffic:Block", true),
			_configuration.GetValue("OpxApiProtection:SuspiciousTraffic:StatusCode", (int)HttpStatusCode.BadRequest),
			_configuration.GetValue("OpxApiProtection:SuspiciousTraffic:BlockedResponseMode", "WrappedFast") ?? "WrappedFast",
			(_configuration.GetSection("OpxApiProtection:SuspiciousTraffic:Patterns").Get<string[]>() ?? DefaultPatterns)
				.Where(pattern => !string.IsNullOrWhiteSpace(pattern))
				.ToArray(),
			regexPatterns
				.Where(pattern => !string.IsNullOrWhiteSpace(pattern))
				.Select(pattern => new Regex(pattern, RegexOptions.IgnoreCase | RegexOptions.CultureInvariant | RegexOptions.Compiled, regexTimeout))
				.ToArray(),
			(_configuration.GetSection("OpxApiProtection:SuspiciousTraffic:ExcludedPathPrefixes").Get<string[]>() ?? ["/health", "/openapi", "/swagger", "/favicon.ico", "/assets", "/static"])
				.Where(path => !string.IsNullOrWhiteSpace(path))
				.Select(path => new PathString(path))
				.ToArray(),
			_configuration.GetValue("OpxApiProtection:SecurityIssueLog:Enabled", true),
			_configuration.GetValue("OpxApiProtection:SecurityIssueLog:Output", "File") ?? "File",
			_configuration.GetValue("OpxApiProtection:SecurityIssueLog:FilePath", "logs/security-issue-log-{date}.log") ?? "logs/security-issue-log-{date}.log",
			_configuration.GetValue("OpxApiProtection:SecurityIssueLog:Format", "Text") ?? "Text",
			Math.Max(1, _configuration.GetValue("OpxApiProtection:SecurityIssueLog:SampleRate", 1)),
			Math.Max(64, _configuration.GetValue("OpxApiProtection:SecurityIssueLog:MaxPathLength", 512)),
			Math.Max(64, _configuration.GetValue("OpxApiProtection:SecurityIssueLog:MaxQueryLength", 512)),
			Math.Max(64, _configuration.GetValue("OpxApiProtection:SecurityIssueLog:MaxHeaderLength", 512)),
			Math.Max(64, _configuration.GetValue("OpxApiProtection:SecurityIssueLog:MaxReasonLength", 256)),
			OpxIpMatcher.Create(_configuration.GetSection("OpxApiProtection:SuspiciousTraffic:AllowedIpAddresses").Get<string[]>() ?? []),
			OpxIpMatcher.Create(_configuration.GetSection("OpxApiProtection:SuspiciousTraffic:DeniedIpAddresses").Get<string[]>() ?? []));
	}

	private static string BuildSecurityIssueMessage(HttpContext context, string reason, SuspiciousTrafficSettings settings)
	{
		var path = CleanLogField(context.Request.Path.ToString(), settings.MaxPathLength);
		var query = CleanLogField(context.Request.QueryString.ToString(), settings.MaxQueryLength);
		var ip = CleanLogField(GetClientIpAddress(context).Text, settings.MaxHeaderLength);
		var host = CleanLogField(context.Request.Host.ToString(), settings.MaxHeaderLength);
		var userAgent = CleanLogField(context.Request.Headers.UserAgent.ToString(), settings.MaxHeaderLength);
		var sanitizedReason = CleanLogField(reason, settings.MaxReasonLength);

		return $"SecurityIssue {context.Request.Method} {path}{query} | IP={ip} | Host={host} | UserAgent={userAgent} | Reason={sanitizedReason}";
	}

	private static string CleanLogField(string? value, int maxLength)
	{
		if (string.IsNullOrEmpty(value))
		{
			return string.Empty;
		}

		Span<char> buffer = value.Length <= 1024 ? stackalloc char[value.Length] : new char[value.Length];
		for (var index = 0; index < value.Length; index++)
		{
			var current = value[index];
			buffer[index] = current is '\r' or '\n' or '\t' ? ' ' : current;
		}

		var sanitized = new string(buffer).Trim();
		return sanitized.Length <= maxLength
			? sanitized
			: string.Concat(sanitized.AsSpan(0, maxLength), "...");
	}

	private static async Task WriteMinimalBlockedResponseAsync(HttpContext context, SuspiciousTrafficSettings settings)
	{
		var response = settings.MinimalBlockedResponseBytes;
		await WriteCachedBlockedResponseAsync(context, response);
	}

	private static async Task WriteWrappedFastBlockedResponseAsync(HttpContext context, SuspiciousTrafficSettings settings)
	{
		var response = settings.WrappedFastBlockedResponseBytes;
		await WriteCachedBlockedResponseAsync(context, response);
	}

	private static async Task WriteCachedBlockedResponseAsync(HttpContext context, byte[] response)
	{
		context.Response.ContentType = "application/json";
		context.Response.StatusCode = StatusCodes.Status200OK;
		context.Response.ContentLength = response.Length;
		await context.Response.Body.WriteAsync(response);
		await context.Response.CompleteAsync();
	}

	private static bool IsExcluded(PathString path, PathString[] excludedPathPrefixes)
	{
		return excludedPathPrefixes.Any(path.StartsWithSegments);
	}

	private static (string Text, System.Net.IPAddress? Address) GetClientIpAddress(HttpContext context)
	{
		if (context.Request.Headers.TryGetValue("X-Forwarded-For", out var forwardedFor)
			&& !string.IsNullOrWhiteSpace(forwardedFor))
		{
			var value = forwardedFor.ToString().Split(',')[0].Trim();
			return System.Net.IPAddress.TryParse(value, out var address)
				? (value, address)
				: (value, null);
		}

		var remoteAddress = context.Connection.RemoteIpAddress;
		return remoteAddress is null
			? ("unknown", null)
			: (remoteAddress.ToString(), remoteAddress);
	}

	private sealed record SuspiciousTrafficSettings(
		bool Enabled,
		bool Block,
		int StatusCode,
		string BlockedResponseMode,
		string[] Patterns,
		Regex[] RegexPatterns,
		PathString[] ExcludedPaths,
		bool SecurityIssueLogEnabled,
		string SecurityIssueLogOutput,
		string SecurityIssueLogFilePath,
		string SecurityIssueLogFormat,
		int SecurityIssueLogSampleRate,
		int MaxPathLength,
		int MaxQueryLength,
		int MaxHeaderLength,
		int MaxReasonLength,
		OpxIpMatcher AllowedIpMatcher,
		OpxIpMatcher DeniedIpMatcher)
	{
		public byte[] MinimalBlockedResponseBytes { get; } = JsonSerializer.SerializeToUtf8Bytes(new
		{
			result = false,
			data = "Suspicious traffic detected",
			statusCode = StatusCode.ToString()
		});

		public byte[] WrappedFastBlockedResponseBytes { get; } = JsonSerializer.SerializeToUtf8Bytes(new
		{
			result = false,
			data = new
			{
				message = "Suspicious traffic detected",
				id = "SuspiciousTraffic",
				objectName = "Request"
			},
			statusCode = StatusCode.ToString()
		});
	}
}
