// Copyright (c) 2026 - opx
using System.Net;
using System.Text.RegularExpressions;
using Opx.Api.Web.Common;

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

	public OpxSuspiciousTrafficGuardMiddleware(
		RequestDelegate next,
		IConfiguration configuration,
		IWebHostEnvironment environment,
		ILogger<OpxSuspiciousTrafficGuardMiddleware> logger)
	{
		_next = next;
		_configuration = configuration;
		_environment = environment;
		_logger = logger;
	}

	public async Task InvokeAsync(HttpContext context)
	{
		if (!_configuration.GetValue("OpxApiProtection:SuspiciousTraffic:Enabled", false))
		{
			await _next(context);
			return;
		}

		var target = GetTarget(context);
		var reason = FindSuspiciousReason(target);

		if (reason is null)
		{
			await _next(context);
			return;
		}

		context.Items["OpxSuspiciousReason"] = reason;
		_logger.LogWarning("Suspicious request detected. Reason={Reason}; Path={Path}; IP={IP}", reason, context.Request.Path, context.Connection.RemoteIpAddress);
		WriteSecurityIssueLog(context, reason);

		if (!_configuration.GetValue("OpxApiProtection:SuspiciousTraffic:Block", true))
		{
			await _next(context);
			return;
		}

		var statusCode = _configuration.GetValue("OpxApiProtection:SuspiciousTraffic:StatusCode", (int)HttpStatusCode.BadRequest);
		await ApiResponseObjectValue.ShowErrorResponseAsync(context, statusCode, new ApiErrorValue
		{
			Message = "Suspicious traffic detected",
			Id = reason,
			ObjectName = context.Request.Path.ToString()
		});
	}

	private string? FindSuspiciousReason(string target)
	{
		var patterns = _configuration
			.GetSection("OpxApiProtection:SuspiciousTraffic:Patterns")
			.Get<string[]>()
			?? DefaultPatterns;

		foreach (var pattern in patterns.Where(pattern => !string.IsNullOrWhiteSpace(pattern)))
		{
			if (target.Contains(pattern, StringComparison.OrdinalIgnoreCase))
			{
				return pattern;
			}
		}

		var regexPatterns = _configuration
			.GetSection("OpxApiProtection:SuspiciousTraffic:RegexPatterns")
			.Get<string[]>()
			?? [];

		foreach (var pattern in regexPatterns.Where(pattern => !string.IsNullOrWhiteSpace(pattern)))
		{
			if (Regex.IsMatch(target, pattern, RegexOptions.IgnoreCase | RegexOptions.CultureInvariant, TimeSpan.FromMilliseconds(100)))
			{
				return pattern;
			}
		}

		return null;
	}

	private static string GetTarget(HttpContext context)
	{
		return string.Join(" ",
			context.Request.Path.ToString(),
			context.Request.QueryString.ToString(),
			context.Request.Headers.UserAgent.ToString(),
			context.Request.Headers.Referer.ToString());
	}

	private void WriteSecurityIssueLog(HttpContext context, string reason)
	{
		if (!_configuration.GetValue("OpxApiProtection:SecurityIssueLog:Enabled", true))
		{
			return;
		}

		var output = _configuration.GetValue("OpxApiProtection:SecurityIssueLog:Output", "File");
		var message = $"SecurityIssue {context.Request.Method} {context.Request.Path}{context.Request.QueryString} | IP={GetClientIpAddress(context)} | Host={context.Request.Host} | UserAgent={context.Request.Headers.UserAgent} | Reason={reason}";

		if (output.Equals("Logger", StringComparison.OrdinalIgnoreCase)
			|| output.Equals("Both", StringComparison.OrdinalIgnoreCase))
		{
			_logger.LogWarning("{Message}", message);
		}

		if (!output.Equals("File", StringComparison.OrdinalIgnoreCase)
			&& !output.Equals("Both", StringComparison.OrdinalIgnoreCase))
		{
			return;
		}

		var configuredPath = _configuration.GetValue("OpxApiProtection:SecurityIssueLog:FilePath", "logs/security-issue-log-{date}.log");
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

	private static string GetClientIpAddress(HttpContext context)
	{
		if (context.Request.Headers.TryGetValue("X-Forwarded-For", out var forwardedFor)
			&& !string.IsNullOrWhiteSpace(forwardedFor))
		{
			return forwardedFor.ToString().Split(',')[0].Trim();
		}

		return context.Connection.RemoteIpAddress?.ToString() ?? "unknown";
	}
}
