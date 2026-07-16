// Copyright (c) 2026 - opx
using System.Text.RegularExpressions;

namespace Opx.Api.Web.Protection;

public sealed class OpxProtectionConfigurationValidator : IHostedService
{
	private readonly IConfiguration _configuration;
	private readonly ILogger<OpxProtectionConfigurationValidator> _logger;

	public OpxProtectionConfigurationValidator(
		IConfiguration configuration,
		ILogger<OpxProtectionConfigurationValidator> logger)
	{
		_configuration = configuration;
		_logger = logger;
	}

	public Task StartAsync(CancellationToken cancellationToken)
	{
		var errors = Validate(_configuration).ToArray();
		if (errors.Length == 0)
		{
			return Task.CompletedTask;
		}

		var message = $"Invalid Opx.Api.Web protection configuration: {string.Join("; ", errors)}";
		if (_configuration.GetValue("OpxApiProtection:Validation:FailFast", false))
		{
			throw new InvalidOperationException(message);
		}

		_logger.LogWarning("{Message}", message);
		return Task.CompletedTask;
	}

	public Task StopAsync(CancellationToken cancellationToken)
	{
		return Task.CompletedTask;
	}

	public static IEnumerable<string> Validate(IConfiguration configuration)
	{
		foreach (var error in ValidateIpList(configuration, "OpxApiProtection:ClientIp:TrustedProxies"))
		{
			yield return error;
		}

		foreach (var error in ValidateIpList(configuration, "OpxApiProtection:ClientIp:TrustedNetworks"))
		{
			yield return error;
		}

		foreach (var error in ValidateIpList(configuration, "OpxApiProtection:ForwardedHeaders:KnownProxies"))
		{
			yield return error;
		}

		foreach (var error in ValidateIpList(configuration, "OpxApiProtection:ForwardedHeaders:KnownNetworks"))
		{
			yield return error;
		}

		foreach (var error in ValidateSingleIp(configuration, "OpxApiProtection:ClientIp:TrustedProxy"))
		{
			yield return error;
		}

		foreach (var error in ValidateSingleIp(configuration, "OpxApiProtection:ClientIp:TrustedNetwork"))
		{
			yield return error;
		}

		var maxForwardedEntries = configuration.GetValue("OpxApiProtection:ClientIp:MaxForwardedEntries", 10);
		if (maxForwardedEntries is <= 0 or > 100)
		{
			yield return "OpxApiProtection:ClientIp:MaxForwardedEntries must be between 1 and 100.";
		}

		var maxHeaderValueLength = configuration.GetValue("OpxApiProtection:ClientIp:MaxHeaderValueLength", 4096);
		if (maxHeaderValueLength is < 64 or > 32768)
		{
			yield return "OpxApiProtection:ClientIp:MaxHeaderValueLength must be between 64 and 32768.";
		}

		var clientIpHeaderNames = configuration.GetSection("OpxApiProtection:ClientIp:HeaderNames").Get<string[]>() ?? [];
		if (clientIpHeaderNames.Length > 16)
		{
			yield return "OpxApiProtection:ClientIp:HeaderNames cannot contain more than 16 entries.";
		}

		foreach (var headerName in clientIpHeaderNames.Where(value => !string.IsNullOrWhiteSpace(value)))
		{
			if (!IsValidHeaderName(headerName.Trim()))
			{
				yield return $"OpxApiProtection:ClientIp:HeaderNames contains invalid HTTP header name '{headerName}'.";
			}
		}

		if (configuration.GetValue("OpxApiProtection:ClientIp:TrustAnyProxy", false)
			&& !configuration.GetValue("OpxApiProtection:ClientIp:TrustForwardedHeaders", false))
		{
			yield return "OpxApiProtection:ClientIp:TrustAnyProxy requires TrustForwardedHeaders to be enabled.";
		}

		foreach (var error in ValidateIpList(configuration, "OpxApiProtection:SuspiciousTraffic:AllowedIpAddresses"))
		{
			yield return error;
		}

		foreach (var error in ValidateIpList(configuration, "OpxApiProtection:SuspiciousTraffic:DeniedIpAddresses"))
		{
			yield return error;
		}

		var logFormat = configuration.GetValue("OpxApiProtection:SecurityIssueLog:Format", "Text") ?? "Text";
		if (!IsOneOf(logFormat, "Text", "JsonLines", "GatewayText"))
		{
			yield return "OpxApiProtection:SecurityIssueLog:Format must be Text, JsonLines, or GatewayText.";
		}

		var logOutput = configuration.GetValue("OpxApiProtection:SecurityIssueLog:Output", "File") ?? "File";
		if (!IsOneOf(logOutput, "Logger", "File", "Both"))
		{
			yield return "OpxApiProtection:SecurityIssueLog:Output must be Logger, File, or Both.";
		}

		var blockedResponseMode = configuration.GetValue("OpxApiProtection:SuspiciousTraffic:BlockedResponseMode", "WrappedFast") ?? "WrappedFast";
		if (!IsOneOf(blockedResponseMode, "Wrapped", "WrappedFast", "Minimal"))
		{
			yield return "OpxApiProtection:SuspiciousTraffic:BlockedResponseMode must be Wrapped, WrappedFast, or Minimal.";
		}

		var blockStatusCode = configuration.GetValue<int?>("OpxApiProtection:SuspiciousTraffic:StatusCode")
			?? configuration.GetValue("OpxApiProtection:SuspiciousTraffic:BlockStatusCode", StatusCodes.Status400BadRequest);
		if (blockStatusCode is < 400 or > 599)
		{
			yield return "OpxApiProtection:SuspiciousTraffic:StatusCode must be between 400 and 599.";
		}

		var responseMessage = configuration.GetValue<string>("OpxApiProtection:SuspiciousTraffic:ResponseMessage")
			?? configuration.GetValue<string>("OpxApiProtection:SuspiciousTraffic:BlockResponseBody");
		if (responseMessage is { Length: > 1024 })
		{
			yield return "OpxApiProtection:SuspiciousTraffic:ResponseMessage cannot exceed 1024 characters.";
		}

		var slowRequestMilliseconds = ReadSlowRequestMilliseconds(configuration);
		if (slowRequestMilliseconds < 0)
		{
			yield return "OpxApiProtection:SuspiciousTraffic slow request threshold cannot be negative.";
		}

		var rateLimitAlgorithm = configuration.GetValue("OpxApiProtection:RateLimiting:Algorithm", "SlidingWindow") ?? "SlidingWindow";
		if (!IsOneOf(rateLimitAlgorithm, "SlidingWindow", "FixedWindow"))
		{
			yield return "OpxApiProtection:RateLimiting:Algorithm must be SlidingWindow or FixedWindow.";
		}

		var regexTimeoutMs = configuration.GetValue("OpxApiProtection:SuspiciousTraffic:RegexTimeoutMilliseconds", 100);
		if (regexTimeoutMs <= 0)
		{
			yield return "OpxApiProtection:SuspiciousTraffic:RegexTimeoutMilliseconds must be greater than 0.";
		}

		var regexPatterns = configuration.GetSection("OpxApiProtection:SuspiciousTraffic:RegexPatterns").Get<string[]>() ?? [];
		foreach (var pattern in regexPatterns.Where(pattern => !string.IsNullOrWhiteSpace(pattern)))
		{
			if (!CanCompileRegex(pattern, regexTimeoutMs))
			{
				yield return $"OpxApiProtection:SuspiciousTraffic:RegexPatterns contains invalid regex '{pattern}'.";
			}
		}

		var policies = configuration.GetSection("OpxApiProtection:Policies").Get<OpxProtectionPolicy[]>() ?? [];
		foreach (var policy in policies)
		{
			if (string.IsNullOrWhiteSpace(policy.PathPrefix) || !policy.PathPrefix.StartsWith("/", StringComparison.Ordinal))
			{
				yield return "OpxApiProtection:Policies PathPrefix must start with '/'.";
			}

			if (policy.RateLimit is <= 0)
			{
				yield return $"OpxApiProtection:Policies '{policy.PathPrefix}' RateLimit must be greater than 0.";
			}

			if (policy.RateLimitWindowSeconds is <= 0)
			{
				yield return $"OpxApiProtection:Policies '{policy.PathPrefix}' RateLimitWindowSeconds must be greater than 0.";
			}
		}

		if (configuration.GetValue("OpxApiProtection:WebSocket:Enabled", false))
		{
			var path = configuration.GetValue("OpxApiProtection:WebSocket:Path", "/opx/ws");
			if (string.IsNullOrWhiteSpace(path) || !path.StartsWith("/", StringComparison.Ordinal))
			{
				yield return "OpxApiProtection:WebSocket:Path must start with '/'.";
			}

			var receiveBufferBytes = configuration.GetValue("OpxApiProtection:WebSocket:ReceiveBufferBytes", 16 * 1024);
			var maxMessageBytes = configuration.GetValue("OpxApiProtection:WebSocket:MaxMessageBytes", 1024 * 1024);
			if (receiveBufferBytes < 1024)
			{
				yield return "OpxApiProtection:WebSocket:ReceiveBufferBytes must be at least 1024.";
			}

			if (maxMessageBytes < receiveBufferBytes)
			{
				yield return "OpxApiProtection:WebSocket:MaxMessageBytes must be greater than or equal to ReceiveBufferBytes.";
			}

			if (configuration.GetValue("OpxApiProtection:WebSocket:IdleTimeoutSeconds", 120) < 0)
			{
				yield return "OpxApiProtection:WebSocket:IdleTimeoutSeconds cannot be negative.";
			}

			if (configuration.GetValue("OpxApiProtection:WebSocket:MessageRateLimitWindowSeconds", 60) <= 0)
			{
				yield return "OpxApiProtection:WebSocket:MessageRateLimitWindowSeconds must be greater than 0.";
			}

			if (configuration.GetValue("OpxApiProtection:WebSocket:MaxSubscriptionsPerConnection", 64) <= 0)
			{
				yield return "OpxApiProtection:WebSocket:MaxSubscriptionsPerConnection must be greater than 0.";
			}

			var maxTopicLength = configuration.GetValue("OpxApiProtection:WebSocket:MaxTopicLength", 128);
			if (maxTopicLength is <= 0 or > 512)
			{
				yield return "OpxApiProtection:WebSocket:MaxTopicLength must be between 1 and 512.";
			}

			if (configuration.GetValue("OpxApiProtection:WebSocket:Redis:Enabled", false))
			{
				if (string.IsNullOrWhiteSpace(configuration.GetValue<string>("OpxApiProtection:WebSocket:Redis:Configuration")))
				{
					yield return "OpxApiProtection:WebSocket:Redis:Configuration is required when Redis is enabled.";
				}

				if (string.IsNullOrWhiteSpace(configuration.GetValue<string>("OpxApiProtection:WebSocket:Redis:Channel")))
				{
					yield return "OpxApiProtection:WebSocket:Redis:Channel is required when Redis is enabled.";
				}
			}
		}
	}

	private static IEnumerable<string> ValidateIpList(IConfiguration configuration, string key)
	{
		var values = configuration.GetSection(key).Get<string[]>() ?? [];
		foreach (var value in values.Where(value => !string.IsNullOrWhiteSpace(value)))
		{
			string? error = null;
			try
			{
				OpxIpMatcher.Create([value]);
			}
			catch (FormatException ex)
			{
				error = $"{key} has invalid value '{value}': {ex.Message}";
			}

			if (error is not null)
			{
				yield return error;
			}
		}
	}

	private static IEnumerable<string> ValidateSingleIp(IConfiguration configuration, string key)
	{
		var value = configuration.GetValue<string>(key);
		if (string.IsNullOrWhiteSpace(value))
		{
			yield break;
		}

		string? error = null;
		try
		{
			OpxIpMatcher.Create([value]);
		}
		catch (FormatException ex)
		{
			error = $"{key} has invalid value '{value}': {ex.Message}";
		}

		if (error is not null)
		{
			yield return error;
		}
	}

	private static bool CanCompileRegex(string pattern, int timeoutMs)
	{
		try
		{
			_ = new Regex(pattern, RegexOptions.IgnoreCase | RegexOptions.CultureInvariant, TimeSpan.FromMilliseconds(timeoutMs));
			return true;
		}
		catch (ArgumentException)
		{
			return false;
		}
	}

	private static double ReadSlowRequestMilliseconds(IConfiguration configuration)
	{
		return configuration.GetValue<double?>("OpxApiProtection:SuspiciousTraffic:SlowResponseMilliseconds")
			?? configuration.GetValue<double?>("OpxApiProtection:SuspiciousTraffic:SlowRequestMilliseconds")
			?? configuration.GetValue<double?>("OpxApiProtection:SuspiciousTraffic:SlowResponseMs")
			?? configuration.GetValue("OpxApiProtection:SuspiciousTraffic:SlowRequestMs", 0d);
	}

	private static bool IsOneOf(string value, params string[] allowed)
	{
		return allowed.Any(item => string.Equals(item, value, StringComparison.OrdinalIgnoreCase));
	}

	private static bool IsValidHeaderName(string value)
	{
		return value.Length is > 0 and <= 128 && value.All(character =>
			char.IsAsciiLetterOrDigit(character)
			|| character is '!' or '#' or '$' or '%' or '&' or '\'' or '*' or '+' or '-' or '.' or '^' or '_' or '`' or '|' or '~');
	}
}
