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
		foreach (var error in ValidateIpList(configuration, "OpxApiProtection:SuspiciousTraffic:AllowedIpAddresses"))
		{
			yield return error;
		}

		foreach (var error in ValidateIpList(configuration, "OpxApiProtection:SuspiciousTraffic:DeniedIpAddresses"))
		{
			yield return error;
		}

		var logFormat = configuration.GetValue("OpxApiProtection:SecurityIssueLog:Format", "Text") ?? "Text";
		if (!IsOneOf(logFormat, "Text", "JsonLines"))
		{
			yield return "OpxApiProtection:SecurityIssueLog:Format must be Text or JsonLines.";
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

	private static bool IsOneOf(string value, params string[] allowed)
	{
		return allowed.Any(item => string.Equals(item, value, StringComparison.OrdinalIgnoreCase));
	}
}
