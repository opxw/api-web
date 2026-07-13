// Copyright (c) 2026 - opx
using Microsoft.Extensions.Primitives;

namespace Opx.Api.Web.Protection;

public sealed class OpxProtectionPolicyProvider
{
	private readonly IConfiguration _configuration;
	private IChangeToken? _changeToken;
	private OpxProtectionPolicy[]? _policies;
	private readonly object _settingsLock = new();

	public OpxProtectionPolicyProvider(IConfiguration configuration)
	{
		_configuration = configuration;
	}

	public OpxProtectionPolicy GetPolicy(PathString path)
	{
		var pathValue = path.ToString();
		foreach (var policy in GetPolicies())
		{
			if (pathValue.StartsWith(policy.PathPrefix, StringComparison.OrdinalIgnoreCase))
			{
				return policy;
			}
		}

		return OpxProtectionPolicy.Empty;
	}

	private OpxProtectionPolicy[] GetPolicies()
	{
		var currentToken = _configuration.GetReloadToken();
		if (_policies is not null && ReferenceEquals(_changeToken, currentToken) && !currentToken.HasChanged)
		{
			return _policies;
		}

		lock (_settingsLock)
		{
			currentToken = _configuration.GetReloadToken();
			if (_policies is not null && ReferenceEquals(_changeToken, currentToken) && !currentToken.HasChanged)
			{
				return _policies;
			}

			_policies = (_configuration.GetSection("OpxApiProtection:Policies").Get<OpxProtectionPolicy[]>() ?? [])
				.Where(policy => !string.IsNullOrWhiteSpace(policy.PathPrefix))
				.OrderByDescending(policy => policy.PathPrefix.Length)
				.ToArray();
			_changeToken = currentToken;
			return _policies;
		}
	}
}

public sealed record OpxProtectionPolicy
{
	public static OpxProtectionPolicy Empty { get; } = new();

	public string PathPrefix { get; init; } = string.Empty;
	public bool SkipAuthorization { get; init; }
	public bool SkipRateLimiting { get; init; }
	public bool SkipSuspiciousTraffic { get; init; }
	public int? RateLimit { get; init; }
	public int? RateLimitWindowSeconds { get; init; }
}
