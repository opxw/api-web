// Copyright (c) 2026 - opx
using System.Net;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Authorization;
using Microsoft.Extensions.Primitives;
using Opx.Api.Web.Common;
using Opx.Api.Web.Protection;

namespace Opx.Api.Web.Middlewares;

public sealed class OpxAuthorizationGuardMiddleware
{
	private readonly IConfiguration _configuration;
	private readonly OpxProtectionMetrics? _metrics;
	private readonly OpxProtectionPolicyProvider? _policyProvider;
	private readonly RequestDelegate _next;
	private readonly object _settingsLock = new();
	private AuthorizationGuardSettings? _settings;
	private IChangeToken? _changeToken;

	public OpxAuthorizationGuardMiddleware(
		RequestDelegate next,
		IConfiguration configuration,
		OpxProtectionMetrics? metrics = null,
		OpxProtectionPolicyProvider? policyProvider = null)
	{
		_next = next;
		_configuration = configuration;
		_metrics = metrics;
		_policyProvider = policyProvider;
	}

	public async Task InvokeAsync(HttpContext context)
	{
		var policy = _policyProvider?.GetPolicy(context.Request.Path) ?? OpxProtectionPolicy.Empty;
		var settings = GetSettings();
		if (!settings.Enabled
			|| policy.SkipAuthorization
			|| IsExcluded(context.Request.Path, settings.ExcludedPathPrefixes)
			|| HasAllowAnonymous(context))
		{
			if (settings.Enabled)
			{
				_metrics?.IncrementAuthorizationBypassed();
			}

			await _next(context);
			return;
		}

		var result = await context.AuthenticateAsync(JwtBearerDefaults.AuthenticationScheme);
		if (!result.Succeeded || result.Principal?.Identity?.IsAuthenticated != true)
		{
			_metrics?.IncrementAuthorizationBlocked();
			await ApiResponseObjectValue.ShowErrorResponseAsync(context, (int)HttpStatusCode.Unauthorized, new ApiErrorValue
			{
				Message = "Unauthorized",
				Id = "AuthorizationGuard",
				ObjectName = context.Request.Path.ToString()
			});
			return;
		}

		context.User = result.Principal;
		await _next(context);
	}

	private AuthorizationGuardSettings GetSettings()
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

			var prefixes = (_configuration
				.GetSection("OpxApiProtection:AuthorizationGuard:ExcludedPathPrefixes")
				.Get<string[]>()
				?? ["/health", "/swagger", "/openapi"])
				.Concat(_configuration.GetSection("OpxApiProtection:AuthorizationGuard:WhitelistedPathPrefixes").Get<string[]>() ?? [])
				.Where(prefix => !string.IsNullOrWhiteSpace(prefix))
				.Select(prefix => new PathString(prefix))
				.ToArray();

			_settings = new AuthorizationGuardSettings(
				_configuration.GetValue("OpxApiProtection:AuthorizationGuard:Enabled", false),
				prefixes);
			_changeToken = currentToken;
			return _settings;
		}
	}

	private static bool IsExcluded(PathString path, PathString[] prefixes)
	{
		return prefixes.Any(path.StartsWithSegments);
	}

	private static bool HasAllowAnonymous(HttpContext context)
	{
		return context.GetEndpoint()?.Metadata.GetMetadata<IAllowAnonymous>() is not null;
	}

	private sealed record AuthorizationGuardSettings(
		bool Enabled,
		PathString[] ExcludedPathPrefixes);
}
