// Copyright (c) 2026 - opx
using Opx.Api.Web.Logs;
using Opx.Api.Web.Protection;

namespace Opx.Api.Web.Middlewares;

public sealed class OpxApiProtectionFastMiddleware
{
	private readonly RequestDelegate _pipeline;

	public OpxApiProtectionFastMiddleware(
		RequestDelegate next,
		IConfiguration configuration,
		IWebHostEnvironment environment,
		ILogger<OpxSuspiciousTrafficGuardMiddleware> suspiciousLogger,
		OpxProtectionMetrics? metrics = null,
		OpxProtectionPolicyProvider? policyProvider = null,
		OpxSecurityIssueLogWriter? securityIssueLogWriter = null)
		: this(
			next,
			includeSecurityHeaders: true,
			configuration,
			environment,
			suspiciousLogger,
			metrics,
			policyProvider,
			securityIssueLogWriter)
	{
	}

	public OpxApiProtectionFastMiddleware(
		RequestDelegate next,
		bool includeSecurityHeaders,
		IConfiguration configuration,
		IWebHostEnvironment environment,
		ILogger<OpxSuspiciousTrafficGuardMiddleware> suspiciousLogger,
		OpxProtectionMetrics? metrics = null,
		OpxProtectionPolicyProvider? policyProvider = null,
		OpxSecurityIssueLogWriter? securityIssueLogWriter = null)
	{
		var authorization = new OpxAuthorizationGuardMiddleware(next, configuration, metrics, policyProvider);
		var suspicious = new OpxSuspiciousTrafficGuardMiddleware(
			authorization.InvokeAsync,
			configuration,
			environment,
			suspiciousLogger,
			securityIssueLogWriter,
			metrics,
			policyProvider);
		var rateLimiting = new OpxRateLimitingMiddleware(suspicious.InvokeAsync, configuration, metrics, policyProvider);
		_pipeline = includeSecurityHeaders
			? new OpxSecurityHeadersMiddleware(rateLimiting.InvokeAsync, configuration).InvokeAsync
			: rateLimiting.InvokeAsync;
	}

	public Task InvokeAsync(HttpContext context)
	{
		return _pipeline(context);
	}
}
