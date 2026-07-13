// Copyright (c) 2026 - opx
using Opx.Api.Web.Logs;
using Opx.Api.Web.Protection;

namespace Opx.Api.Web.Middlewares;

public sealed class OpxApiProtectionFastMiddleware
{
	private readonly OpxSecurityHeadersMiddleware _pipeline;

	public OpxApiProtectionFastMiddleware(
		RequestDelegate next,
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
		_pipeline = new OpxSecurityHeadersMiddleware(rateLimiting.InvokeAsync, configuration);
	}

	public Task InvokeAsync(HttpContext context)
	{
		return _pipeline.InvokeAsync(context);
	}
}
