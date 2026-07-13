// Copyright (c) 2026 - opx
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Opx.Api.Web.Common;
using Opx.Api.Web.Logs;
using Opx.Api.Web.Protection;

namespace Opx.Api.Web.Controllers;

[ApiController]
[Route("opx/protection")]
public sealed class OpxProtectionController : OpxApiController
{
	private readonly IConfiguration _configuration;
	private readonly OpxProtectionMetrics _metrics;
	private readonly OpxSecurityIssueLogWriter _securityIssueLogWriter;

	public OpxProtectionController(
		IConfiguration configuration,
		OpxProtectionMetrics metrics,
		OpxSecurityIssueLogWriter securityIssueLogWriter)
	{
		_configuration = configuration;
		_metrics = metrics;
		_securityIssueLogWriter = securityIssueLogWriter;
	}

	[HttpGet("metrics")]
	public async Task Metrics()
	{
		if (!await EnsureAllowedAsync("MetricsApi"))
		{
			return;
		}

		await OkAsync(_metrics.Snapshot());
	}

	[HttpGet("health")]
	public async Task Health()
	{
		if (!await EnsureAllowedAsync("HealthApi"))
		{
			return;
		}

		await OkAsync(new
		{
			Status = _securityIssueLogWriter.DroppedCount == 0 ? "Healthy" : "Degraded",
			SecurityHeaders = _configuration.GetValue("OpxApiProtection:SecurityHeaders:Enabled", false),
			RateLimiting = _configuration.GetValue("OpxApiProtection:RateLimiting:Enabled", false),
			SuspiciousTraffic = _configuration.GetValue("OpxApiProtection:SuspiciousTraffic:Enabled", false),
			AuthorizationGuard = _configuration.GetValue("OpxApiProtection:AuthorizationGuard:Enabled", false),
			SecurityIssueLogDropped = _securityIssueLogWriter.DroppedCount,
			SecurityIssueLogQueueCapacity = _configuration.GetValue("OpxApiProtection:SecurityIssueLog:QueueCapacity", 8192),
			EndpointProxy = _configuration.GetValue("OpxEndpointProxy:Enabled", _configuration.GetValue("OpxApiProtection:EndpointProxy:Enabled", false))
		});
	}

	private async Task<bool> EnsureAllowedAsync(string objectName)
	{
		if (!_configuration.GetValue("OpxApiProtection:MetricsApi:Enabled", false))
		{
			await FailAsync(new ApiErrorValue
			{
				Message = "Protection API is disabled",
				Id = "ProtectionApi",
				ObjectName = objectName
			}, StatusCodes.Status403Forbidden);
			return false;
		}

		if (_configuration.GetValue("OpxApiProtection:MetricsApi:RequireAuthorization", false)
			&& User.Identity?.IsAuthenticated != true)
		{
			await FailAsync(new ApiErrorValue
			{
				Message = "Unauthorized",
				Id = "ProtectionApi",
				ObjectName = objectName
			}, StatusCodes.Status401Unauthorized);
			return false;
		}

		var requiredRole = _configuration.GetValue<string>("OpxApiProtection:MetricsApi:RequiredRole");
		if (!string.IsNullOrWhiteSpace(requiredRole)
			&& !requiredRole
				.Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
				.Any(User.IsInRole))
		{
			await FailAsync(new ApiErrorValue
			{
				Message = "Forbidden",
				Id = "ProtectionApi",
				ObjectName = objectName
			}, StatusCodes.Status403Forbidden);
			return false;
		}

		var requiredPolicy = _configuration.GetValue<string>("OpxApiProtection:MetricsApi:RequiredPolicy");
		if (!string.IsNullOrWhiteSpace(requiredPolicy))
		{
			var authorizationService = HttpContext.RequestServices.GetService<IAuthorizationService>();
			if (authorizationService is null
				|| !(await authorizationService.AuthorizeAsync(User, requiredPolicy)).Succeeded)
			{
				await FailAsync(new ApiErrorValue
				{
					Message = "Forbidden",
					Id = "ProtectionApi",
					ObjectName = objectName
				}, StatusCodes.Status403Forbidden);
				return false;
			}
		}

		return true;
	}
}
