// Copyright (c) 2026 - opx
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Opx.Api.Web.Common;
using Opx.Api.Web.Logs;

namespace Opx.Api.Web.Controllers;

[ApiController]
[Route("opx/logs")]
public sealed class OpxLogsController : OpxApiController
{
	private readonly IConfiguration _configuration;
	private readonly OpxLogFileReader _logFileReader;

	public OpxLogsController(IConfiguration configuration, OpxLogFileReader logFileReader)
	{
		_configuration = configuration;
		_logFileReader = logFileReader;
	}

	[HttpGet("access")]
	public async Task Access([FromQuery] string? date = null, [FromQuery] int take = 100)
	{
		if (!await EnsureAllowedAsync("AccessLog"))
		{
			return;
		}

		await OkAsync(_logFileReader.ReadAccessLog(date, take));
	}

	[HttpGet("security-issues")]
	public async Task SecurityIssues([FromQuery] string? date = null, [FromQuery] int take = 100)
	{
		if (!await EnsureAllowedAsync("SecurityIssueLog"))
		{
			return;
		}

		await OkAsync(_logFileReader.ReadSecurityIssueLog(date, take));
	}

	private async Task<bool> EnsureAllowedAsync(string objectName)
	{
		if (!_configuration.GetValue("OpxApiProtection:LogApi:Enabled", false))
		{
			await FailAsync(new ApiErrorValue
			{
				Message = "Log API is disabled",
				Id = "LogApi",
				ObjectName = objectName
			}, StatusCodes.Status403Forbidden);
			return false;
		}

		if (_configuration.GetValue("OpxApiProtection:LogApi:RequireAuthorization", false)
			&& User.Identity?.IsAuthenticated != true)
		{
			await FailAsync(new ApiErrorValue
			{
				Message = "Unauthorized",
				Id = "LogApi",
				ObjectName = objectName
			}, StatusCodes.Status401Unauthorized);
			return false;
		}

		var requiredRole = _configuration.GetValue<string>("OpxApiProtection:LogApi:RequiredRole");
		if (!string.IsNullOrWhiteSpace(requiredRole)
			&& !requiredRole
				.Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
				.Any(User.IsInRole))
		{
			await FailAsync(new ApiErrorValue
			{
				Message = "Forbidden",
				Id = "LogApi",
				ObjectName = objectName
			}, StatusCodes.Status403Forbidden);
			return false;
		}

		var requiredPolicy = _configuration.GetValue<string>("OpxApiProtection:LogApi:RequiredPolicy");
		if (!string.IsNullOrWhiteSpace(requiredPolicy))
		{
			var authorizationService = HttpContext.RequestServices.GetService<IAuthorizationService>();
			if (authorizationService is null
				|| !(await authorizationService.AuthorizeAsync(User, requiredPolicy)).Succeeded)
			{
				await FailAsync(new ApiErrorValue
				{
					Message = "Forbidden",
					Id = "LogApi",
					ObjectName = objectName
				}, StatusCodes.Status403Forbidden);
				return false;
			}
		}

		return true;
	}
}
