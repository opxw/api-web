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
		if (!IsEnabled())
		{
			await FailAsync(new ApiErrorValue
			{
				Message = "Log API is disabled",
				Id = "LogApi",
				ObjectName = "AccessLog"
			}, StatusCodes.Status403Forbidden);
			return;
		}

		await OkAsync(_logFileReader.ReadAccessLog(date, take));
	}

	[HttpGet("security-issues")]
	public async Task SecurityIssues([FromQuery] string? date = null, [FromQuery] int take = 100)
	{
		if (!IsEnabled())
		{
			await FailAsync(new ApiErrorValue
			{
				Message = "Log API is disabled",
				Id = "LogApi",
				ObjectName = "SecurityIssueLog"
			}, StatusCodes.Status403Forbidden);
			return;
		}

		await OkAsync(_logFileReader.ReadSecurityIssueLog(date, take));
	}

	private bool IsEnabled()
	{
		return _configuration.GetValue("OpxApiProtection:LogApi:Enabled", false);
	}
}

