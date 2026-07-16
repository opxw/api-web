// Copyright (c) 2026 - opx
using System.Diagnostics;
using Opx.Api.Web.Protection;

namespace Opx.Api.Web.Middlewares;

public sealed class OpxAccessLogMiddleware
{
	private readonly IConfiguration _configuration;
	private readonly IWebHostEnvironment _environment;
	private readonly ILogger<OpxAccessLogMiddleware> _logger;
	private readonly RequestDelegate _next;

	public OpxAccessLogMiddleware(
		RequestDelegate next,
		IConfiguration configuration,
		IWebHostEnvironment environment,
		ILogger<OpxAccessLogMiddleware> logger)
	{
		_next = next;
		_configuration = configuration;
		_environment = environment;
		_logger = logger;
	}

	public async Task InvokeAsync(HttpContext context)
	{
		if (!_configuration.GetValue("OpxApiProtection:AccessLog:Enabled", false))
		{
			await _next(context);
			return;
		}

		var stopwatch = Stopwatch.StartNew();

		try
		{
			await _next(context);
		}
		finally
		{
			stopwatch.Stop();
			WriteLog(context, stopwatch.ElapsedMilliseconds);
		}
	}

	private void WriteLog(HttpContext context, long elapsedMilliseconds)
	{
		var clientIp = OpxClientIpResolver.ResolveDetails(context, _configuration);
		var message = $"Access {context.Request.Method} {context.Request.Path}{context.Request.QueryString} => {context.Response.StatusCode} in {elapsedMilliseconds} ms | IP={clientIp.Text} | PeerIP={clientIp.PeerText} | IPSource={clientIp.Source} | Host={context.Request.Host} | UserAgent={context.Request.Headers.UserAgent} | Suspicious={context.Items["OpxSuspiciousReason"] ?? "-"}";

		if (UseLoggerOutput())
		{
			_logger.LogInformation("{Message}", message);
		}

		if (UseFileOutput())
		{
			WriteFileLog(message);
		}
	}

	private bool UseLoggerOutput()
	{
		var output = _configuration.GetValue("OpxApiProtection:AccessLog:Output", "Logger");
		return output.Equals("Logger", StringComparison.OrdinalIgnoreCase)
			|| output.Equals("Both", StringComparison.OrdinalIgnoreCase);
	}

	private bool UseFileOutput()
	{
		var output = _configuration.GetValue("OpxApiProtection:AccessLog:Output", "Logger");
		return output.Equals("File", StringComparison.OrdinalIgnoreCase)
			|| output.Equals("Both", StringComparison.OrdinalIgnoreCase);
	}

	private void WriteFileLog(string message)
	{
		var configuredPath = _configuration.GetValue("OpxApiProtection:AccessLog:FilePath", "logs/access-log-{date}.log");
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
}
