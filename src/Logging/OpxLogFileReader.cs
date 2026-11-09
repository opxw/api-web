// Copyright (c) 2026 - opx
namespace Opx.Api.Web.Logs;

public sealed class OpxLogFileReader
{
	private readonly IConfiguration _configuration;
	private readonly IWebHostEnvironment _environment;

	public OpxLogFileReader(IConfiguration configuration, IWebHostEnvironment environment)
	{
		_configuration = configuration;
		_environment = environment;
	}

	public OpxLogFileReadResult ReadAccessLog(string? date = null, int take = 100)
	{
		var path = _configuration.GetValue("OpxApiProtection:AccessLog:FilePath", "logs/access-log-{date}.log");
		return Read(path, date, take);
	}

	public OpxLogFileReadResult ReadSecurityIssueLog(string? date = null, int take = 100)
	{
		var path = _configuration.GetValue("OpxApiProtection:SecurityIssueLog:FilePath", "logs/security-issue-log-{date}.log");
		return Read(path, date, take);
	}

	private OpxLogFileReadResult Read(string? configuredPath, string? date, int take)
	{
		var logDate = string.IsNullOrWhiteSpace(date) ? DateTime.Now.ToString("yyyyMMdd") : date.Trim();
		if (!DateTime.TryParseExact(logDate, "yyyyMMdd", null, System.Globalization.DateTimeStyles.None, out _))
		{
			throw new ArgumentException("Date must use yyyyMMdd format.", nameof(date));
		}

		var path = (configuredPath ?? string.Empty).Replace("{date}", logDate, StringComparison.OrdinalIgnoreCase);
		if (!Path.IsPathRooted(path))
		{
			path = Path.Combine(_environment.ContentRootPath, path);
		}

		var lines = File.Exists(path)
			? File.ReadLines(path).TakeLast(Math.Clamp(take, 1, 10000)).ToArray()
			: [];
		return new OpxLogFileReadResult(lines);
	}
}

public sealed record OpxLogFileReadResult(IReadOnlyList<string> Lines);
