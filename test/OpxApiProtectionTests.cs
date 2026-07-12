// Copyright (c) 2026 - opx
using System.Diagnostics;
using System.Net;
using System.Text.Json;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.FileProviders;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging.Abstractions;
using NUnit.Framework;
using Opx.Api.Web.Controllers;
using Opx.Api.Web.Logs;
using Opx.Api.Web.Middlewares;

namespace Opx.Api.Web.Tests;

[TestFixture]
public class OpxApiProtectionTests
{
	[Test]
	public async Task SecurityHeaders_AddsExpectedHeaders()
	{
		var context = CreateContext();
		var middleware = new OpxSecurityHeadersMiddleware(
			_ =>
			{
				context.Response.Headers.Server = "Kestrel";
				context.Response.Headers["X-Powered-By"] = "ASP.NET";
				return Task.CompletedTask;
			},
			CreateConfiguration(new Dictionary<string, string?>
			{
				["OpxApiProtection:SecurityHeaders:Enabled"] = "true"
			}));

		await middleware.InvokeAsync(context);
		await context.Response.StartAsync();

		Assert.Multiple(() =>
		{
			Assert.That(context.Response.Headers["X-Content-Type-Options"].ToString(), Is.EqualTo("nosniff"));
			Assert.That(context.Response.Headers["Referrer-Policy"].ToString(), Is.EqualTo("no-referrer"));
			Assert.That(context.Response.Headers["X-Frame-Options"].ToString(), Is.EqualTo("DENY"));
			Assert.That(context.Response.Headers.ContainsKey("Server"), Is.False);
			Assert.That(context.Response.Headers.ContainsKey("X-Powered-By"), Is.False);
		});
	}

	[Test]
	public async Task SuspiciousTrafficGuard_WhenPathMatchesPattern_WritesBlockedResponse()
	{
		var context = CreateContext();
		context.Request.Path = "/.env";
		var middleware = new OpxSuspiciousTrafficGuardMiddleware(
			_ => Task.CompletedTask,
			CreateConfiguration(new Dictionary<string, string?>
			{
				["OpxApiProtection:SuspiciousTraffic:Enabled"] = "true",
				["OpxApiProtection:SuspiciousTraffic:Block"] = "true"
			}),
			new TestWebHostEnvironment(Path.GetTempPath()),
			NullLogger<OpxSuspiciousTrafficGuardMiddleware>.Instance);

		await middleware.InvokeAsync(context);
		var response = await ReadResponseAsync(context);

		Assert.Multiple(() =>
		{
			Assert.That(context.Response.StatusCode, Is.EqualTo(StatusCodes.Status200OK));
			Assert.That(response.GetProperty("result").GetBoolean(), Is.False);
			Assert.That(response.GetProperty("statusCode").GetString(), Is.EqualTo(((int)HttpStatusCode.BadRequest).ToString()));
			Assert.That(response.GetProperty("data").GetProperty("message").GetString(), Is.EqualTo("Suspicious traffic detected"));
			Assert.That(context.Items["OpxSuspiciousReason"], Is.EqualTo(".env"));
		});
	}

	[Test]
	public async Task RateLimiting_WhenLimitExceeded_WritesTooManyRequestsResponse()
	{
		var configuration = CreateConfiguration(new Dictionary<string, string?>
		{
			["OpxApiProtection:RateLimiting:Enabled"] = "true",
			["OpxApiProtection:RateLimiting:Limit"] = "1",
			["OpxApiProtection:RateLimiting:WindowSeconds"] = "60"
		});

		var firstContext = CreateContext();
		firstContext.Request.Path = "/artists";
		firstContext.Connection.RemoteIpAddress = IPAddress.Parse("127.0.0.10");
		var secondContext = CreateContext();
		secondContext.Request.Path = "/artists";
		secondContext.Connection.RemoteIpAddress = IPAddress.Parse("127.0.0.10");
		var middleware = new OpxRateLimitingMiddleware(_ => Task.CompletedTask, configuration);

		await middleware.InvokeAsync(firstContext);
		await middleware.InvokeAsync(secondContext);
		var response = await ReadResponseAsync(secondContext);

		Assert.Multiple(() =>
		{
			Assert.That(firstContext.Response.Headers["RateLimit-Remaining"].ToString(), Is.EqualTo("0"));
			Assert.That(secondContext.Response.StatusCode, Is.EqualTo(StatusCodes.Status200OK));
			Assert.That(secondContext.Response.Headers["Retry-After"].ToString(), Is.Not.Empty);
			Assert.That(response.GetProperty("result").GetBoolean(), Is.False);
			Assert.That(response.GetProperty("statusCode").GetString(), Is.EqualTo(((int)HttpStatusCode.TooManyRequests).ToString()));
			Assert.That(response.GetProperty("data").GetProperty("message").GetString(), Is.EqualTo("Too Many Requests"));
		});
	}

	[Test]
	public async Task SuspiciousTrafficGuard_WithFiveHundredConcurrentRequests_CompletesWithinOneSecond()
	{
		const int requestCount = 500;
		var configuration = CreateConfiguration(new Dictionary<string, string?>
		{
			["OpxApiProtection:SuspiciousTraffic:Enabled"] = "true",
			["OpxApiProtection:SuspiciousTraffic:Block"] = "true"
		});
		var middleware = new OpxSuspiciousTrafficGuardMiddleware(
			_ => Task.CompletedTask,
			configuration,
			new TestWebHostEnvironment(Path.GetTempPath()),
			NullLogger<OpxSuspiciousTrafficGuardMiddleware>.Instance);
		var stopwatch = Stopwatch.StartNew();

		var tasks = Enumerable.Range(0, requestCount).Select(async index =>
		{
			var context = CreateContext();
			context.Request.Path = $"/scan-{index}/.env";

			await middleware.InvokeAsync(context);
			var response = await ReadResponseAsync(context);

			Assert.Multiple(() =>
			{
				Assert.That(context.Response.StatusCode, Is.EqualTo(StatusCodes.Status200OK));
				Assert.That(response.GetProperty("result").GetBoolean(), Is.False);
				Assert.That(response.GetProperty("statusCode").GetString(), Is.EqualTo(((int)HttpStatusCode.BadRequest).ToString()));
				Assert.That(context.Items["OpxSuspiciousReason"], Is.EqualTo(".env"));
			});
		});

		await Task.WhenAll(tasks);
		stopwatch.Stop();

		Assert.That(stopwatch.ElapsedMilliseconds, Is.LessThan(1000));
	}

	[Test]
	public async Task RateLimiting_WithFiveHundredConcurrentRequests_CompletesWithinOneSecond()
	{
		const int requestCount = 500;
		const int limit = 250;
		var path = $"/rate-stress-{Guid.NewGuid():N}";
		var configuration = CreateConfiguration(new Dictionary<string, string?>
		{
			["OpxApiProtection:RateLimiting:Enabled"] = "true",
			["OpxApiProtection:RateLimiting:Limit"] = limit.ToString(),
			["OpxApiProtection:RateLimiting:WindowSeconds"] = "60"
		});
		var middleware = new OpxRateLimitingMiddleware(_ => Task.CompletedTask, configuration);
		var allowed = 0;
		var blocked = 0;
		var stopwatch = Stopwatch.StartNew();

		var tasks = Enumerable.Range(0, requestCount).Select(async _ =>
		{
			var context = CreateContext();
			context.Request.Path = path;
			context.Connection.RemoteIpAddress = IPAddress.Parse("127.0.0.20");

			await middleware.InvokeAsync(context);

			if (context.Response.Headers.ContainsKey("Retry-After"))
			{
				var response = await ReadResponseAsync(context);
				Assert.That(response.GetProperty("statusCode").GetString(), Is.EqualTo(((int)HttpStatusCode.TooManyRequests).ToString()));
				Interlocked.Increment(ref blocked);
				return;
			}

			Interlocked.Increment(ref allowed);
		});

		await Task.WhenAll(tasks);
		stopwatch.Stop();

		Assert.Multiple(() =>
		{
			Assert.That(allowed, Is.EqualTo(limit));
			Assert.That(blocked, Is.EqualTo(requestCount - limit));
			Assert.That(stopwatch.ElapsedMilliseconds, Is.LessThan(1000));
		});
	}

	[Test]
	public async Task LogsController_Access_WhenEnabled_ReturnsAccessLogLines()
	{
		var root = CreateTempDirectory();
		var date = DateTime.Now.ToString("yyyyMMdd");
		var logPath = Path.Combine(root, "logs", $"access-log-{date}.log");
		Directory.CreateDirectory(Path.GetDirectoryName(logPath)!);
		await File.WriteAllLinesAsync(logPath, ["line-1", "line-2", "line-3"]);
		var configuration = CreateConfiguration(new Dictionary<string, string?>
		{
			["OpxApiProtection:LogApi:Enabled"] = "true",
			["OpxApiProtection:AccessLog:FilePath"] = "logs/access-log-{date}.log"
		});
		var controller = CreateLogsController(configuration, root);

		try
		{
			await controller.Access(date, 2);
			var response = await ReadResponseAsync(controller.HttpContext);
			var lines = response.GetProperty("data").GetProperty("Lines").EnumerateArray().Select(line => line.GetString()).ToList();

			Assert.Multiple(() =>
			{
				Assert.That(response.GetProperty("result").GetBoolean(), Is.True);
				Assert.That(lines, Is.EqualTo(new[] { "line-2", "line-3" }));
			});
		}
		finally
		{
			Directory.Delete(root, true);
		}
	}

	[Test]
	public async Task LogsController_SecurityIssues_WhenEnabled_ReturnsSecurityIssueLogLines()
	{
		var root = CreateTempDirectory();
		var date = DateTime.Now.ToString("yyyyMMdd");
		var logPath = Path.Combine(root, "logs", $"security-issue-log-{date}.log");
		Directory.CreateDirectory(Path.GetDirectoryName(logPath)!);
		await File.WriteAllLinesAsync(logPath, ["issue-1", "issue-2"]);
		var configuration = CreateConfiguration(new Dictionary<string, string?>
		{
			["OpxApiProtection:LogApi:Enabled"] = "true",
			["OpxApiProtection:SecurityIssueLog:FilePath"] = "logs/security-issue-log-{date}.log"
		});
		var controller = CreateLogsController(configuration, root);

		try
		{
			await controller.SecurityIssues(date, 10);
			var response = await ReadResponseAsync(controller.HttpContext);
			var lines = response.GetProperty("data").GetProperty("Lines").EnumerateArray().Select(line => line.GetString()).ToList();

			Assert.Multiple(() =>
			{
				Assert.That(response.GetProperty("result").GetBoolean(), Is.True);
				Assert.That(lines, Is.EqualTo(new[] { "issue-1", "issue-2" }));
			});
		}
		finally
		{
			Directory.Delete(root, true);
		}
	}

	private static DefaultHttpContext CreateContext()
	{
		return new DefaultHttpContext
		{
			Response =
			{
				Body = new MemoryStream()
			}
		};
	}

	private static IConfiguration CreateConfiguration(Dictionary<string, string?> values)
	{
		return new ConfigurationBuilder()
			.AddInMemoryCollection(values)
			.Build();
	}

	private static async Task<JsonElement> ReadResponseAsync(HttpContext context)
	{
		context.Response.Body.Position = 0;
		using var document = await JsonDocument.ParseAsync(context.Response.Body);
		return document.RootElement.Clone();
	}

	private static OpxLogsController CreateLogsController(IConfiguration configuration, string contentRootPath)
	{
		var context = CreateContext();
		var environment = new TestWebHostEnvironment(contentRootPath);
		return new OpxLogsController(configuration, new OpxLogFileReader(configuration, environment))
		{
			ControllerContext = new ControllerContext
			{
				HttpContext = context
			}
		};
	}

	private static string CreateTempDirectory()
	{
		var path = Path.Combine(Path.GetTempPath(), "opx-log-api-tests", Guid.NewGuid().ToString("N"));
		Directory.CreateDirectory(path);
		return path;
	}

	private sealed class TestWebHostEnvironment : IWebHostEnvironment
	{
		public TestWebHostEnvironment(string contentRootPath)
		{
			ContentRootPath = contentRootPath;
			WebRootPath = contentRootPath;
			ContentRootFileProvider = new PhysicalFileProvider(contentRootPath);
			WebRootFileProvider = ContentRootFileProvider;
		}

		public string ApplicationName { get; set; } = "Opx.Api.Web.Tests";
		public IFileProvider ContentRootFileProvider { get; set; }
		public string ContentRootPath { get; set; }
		public string EnvironmentName { get; set; } = "Development";
		public string WebRootPath { get; set; }
		public IFileProvider WebRootFileProvider { get; set; }
	}
}
