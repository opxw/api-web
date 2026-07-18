// Copyright (c) 2026 - opx
using System.Diagnostics;
using System.Net;
using System.Security.Claims;
using System.Text.Json;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.TestHost;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.FileProviders;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using NUnit.Framework;
using Opx.Api.Web.Common;
using Opx.Api.Web.Controllers;
using Opx.Api.Web.Logs;
using Opx.Api.Web.Middlewares;
using Opx.Api.Web.Protection;
using Opx.Web.Framework;
using Opx.Web.Framework.Options;

namespace Opx.Api.Web.Tests;

[TestFixture]
public class OpxApiProtectionTests
{
	[Test]
	public async Task StatusCodeHandler_WhenResponseHasStarted_DoesNotRewriteExistingBody()
	{
		var builder = WebApplication.CreateBuilder();
		builder.WebHost.UseTestServer();
		var app = builder.Build();
		app.Use(async (context, next) =>
		{
			await next();
			await ((WebApplication)null!).HandleUncatchedStatusCodeAsync(context);
		});
		app.Run(async context =>
		{
			context.Response.StatusCode = StatusCodes.Status401Unauthorized;
			context.Response.ContentType = "application/json";
			await context.Response.WriteAsync("{\"custom\":true}");
		});

		await app.StartAsync();
		try
		{
			using var response = await app.GetTestClient().GetAsync("/");

			Assert.Multiple(() =>
			{
				Assert.That(response.StatusCode, Is.EqualTo(HttpStatusCode.Unauthorized));
				Assert.That(response.Content.ReadAsStringAsync().Result, Is.EqualTo("{\"custom\":true}"));
			});
		}
		finally
		{
			await app.DisposeAsync();
		}
	}

	[Test]
	public async Task SecurityHeaders_AddsExpectedHeaders()
	{
		var context = CreateContext();
		var middleware = new OpxSecurityHeadersMiddleware(
			_ => Task.CompletedTask,
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
	public async Task ResponseHeaders_WhenExecutionTimeIsHidden_RemovesHeaderAddedByEndpoint()
	{
		var builder = WebApplication.CreateBuilder();
		builder.WebHost.UseTestServer();
		builder.Configuration.AddInMemoryCollection(new Dictionary<string, string?>
		{
			["OpxApiProtection:ResponseHeaders:ExposeExecutionTime"] = "false"
		});
		builder.Services.AddOpxApiWeb(builder.Configuration);
		var app = builder.Build();
		app.UseOpxSecurityHeaders();
		app.Run(context =>
		{
			context.Response.Headers["Execution-Time"] = "1.234";
			return context.Response.WriteAsync("ok");
		});

		await app.StartAsync();
		try
		{
			using var response = await app.GetTestClient().GetAsync("/");

			Assert.That(response.Headers.Contains("Execution-Time"), Is.False);
		}
		finally
		{
			await app.DisposeAsync();
		}
	}

	[Test]
	public async Task ApiProtectionFastMiddleware_WhenSuspiciousRequest_BlocksAndAddsSecurityHeaders()
	{
		var configuration = CreateConfiguration(new Dictionary<string, string?>
		{
			["OpxApiProtection:SecurityHeaders:Enabled"] = "true",
			["OpxApiProtection:SuspiciousTraffic:Enabled"] = "true"
		});
		var middleware = new OpxApiProtectionFastMiddleware(
			_ => Task.CompletedTask,
			configuration,
			new TestWebHostEnvironment(Path.GetTempPath()),
			NullLogger<OpxSuspiciousTrafficGuardMiddleware>.Instance);
		var context = CreateContext();
		context.Request.Path = "/.env";

		await middleware.InvokeAsync(context);
		var response = await ReadResponseAsync(context);

		Assert.Multiple(() =>
		{
			Assert.That(response.GetProperty("result").GetBoolean(), Is.False);
			Assert.That(context.Response.Headers["X-Content-Type-Options"].ToString(), Is.EqualTo("nosniff"));
		});
	}

	[Test]
	public async Task ApiProtectionFast_WhenRegisteredTwice_AddsEachSecurityHeaderOnce()
	{
		var builder = WebApplication.CreateBuilder();
		builder.WebHost.UseTestServer();
		builder.Services.AddOpxWebFramework();
		var app = builder.Build();
		app.UseOpxApiProtectionFast();
		app.UseOpxApiProtectionFast();
		app.Run(context => context.Response.WriteAsync("ok"));

		await app.StartAsync();
		try
		{
			using var response = await app.GetTestClient().GetAsync("/");

			Assert.Multiple(() =>
			{
				Assert.That(response.Headers.GetValues("X-Content-Type-Options").Single(), Is.EqualTo("nosniff"));
				Assert.That(response.Headers.GetValues("Referrer-Policy").Count(), Is.EqualTo(1));
				Assert.That(response.Headers.GetValues("X-Frame-Options").Count(), Is.EqualTo(1));
			});
		}
		finally
		{
			await app.DisposeAsync();
		}
	}

	[Test]
	public void ApiProtection_WhenNormalAndFastModesAreCombined_ThrowsAtStartup()
	{
		var services = new ServiceCollection()
			.AddOpxWebFramework()
			.BuildServiceProvider();
		var app = new ApplicationBuilder(services);
		app.UseOpxApiProtectionFast();

		var exception = Assert.Throws<InvalidOperationException>(() => app.UseOpxApiProtection());

		Assert.That(exception!.Message, Does.Contain("cannot be combined"));
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
	public async Task SuspiciousTrafficGuard_WhenPathIsExcluded_SkipsScan()
	{
		var context = CreateContext();
		context.Request.Path = "/health/.env";
		var nextCalled = false;
		var middleware = new OpxSuspiciousTrafficGuardMiddleware(
			_ =>
			{
				nextCalled = true;
				return Task.CompletedTask;
			},
			CreateConfiguration(new Dictionary<string, string?>
			{
				["OpxApiProtection:SuspiciousTraffic:Enabled"] = "true",
				["OpxApiProtection:SuspiciousTraffic:Block"] = "true",
				["OpxApiProtection:SuspiciousTraffic:ExcludedPathPrefixes:0"] = "/health"
			}),
			new TestWebHostEnvironment(Path.GetTempPath()),
			NullLogger<OpxSuspiciousTrafficGuardMiddleware>.Instance);

		await middleware.InvokeAsync(context);

		Assert.Multiple(() =>
		{
			Assert.That(nextCalled, Is.True);
			Assert.That(context.Items.ContainsKey("OpxSuspiciousReason"), Is.False);
		});
	}

	[Test]
	public async Task SuspiciousTrafficGuard_WhenDefaultPatternsDisabled_DoesNotRestoreRemovedPattern()
	{
		var nextCalled = false;
		var middleware = new OpxSuspiciousTrafficGuardMiddleware(
			_ =>
			{
				nextCalled = true;
				return Task.CompletedTask;
			},
			CreateConfiguration(new Dictionary<string, string?>
			{
				["OpxApiProtection:SuspiciousTraffic:Enabled"] = "true",
				["OpxApiProtection:SuspiciousTraffic:Block"] = "true",
				["OpxApiProtection:SuspiciousTraffic:UseDefaultPatterns"] = "false",
				["OpxApiProtection:SuspiciousTraffic:Patterns:0"] = "sqlmap"
			}),
			new TestWebHostEnvironment(Path.GetTempPath()),
			NullLogger<OpxSuspiciousTrafficGuardMiddleware>.Instance);
		var context = CreateContext();
		context.Request.Path = "/.env";

		await middleware.InvokeAsync(context);

		Assert.Multiple(() =>
		{
			Assert.That(nextCalled, Is.True);
			Assert.That(context.Items.ContainsKey("OpxSuspiciousReason"), Is.False);
		});
	}

	[Test]
	public async Task SuspiciousTrafficGuard_WhenPathIsOutsideProtectedPrefixes_SkipsScan()
	{
		var nextCalled = false;
		var middleware = new OpxSuspiciousTrafficGuardMiddleware(
			_ =>
			{
				nextCalled = true;
				return Task.CompletedTask;
			},
			CreateConfiguration(new Dictionary<string, string?>
			{
				["OpxApiProtection:SuspiciousTraffic:Enabled"] = "true",
				["OpxApiProtection:SuspiciousTraffic:ProtectedPathPrefixes:0"] = "/api"
			}),
			new TestWebHostEnvironment(Path.GetTempPath()),
			NullLogger<OpxSuspiciousTrafficGuardMiddleware>.Instance);
		var context = CreateContext();
		context.Request.Path = "/public/.env";

		await middleware.InvokeAsync(context);

		Assert.Multiple(() =>
		{
			Assert.That(nextCalled, Is.True);
			Assert.That(context.Items.ContainsKey("OpxSuspiciousReason"), Is.False);
		});
	}

	[Test]
	public async Task SuspiciousTrafficGuard_WhenPathIsInsideProtectedPrefixes_BlocksMatch()
	{
		var middleware = new OpxSuspiciousTrafficGuardMiddleware(
			_ => Task.CompletedTask,
			CreateConfiguration(new Dictionary<string, string?>
			{
				["OpxApiProtection:SuspiciousTraffic:Enabled"] = "true",
				["OpxApiProtection:SuspiciousTraffic:ProtectedPathPrefixes:0"] = "/api"
			}),
			new TestWebHostEnvironment(Path.GetTempPath()),
			NullLogger<OpxSuspiciousTrafficGuardMiddleware>.Instance);
		var context = CreateContext();
		context.Request.Path = "/api/.env";

		await middleware.InvokeAsync(context);

		Assert.That(context.Items["OpxSuspiciousReason"], Is.EqualTo(".env"));
	}

	[Test]
	public async Task SuspiciousTrafficGuard_WhenProtectedPathIsRemovedOnReload_StopsScanningIt()
	{
		var configuration = CreateConfiguration(new Dictionary<string, string?>
		{
			["OpxApiProtection:SuspiciousTraffic:Enabled"] = "true",
			["OpxApiProtection:SuspiciousTraffic:ProtectedPathPrefixes:0"] = "/api",
			["OpxApiProtection:SuspiciousTraffic:ProtectedPathPrefixes:1"] = "/admin"
		});
		var nextCalls = 0;
		var middleware = new OpxSuspiciousTrafficGuardMiddleware(
			_ =>
			{
				Interlocked.Increment(ref nextCalls);
				return Task.CompletedTask;
			},
			configuration,
			new TestWebHostEnvironment(Path.GetTempPath()),
			NullLogger<OpxSuspiciousTrafficGuardMiddleware>.Instance);
		var protectedContext = CreateContext();
		protectedContext.Request.Path = "/admin/.env";

		await middleware.InvokeAsync(protectedContext);
		configuration["OpxApiProtection:SuspiciousTraffic:ProtectedPathPrefixes:1"] = null;
		((IConfigurationRoot)configuration).Reload();
		var removedContext = CreateContext();
		removedContext.Request.Path = "/admin/.env";

		await middleware.InvokeAsync(removedContext);

		Assert.Multiple(() =>
		{
			Assert.That(protectedContext.Items["OpxSuspiciousReason"], Is.EqualTo(".env"));
			Assert.That(removedContext.Items.ContainsKey("OpxSuspiciousReason"), Is.False);
			Assert.That(nextCalls, Is.EqualTo(1));
		});
	}

	[Test]
	public async Task SuspiciousTrafficGuard_WhenLastProtectedPathIsRemovedAndScanAllDisabled_SkipsScan()
	{
		var configuration = CreateConfiguration(new Dictionary<string, string?>
		{
			["OpxApiProtection:SuspiciousTraffic:Enabled"] = "true",
			["OpxApiProtection:SuspiciousTraffic:ScanAllPaths"] = "false",
			["OpxApiProtection:SuspiciousTraffic:ProtectedPathPrefixes:0"] = "/admin"
		});
		var nextCalls = 0;
		var middleware = new OpxSuspiciousTrafficGuardMiddleware(
			_ =>
			{
				Interlocked.Increment(ref nextCalls);
				return Task.CompletedTask;
			},
			configuration,
			new TestWebHostEnvironment(Path.GetTempPath()),
			NullLogger<OpxSuspiciousTrafficGuardMiddleware>.Instance);
		configuration["OpxApiProtection:SuspiciousTraffic:ProtectedPathPrefixes:0"] = null;
		((IConfigurationRoot)configuration).Reload();
		var context = CreateContext();
		context.Request.Path = "/admin/.env";

		await middleware.InvokeAsync(context);

		Assert.Multiple(() =>
		{
			Assert.That(context.Items.ContainsKey("OpxSuspiciousReason"), Is.False);
			Assert.That(nextCalls, Is.EqualTo(1));
		});
	}

	[Test]
	public async Task SuspiciousTrafficGuard_WhenMinimalBlockedResponseMode_WritesCompactResponse()
	{
		var context = CreateContext();
		context.Request.Path = "/.env";
		var middleware = new OpxSuspiciousTrafficGuardMiddleware(
			_ => Task.CompletedTask,
			CreateConfiguration(new Dictionary<string, string?>
			{
				["OpxApiProtection:SuspiciousTraffic:Enabled"] = "true",
				["OpxApiProtection:SuspiciousTraffic:Block"] = "true",
				["OpxApiProtection:SuspiciousTraffic:BlockedResponseMode"] = "Minimal"
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
			Assert.That(response.GetProperty("data").GetString(), Is.EqualTo("Suspicious traffic detected"));
		});
	}

	[Test]
	public async Task SuspiciousTrafficGuard_WhenWrappedFastBlockedResponseMode_WritesWrappedResponse()
	{
		var middleware = new OpxSuspiciousTrafficGuardMiddleware(
			_ => Task.CompletedTask,
			CreateConfiguration(new Dictionary<string, string?>
			{
				["OpxApiProtection:SuspiciousTraffic:Enabled"] = "true",
				["OpxApiProtection:SuspiciousTraffic:Block"] = "true",
				["OpxApiProtection:SuspiciousTraffic:BlockedResponseMode"] = "WrappedFast"
			}),
			new TestWebHostEnvironment(Path.GetTempPath()),
			NullLogger<OpxSuspiciousTrafficGuardMiddleware>.Instance);
		var context = CreateContext();
		context.Request.Path = "/.env";

		await middleware.InvokeAsync(context);
		var response = await ReadResponseAsync(context);

		Assert.Multiple(() =>
		{
			Assert.That(context.Response.StatusCode, Is.EqualTo(StatusCodes.Status200OK));
			Assert.That(response.GetProperty("result").GetBoolean(), Is.False);
			Assert.That(response.GetProperty("statusCode").GetString(), Is.EqualTo(((int)HttpStatusCode.BadRequest).ToString()));
			Assert.That(response.GetProperty("data").GetProperty("message").GetString(), Is.EqualTo("Suspicious traffic detected"));
			Assert.That(response.GetProperty("data").GetProperty("id").GetString(), Is.EqualTo("SuspiciousTraffic"));
		});
	}

	[Test]
	public async Task SuspiciousTrafficGuard_WhenBlockedResponseModeNotConfigured_UsesWrappedFast()
	{
		var middleware = new OpxSuspiciousTrafficGuardMiddleware(
			_ => Task.CompletedTask,
			CreateConfiguration(new Dictionary<string, string?>
			{
				["OpxApiProtection:SuspiciousTraffic:Enabled"] = "true",
				["OpxApiProtection:SuspiciousTraffic:Block"] = "true"
			}),
			new TestWebHostEnvironment(Path.GetTempPath()),
			NullLogger<OpxSuspiciousTrafficGuardMiddleware>.Instance);
		var context = CreateContext();
		context.Request.Path = "/.env";

		await middleware.InvokeAsync(context);
		var response = await ReadResponseAsync(context);

		Assert.Multiple(() =>
		{
			Assert.That(response.GetProperty("result").GetBoolean(), Is.False);
			Assert.That(response.GetProperty("data").GetProperty("id").GetString(), Is.EqualTo("SuspiciousTraffic"));
			Assert.That(response.GetProperty("data").GetProperty("objectName").GetString(), Is.EqualTo("Request"));
		});
	}

	[Test]
	public async Task SuspiciousTrafficGuard_WhenResponseStatusIsMonitored_RecordsWithoutBlocking()
	{
		var middleware = new OpxSuspiciousTrafficGuardMiddleware(
			context =>
			{
				context.Response.StatusCode = StatusCodes.Status404NotFound;
				return Task.CompletedTask;
			},
			CreateConfiguration(new Dictionary<string, string?>
			{
				["OpxApiProtection:SuspiciousTraffic:Enabled"] = "true",
				["OpxApiProtection:SuspiciousTraffic:Block"] = "false",
				["OpxApiProtection:SuspiciousTraffic:ResponseStatusCodes:0"] = "404"
			}),
			new TestWebHostEnvironment(Path.GetTempPath()),
			NullLogger<OpxSuspiciousTrafficGuardMiddleware>.Instance);
		var context = CreateContext();

		await middleware.InvokeAsync(context);

		Assert.Multiple(() =>
		{
			Assert.That(context.Response.StatusCode, Is.EqualTo(StatusCodes.Status404NotFound));
			Assert.That(context.Items["OpxSuspiciousReason"], Is.EqualTo("status:404"));
		});
	}

	[Test]
	public async Task SuspiciousTrafficGuard_WhenCleanResponseIsNotMonitored_DoesNotRecord()
	{
		var middleware = new OpxSuspiciousTrafficGuardMiddleware(
			_ => Task.CompletedTask,
			CreateConfiguration(new Dictionary<string, string?>
			{
				["OpxApiProtection:SuspiciousTraffic:Enabled"] = "true",
				["OpxApiProtection:SuspiciousTraffic:Block"] = "false",
				["OpxApiProtection:SuspiciousTraffic:ResponseStatusCodes:0"] = "404"
			}),
			new TestWebHostEnvironment(Path.GetTempPath()),
			NullLogger<OpxSuspiciousTrafficGuardMiddleware>.Instance);
		var context = CreateContext();

		await middleware.InvokeAsync(context);

		Assert.That(context.Items.ContainsKey("OpxSuspiciousReason"), Is.False);
	}

	[Test]
	public async Task SuspiciousTrafficGuard_WhenRequestIsSlow_RecordsElapsedReason()
	{
		var middleware = new OpxSuspiciousTrafficGuardMiddleware(
			async _ => await Task.Delay(20),
			CreateConfiguration(new Dictionary<string, string?>
			{
				["OpxApiProtection:SuspiciousTraffic:Enabled"] = "true",
				["OpxApiProtection:SuspiciousTraffic:Block"] = "false",
				["OpxApiProtection:SuspiciousTraffic:SlowRequestMilliseconds"] = "1"
			}),
			new TestWebHostEnvironment(Path.GetTempPath()),
			NullLogger<OpxSuspiciousTrafficGuardMiddleware>.Instance);
		var context = CreateContext();

		await middleware.InvokeAsync(context);

		Assert.That(context.Items["OpxSuspiciousReason"]?.ToString(), Does.StartWith("slow:"));
	}

	[Test]
	public async Task SuspiciousTrafficGuard_WhenRequestIsBelowSlowThreshold_DoesNotRecord()
	{
		var middleware = new OpxSuspiciousTrafficGuardMiddleware(
			async _ => await Task.Delay(5),
			CreateConfiguration(new Dictionary<string, string?>
			{
				["OpxApiProtection:SuspiciousTraffic:Enabled"] = "true",
				["OpxApiProtection:SuspiciousTraffic:Block"] = "false",
				["OpxApiProtection:SuspiciousTraffic:SlowRequestMilliseconds"] = "5000"
			}),
			new TestWebHostEnvironment(Path.GetTempPath()),
			NullLogger<OpxSuspiciousTrafficGuardMiddleware>.Instance);
		var context = CreateContext();

		await middleware.InvokeAsync(context);

		Assert.That(context.Items.ContainsKey("OpxSuspiciousReason"), Is.False);
	}

	[Test]
	public async Task SuspiciousTrafficGuard_WhenSlowResponseAliasIsConfigured_RecordsElapsedReason()
	{
		var middleware = new OpxSuspiciousTrafficGuardMiddleware(
			async _ => await Task.Delay(20),
			CreateConfiguration(new Dictionary<string, string?>
			{
				["OpxApiProtection:SuspiciousTraffic:Enabled"] = "true",
				["OpxApiProtection:SuspiciousTraffic:Block"] = "false",
				["OpxApiProtection:SuspiciousTraffic:SlowResponseMilliseconds"] = "1"
			}),
			new TestWebHostEnvironment(Path.GetTempPath()),
			NullLogger<OpxSuspiciousTrafficGuardMiddleware>.Instance);
		var context = CreateContext();

		await middleware.InvokeAsync(context);

		Assert.That(context.Items["OpxSuspiciousReason"]?.ToString(), Does.StartWith("slow:"));
	}

	[Test]
	public async Task SuspiciousTrafficGuard_WhenLegacySlowRequestMsIsHigh_DoesNotRecordFastResponse()
	{
		var middleware = new OpxSuspiciousTrafficGuardMiddleware(
			async _ => await Task.Delay(5),
			CreateConfiguration(new Dictionary<string, string?>
			{
				["OpxApiProtection:SuspiciousTraffic:Enabled"] = "true",
				["OpxApiProtection:SuspiciousTraffic:BlockRequest"] = "false",
				["OpxApiProtection:SuspiciousTraffic:SlowRequestMs"] = "50000000"
			}),
			new TestWebHostEnvironment(Path.GetTempPath()),
			NullLogger<OpxSuspiciousTrafficGuardMiddleware>.Instance);
		var context = CreateContext();

		await middleware.InvokeAsync(context);

		Assert.That(context.Items.ContainsKey("OpxSuspiciousReason"), Is.False);
	}

	[Test]
	public async Task SuspiciousTrafficGuard_WhenLegacyBlockSettingsAreUsed_AppliesStatusAndMessage()
	{
		var middleware = new OpxSuspiciousTrafficGuardMiddleware(
			_ => Task.CompletedTask,
			CreateConfiguration(new Dictionary<string, string?>
			{
				["OpxApiProtection:SuspiciousTraffic:Enabled"] = "true",
				["OpxApiProtection:SuspiciousTraffic:BlockRequest"] = "true",
				["OpxApiProtection:SuspiciousTraffic:BlockStatusCode"] = "403",
				["OpxApiProtection:SuspiciousTraffic:BlockResponseBody"] = "Request blocked"
			}),
			new TestWebHostEnvironment(Path.GetTempPath()),
			NullLogger<OpxSuspiciousTrafficGuardMiddleware>.Instance);
		var context = CreateContext();
		context.Request.Path = "/.env";

		await middleware.InvokeAsync(context);
		var response = await ReadResponseAsync(context);

		Assert.Multiple(() =>
		{
			Assert.That(response.GetProperty("statusCode").GetString(), Is.EqualTo("403"));
			Assert.That(response.GetProperty("data").GetProperty("message").GetString(), Is.EqualTo("Request blocked"));
		});
	}

	[Test]
	public async Task SuspiciousTrafficGuard_ModernBlockSettingOverridesLegacySetting()
	{
		var nextCalled = false;
		var middleware = new OpxSuspiciousTrafficGuardMiddleware(
			_ =>
			{
				nextCalled = true;
				return Task.CompletedTask;
			},
			CreateConfiguration(new Dictionary<string, string?>
			{
				["OpxApiProtection:SuspiciousTraffic:Enabled"] = "true",
				["OpxApiProtection:SuspiciousTraffic:Block"] = "false",
				["OpxApiProtection:SuspiciousTraffic:BlockRequest"] = "true"
			}),
			new TestWebHostEnvironment(Path.GetTempPath()),
			NullLogger<OpxSuspiciousTrafficGuardMiddleware>.Instance);
		var context = CreateContext();
		context.Request.Path = "/.env";

		await middleware.InvokeAsync(context);

		Assert.That(nextCalled, Is.True);
	}

	[Test]
	public async Task SuspiciousTrafficGuard_WithSecurityIssueLogSampleRate_WritesSampledLogs()
	{
		var root = CreateTempDirectory();
		var date = DateTime.Now.ToString("yyyyMMdd");
		var logPath = Path.Combine(root, "logs", $"security-issue-log-{date}.log");
		var writer = new OpxSecurityIssueLogWriter(NullLogger<OpxSecurityIssueLogWriter>.Instance);
		var middleware = new OpxSuspiciousTrafficGuardMiddleware(
			_ => Task.CompletedTask,
			CreateConfiguration(new Dictionary<string, string?>
			{
				["OpxApiProtection:SuspiciousTraffic:Enabled"] = "true",
				["OpxApiProtection:SuspiciousTraffic:Block"] = "true",
				["OpxApiProtection:SecurityIssueLog:Enabled"] = "true",
				["OpxApiProtection:SecurityIssueLog:Output"] = "File",
				["OpxApiProtection:SecurityIssueLog:FilePath"] = "logs/security-issue-log-{date}.log",
				["OpxApiProtection:SecurityIssueLog:SampleRate"] = "10"
			}),
			new TestWebHostEnvironment(root),
			NullLogger<OpxSuspiciousTrafficGuardMiddleware>.Instance,
			writer);

		try
		{
			await writer.StartAsync(CancellationToken.None);

			for (var index = 0; index < 11; index++)
			{
				var context = CreateContext();
				context.Request.Path = $"/scan-{index}/.env";
				await middleware.InvokeAsync(context);
			}

			await writer.FlushAsync(CancellationToken.None);
			var lines = await File.ReadAllLinesAsync(logPath);
			Assert.That(lines, Has.Length.EqualTo(2));
		}
		finally
		{
			await writer.StopAsync(CancellationToken.None);
			Directory.Delete(root, true);
		}
	}

	[Test]
	public async Task SuspiciousTrafficGuard_WhenWritingSecurityIssueLog_SanitizesAndTruncatesFields()
	{
		var root = CreateTempDirectory();
		var date = DateTime.Now.ToString("yyyyMMdd");
		var logPath = Path.Combine(root, "logs", $"security-issue-log-{date}.log");
		var writer = new OpxSecurityIssueLogWriter(NullLogger<OpxSecurityIssueLogWriter>.Instance);
		var middleware = new OpxSuspiciousTrafficGuardMiddleware(
			_ => Task.CompletedTask,
			CreateConfiguration(new Dictionary<string, string?>
			{
				["OpxApiProtection:SuspiciousTraffic:Enabled"] = "true",
				["OpxApiProtection:SuspiciousTraffic:Block"] = "true",
				["OpxApiProtection:SecurityIssueLog:Enabled"] = "true",
				["OpxApiProtection:SecurityIssueLog:Output"] = "File",
				["OpxApiProtection:SecurityIssueLog:FilePath"] = "logs/security-issue-log-{date}.log",
				["OpxApiProtection:SecurityIssueLog:MaxPathLength"] = "64",
				["OpxApiProtection:SecurityIssueLog:MaxQueryLength"] = "64",
				["OpxApiProtection:SecurityIssueLog:MaxHeaderLength"] = "64",
				["OpxApiProtection:SecurityIssueLog:MaxReasonLength"] = "64"
			}),
			new TestWebHostEnvironment(root),
			NullLogger<OpxSuspiciousTrafficGuardMiddleware>.Instance,
			writer);

		try
		{
			await writer.StartAsync(CancellationToken.None);
			var context = CreateContext();
			context.Request.Path = "/scan/.env";
			context.Request.QueryString = new QueryString($"?value={new string('x', 200)}");
			context.Request.Headers.UserAgent = $"bad-agent\r\nFakeLog=1 {new string('y', 200)}";

			await middleware.InvokeAsync(context);
			await writer.FlushAsync(CancellationToken.None);

			var line = (await File.ReadAllLinesAsync(logPath)).Single();
			Assert.Multiple(() =>
			{
				Assert.That(line, Does.Not.Contain("\r"));
				Assert.That(line, Does.Not.Contain("\n"));
				Assert.That(line, Does.Contain("..."));
				Assert.That(line, Does.Contain("FakeLog=1"));
			});
		}
		finally
		{
			await writer.StopAsync(CancellationToken.None);
			Directory.Delete(root, true);
		}
	}

	[Test]
	public async Task SuspiciousTrafficGuard_WhenSecurityIssueLogFormatJsonLines_WritesJsonLine()
	{
		var root = CreateTempDirectory();
		var date = DateTime.Now.ToString("yyyyMMdd");
		var logPath = Path.Combine(root, "logs", $"security-issue-log-{date}.log");
		var writer = new OpxSecurityIssueLogWriter(NullLogger<OpxSecurityIssueLogWriter>.Instance);
		var middleware = new OpxSuspiciousTrafficGuardMiddleware(
			_ => Task.CompletedTask,
			CreateConfiguration(new Dictionary<string, string?>
			{
				["OpxApiProtection:SuspiciousTraffic:Enabled"] = "true",
				["OpxApiProtection:SuspiciousTraffic:Block"] = "true",
				["OpxApiProtection:SecurityIssueLog:Enabled"] = "true",
				["OpxApiProtection:SecurityIssueLog:Output"] = "File",
				["OpxApiProtection:SecurityIssueLog:FilePath"] = "logs/security-issue-log-{date}.log",
				["OpxApiProtection:SecurityIssueLog:Format"] = "JsonLines"
			}),
			new TestWebHostEnvironment(root),
			NullLogger<OpxSuspiciousTrafficGuardMiddleware>.Instance,
			writer);

		try
		{
			await writer.StartAsync(CancellationToken.None);
			var context = CreateContext();
			context.Request.Method = HttpMethods.Get;
			context.Request.Path = "/.env";

			await middleware.InvokeAsync(context);
			await writer.FlushAsync(CancellationToken.None);

			var line = (await File.ReadAllLinesAsync(logPath)).Single();
			using var document = JsonDocument.Parse(line);

			Assert.Multiple(() =>
			{
				Assert.That(document.RootElement.GetProperty("type").GetString(), Is.EqualTo("SecurityIssue"));
				Assert.That(document.RootElement.GetProperty("message").GetString(), Does.Contain("SecurityIssue GET /.env"));
			});
		}
		finally
		{
			await writer.StopAsync(CancellationToken.None);
			Directory.Delete(root, true);
		}
	}

	[Test]
	public async Task SuspiciousTrafficGuard_CloudflareTunnelLog_WritesResolvedPeerAndSource()
	{
		var root = CreateTempDirectory();
		var date = DateTime.Now.ToString("yyyyMMdd");
		var logPath = Path.Combine(root, "logs", $"security-issue-log-{date}.log");
		var configuration = CreateConfiguration(new Dictionary<string, string?>
		{
			["OpxApiProtection:SuspiciousTraffic:Enabled"] = "true",
			["OpxApiProtection:SuspiciousTraffic:Block"] = "true",
			["OpxApiProtection:SecurityIssueLog:Enabled"] = "true",
			["OpxApiProtection:SecurityIssueLog:Output"] = "File",
			["OpxApiProtection:SecurityIssueLog:FilePath"] = "logs/security-issue-log-{date}.log",
			["OpxApiProtection:ClientIp:TrustForwardedHeaders"] = "true",
			["OpxApiProtection:ClientIp:HeaderNames:0"] = "CF-Connecting-IP"
		});
		var writer = new OpxSecurityIssueLogWriter(NullLogger<OpxSecurityIssueLogWriter>.Instance);
		var middleware = new OpxSuspiciousTrafficGuardMiddleware(
			_ => Task.CompletedTask,
			configuration,
			new TestWebHostEnvironment(root),
			NullLogger<OpxSuspiciousTrafficGuardMiddleware>.Instance,
			writer);

		try
		{
			await writer.StartAsync(CancellationToken.None);
			var context = CreateContext();
			context.Connection.RemoteIpAddress = IPAddress.Loopback;
			context.Request.Headers["CF-Connecting-IP"] = "203.0.113.120";
			context.Request.Path = "/.env";

			await middleware.InvokeAsync(context);
			await writer.FlushAsync(CancellationToken.None);

			var line = (await File.ReadAllLinesAsync(logPath)).Single();
			Assert.Multiple(() =>
			{
				Assert.That(line, Does.Contain("IP=203.0.113.120"));
				Assert.That(line, Does.Contain("PeerIP=127.0.0.1"));
				Assert.That(line, Does.Contain("IPSource=CF-Connecting-IP"));
			});
		}
		finally
		{
			await writer.StopAsync(CancellationToken.None);
			Directory.Delete(root, true);
		}
	}

	[Test]
	public async Task SuspiciousTrafficGuard_WhenIpIsAllowed_SkipsScan()
	{
		var nextCount = 0;
		var middleware = new OpxSuspiciousTrafficGuardMiddleware(
			_ =>
			{
				Interlocked.Increment(ref nextCount);
				return Task.CompletedTask;
			},
			CreateConfiguration(new Dictionary<string, string?>
			{
				["OpxApiProtection:SuspiciousTraffic:Enabled"] = "true",
				["OpxApiProtection:SuspiciousTraffic:AllowedIpAddresses:0"] = "127.0.0.1"
			}),
			new TestWebHostEnvironment(Path.GetTempPath()),
			NullLogger<OpxSuspiciousTrafficGuardMiddleware>.Instance);
		var context = CreateContext();
		context.Request.Path = "/.env";
		context.Connection.RemoteIpAddress = IPAddress.Parse("127.0.0.1");

		await middleware.InvokeAsync(context);

		Assert.That(nextCount, Is.EqualTo(1));
	}

	[Test]
	public async Task SuspiciousTrafficGuard_WhenRealIpHeaderIsAllowed_SkipsGatewayIp()
	{
		var nextCount = 0;
		var middleware = new OpxSuspiciousTrafficGuardMiddleware(
			_ =>
			{
				Interlocked.Increment(ref nextCount);
				return Task.CompletedTask;
			},
			CreateConfiguration(new Dictionary<string, string?>
			{
				["OpxApiProtection:SuspiciousTraffic:Enabled"] = "true",
				["OpxApiProtection:SuspiciousTraffic:AllowedIpAddresses:0"] = "203.0.113.10",
				["OpxApiProtection:ClientIp:TrustForwardedHeaders"] = "true",
				["OpxApiProtection:ClientIp:TrustedProxies:0"] = "10.0.0.5",
				["OpxApiProtection:ClientIp:HeaderNames:0"] = "X-Real-IP"
			}),
			new TestWebHostEnvironment(Path.GetTempPath()),
			NullLogger<OpxSuspiciousTrafficGuardMiddleware>.Instance);
		var context = CreateContext();
		context.Request.Path = "/.env";
		context.Connection.RemoteIpAddress = IPAddress.Parse("10.0.0.5");
		context.Request.Headers["X-Real-IP"] = "203.0.113.10";

		await middleware.InvokeAsync(context);

		Assert.That(nextCount, Is.EqualTo(1));
	}

	[Test]
	public async Task SuspiciousTrafficGuard_WhenIpMatchesAllowedCidr_SkipsScan()
	{
		var nextCount = 0;
		var middleware = new OpxSuspiciousTrafficGuardMiddleware(
			_ =>
			{
				Interlocked.Increment(ref nextCount);
				return Task.CompletedTask;
			},
			CreateConfiguration(new Dictionary<string, string?>
			{
				["OpxApiProtection:SuspiciousTraffic:Enabled"] = "true",
				["OpxApiProtection:SuspiciousTraffic:AllowedIpAddresses:0"] = "10.10.0.0/16"
			}),
			new TestWebHostEnvironment(Path.GetTempPath()),
			NullLogger<OpxSuspiciousTrafficGuardMiddleware>.Instance);
		var context = CreateContext();
		context.Request.Path = "/.env";
		context.Connection.RemoteIpAddress = IPAddress.Parse("10.10.12.5");

		await middleware.InvokeAsync(context);

		Assert.That(nextCount, Is.EqualTo(1));
	}

	[Test]
	public async Task SuspiciousTrafficGuard_WhenIpIsDenied_BlocksRequest()
	{
		var middleware = new OpxSuspiciousTrafficGuardMiddleware(
			_ => Task.CompletedTask,
			CreateConfiguration(new Dictionary<string, string?>
			{
				["OpxApiProtection:SuspiciousTraffic:Enabled"] = "true",
				["OpxApiProtection:SuspiciousTraffic:DeniedIpAddresses:0"] = "127.0.0.2"
			}),
			new TestWebHostEnvironment(Path.GetTempPath()),
			NullLogger<OpxSuspiciousTrafficGuardMiddleware>.Instance);
		var context = CreateContext();
		context.Request.Path = "/safe";
		context.Connection.RemoteIpAddress = IPAddress.Parse("127.0.0.2");

		await middleware.InvokeAsync(context);
		var response = await ReadResponseAsync(context);

		Assert.Multiple(() =>
		{
			Assert.That(response.GetProperty("result").GetBoolean(), Is.False);
			Assert.That(context.Items["OpxSuspiciousReason"], Is.EqualTo("Denied IP 127.0.0.2"));
		});
	}

	[Test]
	public async Task SuspiciousTrafficGuard_WhenIpMatchesDeniedCidr_BlocksRequest()
	{
		var middleware = new OpxSuspiciousTrafficGuardMiddleware(
			_ => Task.CompletedTask,
			CreateConfiguration(new Dictionary<string, string?>
			{
				["OpxApiProtection:SuspiciousTraffic:Enabled"] = "true",
				["OpxApiProtection:SuspiciousTraffic:DeniedIpAddresses:0"] = "172.16.0.0/12"
			}),
			new TestWebHostEnvironment(Path.GetTempPath()),
			NullLogger<OpxSuspiciousTrafficGuardMiddleware>.Instance);
		var context = CreateContext();
		context.Request.Path = "/safe";
		context.Connection.RemoteIpAddress = IPAddress.Parse("172.16.5.9");

		await middleware.InvokeAsync(context);
		var response = await ReadResponseAsync(context);

		Assert.Multiple(() =>
		{
			Assert.That(response.GetProperty("result").GetBoolean(), Is.False);
			Assert.That(context.Items["OpxSuspiciousReason"], Is.EqualTo("Denied IP 172.16.5.9"));
		});
	}

	[Test]
	public void ProtectionConfigurationValidator_WhenInvalidCidr_ReturnsError()
	{
		var errors = OpxProtectionConfigurationValidator.Validate(CreateConfiguration(new Dictionary<string, string?>
		{
			["OpxApiProtection:SuspiciousTraffic:AllowedIpAddresses:0"] = "10.0.0.0/99"
		})).ToArray();

		Assert.That(errors.Single(), Does.Contain("AllowedIpAddresses"));
	}

	[Test]
	public void ProtectionConfigurationValidator_WhenInvalidMode_ReturnsError()
	{
		var errors = OpxProtectionConfigurationValidator.Validate(CreateConfiguration(new Dictionary<string, string?>
		{
			["OpxApiProtection:SuspiciousTraffic:BlockedResponseMode"] = "Unknown"
		})).ToArray();

		Assert.That(errors.Single(), Does.Contain("BlockedResponseMode"));
	}

	[Test]
	public void ProtectionConfigurationValidator_WhenGatewayTextIsConfigured_ReturnsNoError()
	{
		var configuration = CreateConfiguration(new Dictionary<string, string?>
		{
			["OpxApiProtection:SecurityIssueLog:Format"] = "GatewayText"
		});

		var errors = OpxProtectionConfigurationValidator.Validate(configuration).ToArray();

		Assert.That(errors, Is.Empty);
	}

	[TestCase("BlockStatusCode", "399")]
	[TestCase("StatusCode", "600")]
	public void ProtectionConfigurationValidator_WhenBlockedStatusCodeIsInvalid_ReturnsError(string key, string value)
	{
		var configuration = CreateConfiguration(new Dictionary<string, string?>
		{
			[$"OpxApiProtection:SuspiciousTraffic:{key}"] = value
		});

		var errors = OpxProtectionConfigurationValidator.Validate(configuration).ToArray();

		Assert.That(errors, Has.Some.Contains("StatusCode"));
	}

	[Test]
	public void ProtectionConfigurationValidator_WhenLegacySlowThresholdIsNegative_ReturnsError()
	{
		var configuration = CreateConfiguration(new Dictionary<string, string?>
		{
			["OpxApiProtection:SuspiciousTraffic:SlowRequestMs"] = "-1"
		});

		var errors = OpxProtectionConfigurationValidator.Validate(configuration).ToArray();

		Assert.That(errors, Has.Some.Contains("cannot be negative"));
	}

	[Test]
	public void AddOpxApiWeb_WhenLegacyIncludeInAccessLogIsEnabled_MapsFrameworkOption()
	{
		var configuration = CreateConfiguration(new Dictionary<string, string?>
		{
			["OpxApiProtection:SuspiciousTraffic:IncludeInAccessLog"] = "true"
		});
		using var services = new ServiceCollection()
			.AddLogging()
			.AddOpxApiWeb(configuration)
			.BuildServiceProvider();

		var options = services.GetRequiredService<IOptions<OpxWebFrameworkOptions>>().Value;

		Assert.That(options.AccessLog.IncludeSuspiciousRequests, Is.True);
	}

	[Test]
	public void ChinookAppSettings_AreValidProtectionConfigurations()
	{
		var repositoryRoot = FindRepositoryRoot();
		var sampleRoot = Path.Combine(repositoryRoot.Parent!.FullName, "api-samples");
		var files = Directory.GetFiles(sampleRoot, "appsettings*.json", SearchOption.AllDirectories)
			.Where(path => !path.Contains($"{Path.DirectorySeparatorChar}bin{Path.DirectorySeparatorChar}", StringComparison.OrdinalIgnoreCase)
				&& !path.Contains($"{Path.DirectorySeparatorChar}obj{Path.DirectorySeparatorChar}", StringComparison.OrdinalIgnoreCase))
			.ToArray();

		Assert.That(files, Is.Not.Empty);
		foreach (var file in files)
		{
			var configuration = new ConfigurationBuilder().AddJsonFile(file).Build();
			var errors = OpxProtectionConfigurationValidator.Validate(configuration).ToArray();
			Assert.That(errors, Is.Empty, file);
		}
	}

	[Test]
	public void ProtectionConfigurationValidator_WhenInvalidRateLimitAlgorithm_ReturnsError()
	{
		var errors = OpxProtectionConfigurationValidator.Validate(CreateConfiguration(new Dictionary<string, string?>
		{
			["OpxApiProtection:RateLimiting:Algorithm"] = "TokenBucket"
		})).ToArray();

		Assert.That(errors.Single(), Does.Contain("Algorithm"));
	}

	[Test]
	public void ProtectionConfigurationValidator_WhenWebSocketLimitsAreInvalid_ReturnsErrors()
	{
		var configuration = CreateConfiguration(new Dictionary<string, string?>
		{
			["OpxApiProtection:WebSocket:Enabled"] = "true",
			["OpxApiProtection:WebSocket:Path"] = "ws",
			["OpxApiProtection:WebSocket:ReceiveBufferBytes"] = "512",
			["OpxApiProtection:WebSocket:MaxMessageBytes"] = "256",
			["OpxApiProtection:WebSocket:IdleTimeoutSeconds"] = "-1",
			["OpxApiProtection:WebSocket:MessageRateLimitWindowSeconds"] = "0"
		});

		var errors = OpxProtectionConfigurationValidator.Validate(configuration).ToArray();

		Assert.Multiple(() =>
		{
			Assert.That(errors, Has.Some.Contains("WebSocket:Path"));
			Assert.That(errors, Has.Some.Contains("ReceiveBufferBytes"));
			Assert.That(errors, Has.Some.Contains("MaxMessageBytes"));
			Assert.That(errors, Has.Some.Contains("IdleTimeoutSeconds"));
			Assert.That(errors, Has.Some.Contains("MessageRateLimitWindowSeconds"));
		});
	}

	[Test]
	public async Task SecurityIssueLogWriter_WhenStopped_DrainsQueuedLogs()
	{
		var root = CreateTempDirectory();
		var logPath = Path.Combine(root, "logs", "security-issue-log-test.log");
		var writer = new OpxSecurityIssueLogWriter(
			NullLogger<OpxSecurityIssueLogWriter>.Instance,
			CreateConfiguration(new Dictionary<string, string?>
			{
				["OpxApiProtection:SecurityIssueLog:QueueCapacity"] = "10",
				["OpxApiProtection:SecurityIssueLog:BatchSize"] = "2",
				["OpxApiProtection:SecurityIssueLog:FlushIntervalMilliseconds"] = "1"
			}));

		try
		{
			await writer.StartAsync(CancellationToken.None);
			Assert.That(writer.TryWrite(SecurityIssueLogEntry.Create("SecurityIssue GET /.env", false, true, logPath)), Is.True);
			Assert.That(writer.TryWrite(SecurityIssueLogEntry.Create("SecurityIssue GET /.git", false, true, logPath)), Is.True);

			await writer.StopAsync(CancellationToken.None);
			var lines = await File.ReadAllLinesAsync(logPath);

			Assert.That(lines, Has.Length.EqualTo(2));
		}
		finally
		{
			Directory.Delete(root, true);
		}
	}

	[Test]
	public void SecurityIssueLogWriter_WhenQueueIsFull_IncrementsDroppedCount()
	{
		var writer = new OpxSecurityIssueLogWriter(
			NullLogger<OpxSecurityIssueLogWriter>.Instance,
			CreateConfiguration(new Dictionary<string, string?>
			{
				["OpxApiProtection:SecurityIssueLog:QueueCapacity"] = "1"
			}));

		Assert.Multiple(() =>
		{
			Assert.That(writer.TryWrite(SecurityIssueLogEntry.Create("first", false, false, null)), Is.True);
			Assert.That(writer.TryWrite(SecurityIssueLogEntry.Create("second", false, false, null)), Is.False);
			Assert.That(writer.DroppedCount, Is.EqualTo(1));
		});
	}

	[Test]
	public async Task SecurityIssueLogWriter_WithFiveThousandFileLogs_CompletesWithinTwoSeconds()
	{
		const int logCount = 5000;
		var root = CreateTempDirectory();
		var logPath = Path.Combine(root, "logs", "security-issue-log-stress.log");
		var writer = new OpxSecurityIssueLogWriter(
			NullLogger<OpxSecurityIssueLogWriter>.Instance,
			CreateConfiguration(new Dictionary<string, string?>
			{
				["OpxApiProtection:SecurityIssueLog:QueueCapacity"] = "8192",
				["OpxApiProtection:SecurityIssueLog:BatchSize"] = "250",
				["OpxApiProtection:SecurityIssueLog:FlushIntervalMilliseconds"] = "1"
			}));

		try
		{
			await writer.StartAsync(CancellationToken.None);
			var stopwatch = Stopwatch.StartNew();

			for (var index = 0; index < logCount; index++)
			{
				Assert.That(writer.TryWrite(SecurityIssueLogEntry.Create($"SecurityIssue GET /.env/{index}", false, true, logPath)), Is.True);
			}

			await writer.FlushAsync(CancellationToken.None);
			stopwatch.Stop();
			var lines = await File.ReadAllLinesAsync(logPath);

			Assert.Multiple(() =>
			{
				Assert.That(lines, Has.Length.EqualTo(logCount));
				Assert.That(writer.DroppedCount, Is.EqualTo(0));
				Assert.That(stopwatch.ElapsedMilliseconds, Is.LessThan(2000));
			});
		}
		finally
		{
			await writer.StopAsync(CancellationToken.None);
			Directory.Delete(root, true);
		}
	}

	[Test]
	public async Task EndpointLogWriter_WithFiveThousandFileLogs_CompletesWithinTwoSeconds()
	{
		const int logCount = 5000;
		var root = CreateTempDirectory();
		var logPath = Path.Combine(root, "logs", "endpoint-log-stress.log");
		var writer = new OpxEndpointLogWriter(
			NullLogger<OpxEndpointLogWriter>.Instance,
			CreateConfiguration(new Dictionary<string, string?>
			{
				["EndpointLog:QueueCapacity"] = "8192",
				["EndpointLog:BatchSize"] = "250",
				["EndpointLog:FlushIntervalMilliseconds"] = "1"
			}));

		try
		{
			await writer.StartAsync(CancellationToken.None);
			var stopwatch = Stopwatch.StartNew();

			for (var index = 0; index < logCount; index++)
			{
				Assert.That(writer.TryWrite(EndpointLogEntry.Create($"Endpoint executed GET /artists/{index}", logPath)), Is.True);
			}

			await writer.FlushAsync(CancellationToken.None);
			stopwatch.Stop();
			var lines = await File.ReadAllLinesAsync(logPath);

			Assert.Multiple(() =>
			{
				Assert.That(lines, Has.Length.EqualTo(logCount));
				Assert.That(writer.DroppedCount, Is.EqualTo(0));
				Assert.That(stopwatch.ElapsedMilliseconds, Is.LessThan(2000));
			});
		}
		finally
		{
			await writer.StopAsync(CancellationToken.None);
			Directory.Delete(root, true);
		}
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
	public async Task RateLimiting_WhenRealIpHeaderDiffers_UsesRealIpInsteadOfGatewayIp()
	{
		var configuration = CreateConfiguration(new Dictionary<string, string?>
		{
			["OpxApiProtection:RateLimiting:Enabled"] = "true",
			["OpxApiProtection:RateLimiting:Limit"] = "1",
			["OpxApiProtection:RateLimiting:WindowSeconds"] = "60",
			["OpxApiProtection:ClientIp:TrustForwardedHeaders"] = "true",
			["OpxApiProtection:ClientIp:TrustedProxies:0"] = "10.0.0.5",
			["OpxApiProtection:ClientIp:HeaderNames:0"] = "X-Real-IP"
		});
		var path = $"/rate-real-ip-{Guid.NewGuid():N}";
		var firstContext = CreateContext();
		firstContext.Request.Path = path;
		firstContext.Connection.RemoteIpAddress = IPAddress.Parse("10.0.0.5");
		firstContext.Request.Headers["X-Real-IP"] = "203.0.113.10";
		var secondContext = CreateContext();
		secondContext.Request.Path = path;
		secondContext.Connection.RemoteIpAddress = IPAddress.Parse("10.0.0.5");
		secondContext.Request.Headers["X-Real-IP"] = "203.0.113.11";
		var middleware = new OpxRateLimitingMiddleware(_ => Task.CompletedTask, configuration);

		await middleware.InvokeAsync(firstContext);
		await middleware.InvokeAsync(secondContext);

		Assert.Multiple(() =>
		{
			Assert.That(firstContext.Response.HasStarted, Is.False);
			Assert.That(secondContext.Response.HasStarted, Is.False);
			Assert.That(firstContext.Response.Body.Length, Is.Zero);
			Assert.That(secondContext.Response.Body.Length, Is.Zero);
		});
	}

	[Test]
	public async Task RateLimiting_WhenWriteHeadersOnSuccessIsFalse_DoesNotWriteHeadersForAllowedRequest()
	{
		var configuration = CreateConfiguration(new Dictionary<string, string?>
		{
			["OpxApiProtection:RateLimiting:Enabled"] = "true",
			["OpxApiProtection:RateLimiting:Limit"] = "10",
			["OpxApiProtection:RateLimiting:WindowSeconds"] = "60",
			["OpxApiProtection:RateLimiting:WriteHeadersOnSuccess"] = "false"
		});
		var context = CreateContext();
		context.Request.Path = $"/rate-header-{Guid.NewGuid():N}";
		var middleware = new OpxRateLimitingMiddleware(_ => Task.CompletedTask, configuration);

		await middleware.InvokeAsync(context);

		Assert.That(context.Response.Headers.ContainsKey("RateLimit-Limit"), Is.False);
	}

	[Test]
	public async Task RateLimiting_WhenWriteHeadersOnSuccessIsFalse_StillWritesHeadersForBlockedRequest()
	{
		var configuration = CreateConfiguration(new Dictionary<string, string?>
		{
			["OpxApiProtection:RateLimiting:Enabled"] = "true",
			["OpxApiProtection:RateLimiting:Limit"] = "1",
			["OpxApiProtection:RateLimiting:WindowSeconds"] = "60",
			["OpxApiProtection:RateLimiting:WriteHeadersOnSuccess"] = "false"
		});
		var path = $"/rate-header-blocked-{Guid.NewGuid():N}";
		var firstContext = CreateContext();
		firstContext.Request.Path = path;
		firstContext.Connection.RemoteIpAddress = IPAddress.Parse("127.0.0.40");
		var secondContext = CreateContext();
		secondContext.Request.Path = path;
		secondContext.Connection.RemoteIpAddress = IPAddress.Parse("127.0.0.40");
		var middleware = new OpxRateLimitingMiddleware(_ => Task.CompletedTask, configuration);

		await middleware.InvokeAsync(firstContext);
		await middleware.InvokeAsync(secondContext);

		Assert.Multiple(() =>
		{
			Assert.That(firstContext.Response.Headers.ContainsKey("RateLimit-Limit"), Is.False);
			Assert.That(secondContext.Response.Headers.ContainsKey("RateLimit-Limit"), Is.True);
			Assert.That(secondContext.Response.Headers.ContainsKey("Retry-After"), Is.True);
		});
	}

	[Test]
	public async Task RateLimiting_WhenAlgorithmFixedWindow_BlocksAfterLimit()
	{
		var configuration = CreateConfiguration(new Dictionary<string, string?>
		{
			["OpxApiProtection:RateLimiting:Enabled"] = "true",
			["OpxApiProtection:RateLimiting:Algorithm"] = "FixedWindow",
			["OpxApiProtection:RateLimiting:Limit"] = "1",
			["OpxApiProtection:RateLimiting:WindowSeconds"] = "60"
		});
		var path = $"/fixed-window-{Guid.NewGuid():N}";
		var firstContext = CreateContext();
		firstContext.Request.Path = path;
		firstContext.Connection.RemoteIpAddress = IPAddress.Parse("127.0.0.41");
		var secondContext = CreateContext();
		secondContext.Request.Path = path;
		secondContext.Connection.RemoteIpAddress = IPAddress.Parse("127.0.0.41");
		var middleware = new OpxRateLimitingMiddleware(_ => Task.CompletedTask, configuration);

		await middleware.InvokeAsync(firstContext);
		await middleware.InvokeAsync(secondContext);

		Assert.That(secondContext.Response.Headers.ContainsKey("Retry-After"), Is.True);
	}

	[Test]
	public async Task RateLimiting_WhenPolicyOverridesLimit_UsesPolicyLimit()
	{
		var configuration = CreateConfiguration(new Dictionary<string, string?>
		{
			["OpxApiProtection:RateLimiting:Enabled"] = "true",
			["OpxApiProtection:RateLimiting:Limit"] = "1",
			["OpxApiProtection:Policies:0:PathPrefix"] = "/api/heavy",
			["OpxApiProtection:Policies:0:RateLimit"] = "2",
			["OpxApiProtection:Policies:0:RateLimitWindowSeconds"] = "60"
		});
		var provider = new OpxProtectionPolicyProvider(configuration);
		var middleware = new OpxRateLimitingMiddleware(_ => Task.CompletedTask, configuration, null, provider);

		var first = CreateContext();
		first.Request.Path = "/api/heavy/a";
		first.Connection.RemoteIpAddress = IPAddress.Parse("127.0.0.30");
		var second = CreateContext();
		second.Request.Path = "/api/heavy/a";
		second.Connection.RemoteIpAddress = IPAddress.Parse("127.0.0.30");
		var third = CreateContext();
		third.Request.Path = "/api/heavy/a";
		third.Connection.RemoteIpAddress = IPAddress.Parse("127.0.0.30");

		await middleware.InvokeAsync(first);
		await middleware.InvokeAsync(second);
		await middleware.InvokeAsync(third);

		Assert.Multiple(() =>
		{
			Assert.That(first.Response.Headers.ContainsKey("Retry-After"), Is.False);
			Assert.That(second.Response.Headers.ContainsKey("Retry-After"), Is.False);
			Assert.That(third.Response.Headers.ContainsKey("Retry-After"), Is.True);
		});
	}

	[Test]
	public async Task AuthorizationGuard_WhenPathIsWhitelisted_DoesNotRequireToken()
	{
		var nextCount = 0;
		var middleware = new OpxAuthorizationGuardMiddleware(
			_ =>
			{
				Interlocked.Increment(ref nextCount);
				return Task.CompletedTask;
			},
			CreateConfiguration(new Dictionary<string, string?>
			{
				["OpxApiProtection:AuthorizationGuard:Enabled"] = "true",
				["OpxApiProtection:AuthorizationGuard:WhitelistedPathPrefixes:0"] = "/public"
			}));
		var context = CreateContext();
		context.Request.Path = "/public/callback";

		await middleware.InvokeAsync(context);

		Assert.That(nextCount, Is.EqualTo(1));
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
	public async Task SuspiciousTrafficGuard_WithFiveHundredMinimalSampledBlockedRequests_CompletesWithinOneSecond()
	{
		const int requestCount = 500;
		var root = CreateTempDirectory();
		var configuration = CreateConfiguration(new Dictionary<string, string?>
		{
			["OpxApiProtection:SuspiciousTraffic:Enabled"] = "true",
			["OpxApiProtection:SuspiciousTraffic:Block"] = "true",
			["OpxApiProtection:SuspiciousTraffic:BlockedResponseMode"] = "Minimal",
			["OpxApiProtection:SecurityIssueLog:Enabled"] = "true",
			["OpxApiProtection:SecurityIssueLog:Output"] = "File",
			["OpxApiProtection:SecurityIssueLog:FilePath"] = "logs/security-issue-log-{date}.log",
			["OpxApiProtection:SecurityIssueLog:SampleRate"] = "10"
		});
		var middleware = new OpxSuspiciousTrafficGuardMiddleware(
			_ => Task.CompletedTask,
			configuration,
			new TestWebHostEnvironment(root),
			NullLogger<OpxSuspiciousTrafficGuardMiddleware>.Instance);
		var stopwatch = Stopwatch.StartNew();

		try
		{
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
					Assert.That(response.GetProperty("data").GetString(), Is.EqualTo("Suspicious traffic detected"));
				});
			});

			await Task.WhenAll(tasks);
			stopwatch.Stop();

			Assert.That(stopwatch.ElapsedMilliseconds, Is.LessThan(1000));
		}
		finally
		{
			Directory.Delete(root, true);
		}
	}

	[Test]
	public async Task SuspiciousTrafficGuard_WithFiveHundredWrappedFastSampledBlockedRequests_CompletesWithinOneSecond()
	{
		const int requestCount = 500;
		var root = CreateTempDirectory();
		var configuration = CreateConfiguration(new Dictionary<string, string?>
		{
			["OpxApiProtection:SuspiciousTraffic:Enabled"] = "true",
			["OpxApiProtection:SuspiciousTraffic:Block"] = "true",
			["OpxApiProtection:SuspiciousTraffic:BlockedResponseMode"] = "WrappedFast",
			["OpxApiProtection:SecurityIssueLog:Enabled"] = "true",
			["OpxApiProtection:SecurityIssueLog:Output"] = "File",
			["OpxApiProtection:SecurityIssueLog:FilePath"] = "logs/security-issue-log-{date}.log",
			["OpxApiProtection:SecurityIssueLog:SampleRate"] = "10"
		});
		var middleware = new OpxSuspiciousTrafficGuardMiddleware(
			_ => Task.CompletedTask,
			configuration,
			new TestWebHostEnvironment(root),
			NullLogger<OpxSuspiciousTrafficGuardMiddleware>.Instance);
		var stopwatch = Stopwatch.StartNew();

		try
		{
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
					Assert.That(response.GetProperty("data").GetProperty("message").GetString(), Is.EqualTo("Suspicious traffic detected"));
				});
			});

			await Task.WhenAll(tasks);
			stopwatch.Stop();

			Assert.That(stopwatch.ElapsedMilliseconds, Is.LessThan(1000));
		}
		finally
		{
			Directory.Delete(root, true);
		}
	}

	[Test]
	public async Task SuspiciousTrafficGuard_WithFiveHundredCleanRequests_CompletesWithinOneSecond()
	{
		const int requestCount = 500;
		var configuration = CreateConfiguration(new Dictionary<string, string?>
		{
			["OpxApiProtection:SuspiciousTraffic:Enabled"] = "true",
			["OpxApiProtection:SuspiciousTraffic:Block"] = "true"
		});
		var nextCount = 0;
		var middleware = new OpxSuspiciousTrafficGuardMiddleware(
			_ =>
			{
				Interlocked.Increment(ref nextCount);
				return Task.CompletedTask;
			},
			configuration,
			new TestWebHostEnvironment(Path.GetTempPath()),
			NullLogger<OpxSuspiciousTrafficGuardMiddleware>.Instance);
		var stopwatch = Stopwatch.StartNew();

		var tasks = Enumerable.Range(0, requestCount).Select(async index =>
		{
			var context = CreateContext();
			context.Request.Path = $"/artists/{index}";

			await middleware.InvokeAsync(context);

			Assert.That(context.Items.ContainsKey("OpxSuspiciousReason"), Is.False);
		});

		await Task.WhenAll(tasks);
		stopwatch.Stop();

		Assert.Multiple(() =>
		{
			Assert.That(nextCount, Is.EqualTo(requestCount));
			Assert.That(stopwatch.ElapsedMilliseconds, Is.LessThan(1000));
		});
	}

	[Test]
	public async Task SuspiciousTrafficGuard_WithFiveThousandCleanRequests_CompletesWithinOneSecond()
	{
		const int requestCount = 5000;
		var configuration = CreateConfiguration(new Dictionary<string, string?>
		{
			["OpxApiProtection:SuspiciousTraffic:Enabled"] = "true",
			["OpxApiProtection:SuspiciousTraffic:Block"] = "true"
		});
		var nextCount = 0;
		var middleware = new OpxSuspiciousTrafficGuardMiddleware(
			_ =>
			{
				Interlocked.Increment(ref nextCount);
				return Task.CompletedTask;
			},
			configuration,
			new TestWebHostEnvironment(Path.GetTempPath()),
			NullLogger<OpxSuspiciousTrafficGuardMiddleware>.Instance);
		var stopwatch = Stopwatch.StartNew();

		var tasks = Enumerable.Range(0, requestCount).Select(async index =>
		{
			var context = CreateContext();
			context.Request.Path = $"/artists/{index}";

			await middleware.InvokeAsync(context);
		});

		await Task.WhenAll(tasks);
		stopwatch.Stop();

		Assert.Multiple(() =>
		{
			Assert.That(nextCount, Is.EqualTo(requestCount));
			Assert.That(stopwatch.ElapsedMilliseconds, Is.LessThan(1000));
		});
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
	public async Task RateLimiting_WithFiveThousandPolicySkippedRequests_CompletesWithinOneSecond()
	{
		const int requestCount = 5000;
		var configuration = CreateConfiguration(new Dictionary<string, string?>
		{
			["OpxApiProtection:RateLimiting:Enabled"] = "true",
			["OpxApiProtection:Policies:0:PathPrefix"] = "/public",
			["OpxApiProtection:Policies:0:SkipRateLimiting"] = "true"
		});
		var provider = new OpxProtectionPolicyProvider(configuration);
		var nextCount = 0;
		var middleware = new OpxRateLimitingMiddleware(
			_ =>
			{
				Interlocked.Increment(ref nextCount);
				return Task.CompletedTask;
			},
			configuration,
			null,
			provider);
		var stopwatch = Stopwatch.StartNew();

		var tasks = Enumerable.Range(0, requestCount).Select(async index =>
		{
			var context = CreateContext();
			context.Request.Path = $"/public/{index}";
			await middleware.InvokeAsync(context);
		});

		await Task.WhenAll(tasks);
		stopwatch.Stop();

		Assert.Multiple(() =>
		{
			Assert.That(nextCount, Is.EqualTo(requestCount));
			Assert.That(stopwatch.ElapsedMilliseconds, Is.LessThan(1000));
		});
	}

	[Test]
	public async Task AuthorizationGuard_WithFiveThousandWhitelistedRequests_CompletesWithinOneSecond()
	{
		const int requestCount = 5000;
		var configuration = CreateConfiguration(new Dictionary<string, string?>
		{
			["OpxApiProtection:AuthorizationGuard:Enabled"] = "true",
			["OpxApiProtection:AuthorizationGuard:WhitelistedPathPrefixes:0"] = "/public"
		});
		var nextCount = 0;
		var middleware = new OpxAuthorizationGuardMiddleware(
			_ =>
			{
				Interlocked.Increment(ref nextCount);
				return Task.CompletedTask;
			},
			configuration);
		var stopwatch = Stopwatch.StartNew();

		var tasks = Enumerable.Range(0, requestCount).Select(async index =>
		{
			var context = CreateContext();
			context.Request.Path = $"/public/{index}";
			await middleware.InvokeAsync(context);
		});

		await Task.WhenAll(tasks);
		stopwatch.Stop();

		Assert.Multiple(() =>
		{
			Assert.That(nextCount, Is.EqualTo(requestCount));
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

	[Test]
	public async Task LogsController_WhenRequireAuthorizationAndAnonymous_ReturnsUnauthorized()
	{
		var configuration = CreateConfiguration(new Dictionary<string, string?>
		{
			["OpxApiProtection:LogApi:Enabled"] = "true",
			["OpxApiProtection:LogApi:RequireAuthorization"] = "true"
		});
		var controller = CreateLogsController(configuration, Path.GetTempPath());

		await controller.Access();
		var response = await ReadResponseAsync(controller.HttpContext);

		Assert.Multiple(() =>
		{
			Assert.That(response.GetProperty("result").GetBoolean(), Is.False);
			Assert.That(response.GetProperty("statusCode").GetString(), Is.EqualTo(StatusCodes.Status401Unauthorized.ToString()));
			Assert.That(response.GetProperty("data").GetProperty("message").GetString(), Is.EqualTo("Unauthorized"));
		});
	}

	[Test]
	public async Task LogsController_WhenRequireAuthorizationAndAuthenticated_ReturnsLogLines()
	{
		var root = CreateTempDirectory();
		var date = DateTime.Now.ToString("yyyyMMdd");
		var logPath = Path.Combine(root, "logs", $"access-log-{date}.log");
		Directory.CreateDirectory(Path.GetDirectoryName(logPath)!);
		await File.WriteAllLinesAsync(logPath, ["line-1"]);
		var configuration = CreateConfiguration(new Dictionary<string, string?>
		{
			["OpxApiProtection:LogApi:Enabled"] = "true",
			["OpxApiProtection:LogApi:RequireAuthorization"] = "true",
			["OpxApiProtection:AccessLog:FilePath"] = "logs/access-log-{date}.log"
		});
		var controller = CreateLogsController(configuration, root);
		controller.HttpContext.User = new ClaimsPrincipal(new ClaimsIdentity([new Claim(ClaimTypes.Name, "opx")], "Test"));

		try
		{
			await controller.Access(date, 10);
			var response = await ReadResponseAsync(controller.HttpContext);

			Assert.That(response.GetProperty("result").GetBoolean(), Is.True);
		}
		finally
		{
			Directory.Delete(root, true);
		}
	}

	[Test]
	public async Task LogsController_WhenRequiredRoleMissing_ReturnsForbidden()
	{
		var configuration = CreateConfiguration(new Dictionary<string, string?>
		{
			["OpxApiProtection:LogApi:Enabled"] = "true",
			["OpxApiProtection:LogApi:RequireAuthorization"] = "true",
			["OpxApiProtection:LogApi:RequiredRole"] = "Admin"
		});
		var controller = CreateLogsController(configuration, Path.GetTempPath());
		controller.HttpContext.User = new ClaimsPrincipal(new ClaimsIdentity([new Claim(ClaimTypes.Name, "opx")], "Test"));

		await controller.Access();
		var response = await ReadResponseAsync(controller.HttpContext);

		Assert.Multiple(() =>
		{
			Assert.That(response.GetProperty("result").GetBoolean(), Is.False);
			Assert.That(response.GetProperty("statusCode").GetString(), Is.EqualTo(StatusCodes.Status403Forbidden.ToString()));
			Assert.That(response.GetProperty("data").GetProperty("message").GetString(), Is.EqualTo("Forbidden"));
		});
	}

	[Test]
	public async Task LogsController_WhenRequiredPolicyPasses_ReturnsLogLines()
	{
		var root = CreateTempDirectory();
		var date = DateTime.Now.ToString("yyyyMMdd");
		var logPath = Path.Combine(root, "logs", $"access-log-{date}.log");
		Directory.CreateDirectory(Path.GetDirectoryName(logPath)!);
		await File.WriteAllLinesAsync(logPath, ["line-1"]);
		var configuration = CreateConfiguration(new Dictionary<string, string?>
		{
			["OpxApiProtection:LogApi:Enabled"] = "true",
			["OpxApiProtection:LogApi:RequireAuthorization"] = "true",
			["OpxApiProtection:LogApi:RequiredPolicy"] = "OpxLogViewer",
			["OpxApiProtection:AccessLog:FilePath"] = "logs/access-log-{date}.log"
		});
		var services = new ServiceCollection()
			.AddLogging()
			.AddAuthorization(options => options.AddPolicy("OpxLogViewer", policy => policy.RequireClaim("scope", "opx.logs.read")))
			.BuildServiceProvider();
		var controller = CreateLogsController(configuration, root, services);
		controller.HttpContext.User = new ClaimsPrincipal(new ClaimsIdentity(
		[
			new Claim(ClaimTypes.Name, "opx"),
			new Claim("scope", "opx.logs.read")
		], "Test"));

		try
		{
			await controller.Access(date, 10);
			var response = await ReadResponseAsync(controller.HttpContext);

			Assert.That(response.GetProperty("result").GetBoolean(), Is.True);
		}
		finally
		{
			await services.DisposeAsync();
			Directory.Delete(root, true);
		}
	}

	[Test]
	public async Task ProtectionController_Metrics_WhenEnabled_ReturnsCounters()
	{
		var metrics = new OpxProtectionMetrics();
		metrics.IncrementSuspiciousDetected();
		metrics.IncrementRateLimitBlocked();
		var controller = CreateProtectionController(CreateConfiguration(new Dictionary<string, string?>
		{
			["OpxApiProtection:MetricsApi:Enabled"] = "true"
		}), metrics);

		await controller.Metrics();
		var response = await ReadResponseAsync(controller.HttpContext);

		Assert.Multiple(() =>
		{
			Assert.That(response.GetProperty("result").GetBoolean(), Is.True);
			Assert.That(response.GetProperty("data").GetProperty("SuspiciousDetected").GetInt64(), Is.EqualTo(1));
			Assert.That(response.GetProperty("data").GetProperty("RateLimitBlocked").GetInt64(), Is.EqualTo(1));
		});
	}

	[Test]
	public async Task ProtectionController_Health_WhenEnabled_ReturnsHealthState()
	{
		var controller = CreateProtectionController(CreateConfiguration(new Dictionary<string, string?>
		{
			["OpxApiProtection:MetricsApi:Enabled"] = "true",
			["OpxApiProtection:SuspiciousTraffic:Enabled"] = "true"
		}), new OpxProtectionMetrics());

		await controller.Health();
		var response = await ReadResponseAsync(controller.HttpContext);

		Assert.Multiple(() =>
		{
			Assert.That(response.GetProperty("result").GetBoolean(), Is.True);
			Assert.That(response.GetProperty("data").GetProperty("Status").GetString(), Is.EqualTo("Healthy"));
			Assert.That(response.GetProperty("data").GetProperty("SuspiciousTraffic").GetBoolean(), Is.True);
		});
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

	private static DirectoryInfo FindRepositoryRoot()
	{
		var directory = new DirectoryInfo(AppContext.BaseDirectory);
		while (directory is not null && !File.Exists(Path.Combine(directory.FullName, "Opx.Api.Web.slnx")))
		{
			directory = directory.Parent;
		}

		return directory ?? throw new DirectoryNotFoundException("Unable to locate the api-web repository root.");
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

	private static OpxLogsController CreateLogsController(IConfiguration configuration, string contentRootPath, IServiceProvider? serviceProvider = null)
	{
		var context = CreateContext();
		context.RequestServices = serviceProvider ?? new ServiceCollection().BuildServiceProvider();
		var environment = new TestWebHostEnvironment(contentRootPath);
		return new OpxLogsController(configuration, new OpxLogFileReader(configuration, environment))
		{
			ControllerContext = new ControllerContext
			{
				HttpContext = context
			}
		};
	}

	private static OpxProtectionController CreateProtectionController(IConfiguration configuration, OpxProtectionMetrics metrics)
	{
		var context = CreateContext();
		var writer = new OpxSecurityIssueLogWriter(NullLogger<OpxSecurityIssueLogWriter>.Instance, configuration, metrics);
		return new OpxProtectionController(configuration, metrics, writer)
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
