// Copyright (c) 2026 - opx
using BenchmarkDotNet.Attributes;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.FileProviders;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging.Abstractions;
using Opx.Api.Web.Middlewares;

[MemoryDiagnoser]
[SimpleJob(warmupCount: 3, iterationCount: 8)]
public class OpxMiddlewareBenchmarks
{
	private OpxAuthorizationGuardMiddleware _authorizationGuard = null!;
	private OpxRateLimitingMiddleware _fixedWindowRateLimit = null!;
	private OpxSuspiciousTrafficGuardMiddleware _suspiciousTrafficGuard = null!;
	private TestWebHostEnvironment _environment = null!;

	[GlobalSetup]
	public void Setup()
	{
		_environment = new TestWebHostEnvironment(Path.GetTempPath());
		_authorizationGuard = new OpxAuthorizationGuardMiddleware(
			_ => Task.CompletedTask,
			CreateConfiguration(new Dictionary<string, string?>
			{
				["OpxApiProtection:AuthorizationGuard:Enabled"] = "true",
				["OpxApiProtection:AuthorizationGuard:WhitelistedPathPrefixes:0"] = "/public"
			}));
		_fixedWindowRateLimit = new OpxRateLimitingMiddleware(
			_ => Task.CompletedTask,
			CreateConfiguration(new Dictionary<string, string?>
			{
				["OpxApiProtection:RateLimiting:Enabled"] = "true",
				["OpxApiProtection:RateLimiting:Algorithm"] = "FixedWindow",
				["OpxApiProtection:RateLimiting:Limit"] = "1000000",
				["OpxApiProtection:RateLimiting:WindowSeconds"] = "60",
				["OpxApiProtection:RateLimiting:WriteHeadersOnSuccess"] = "false"
			}));
		_suspiciousTrafficGuard = new OpxSuspiciousTrafficGuardMiddleware(
			_ => Task.CompletedTask,
			CreateConfiguration(new Dictionary<string, string?>
			{
				["OpxApiProtection:SuspiciousTraffic:Enabled"] = "true"
			}),
			_environment,
			NullLogger<OpxSuspiciousTrafficGuardMiddleware>.Instance);
	}

	[Benchmark]
	public Task AuthorizationWhitelisted()
	{
		var context = CreateContext("/public/ping");
		return _authorizationGuard.InvokeAsync(context);
	}

	[Benchmark]
	public Task RateLimitFixedWindowAllowed()
	{
		var context = CreateContext("/api/artists");
		return _fixedWindowRateLimit.InvokeAsync(context);
	}

	[Benchmark]
	public Task SuspiciousClean()
	{
		var context = CreateContext("/api/artists");
		return _suspiciousTrafficGuard.InvokeAsync(context);
	}

	private static DefaultHttpContext CreateContext(string path)
	{
		return new DefaultHttpContext
		{
			Request =
			{
				Path = path
			},
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

	private sealed class TestWebHostEnvironment : IWebHostEnvironment
	{
		public TestWebHostEnvironment(string contentRootPath)
		{
			ContentRootPath = contentRootPath;
		}

		public string ApplicationName { get; set; } = "Opx.Api.Web.Benchmarks";
		public IFileProvider ContentRootFileProvider { get; set; } = null!;
		public string ContentRootPath { get; set; }
		public string EnvironmentName { get; set; } = "Development";
		public string WebRootPath { get; set; } = string.Empty;
		public IFileProvider WebRootFileProvider { get; set; } = null!;
	}
}
