// Copyright (c) 2026 - opx
using System.Net;
using BenchmarkDotNet.Attributes;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.Configuration;
using Opx.Api.Web;

[MemoryDiagnoser]
[SimpleJob(warmupCount: 3, iterationCount: 8)]
public class OpxEndpointProxyBenchmarks
{
	private WebApplication _redirectApp = null!;
	private WebApplication _rewriteApp = null!;
	private HttpClient _redirectClient = null!;
	private HttpClient _rewriteClient = null!;

	[GlobalSetup]
	public async Task SetupAsync()
	{
		_redirectApp = await CreateAppAsync("Redirect");
		_rewriteApp = await CreateAppAsync("Rewrite");
		_redirectClient = _redirectApp.GetTestClient();
		_rewriteClient = _rewriteApp.GetTestClient();
		_redirectClient.DefaultRequestHeaders.Add("X-Opx-Proxy-Key", "benchmark-secret");
		_rewriteClient.DefaultRequestHeaders.Add("X-Opx-Proxy-Key", "benchmark-secret");
	}

	[GlobalCleanup]
	public async Task CleanupAsync()
	{
		_redirectClient.Dispose();
		_rewriteClient.Dispose();
		await _redirectApp.DisposeAsync();
		await _rewriteApp.DisposeAsync();
	}

	[Benchmark(Baseline = true)]
	public async Task<HttpStatusCode> EndpointProxyRedirect()
	{
		var response = await _redirectClient.GetAsync("/_bench/a1?take=1", HttpCompletionOption.ResponseHeadersRead);
		return response.StatusCode;
	}

	[Benchmark]
	public async Task<string> EndpointProxyRewrite()
	{
		return await _rewriteClient.GetStringAsync("/_bench/a1?take=1");
	}

	[Benchmark]
	public async Task<string> DirectTarget()
	{
		return await _rewriteClient.GetStringAsync("/target/access?take=1");
	}

	private static async Task<WebApplication> CreateAppAsync(string mode)
	{
		var builder = WebApplication.CreateBuilder();
		builder.WebHost.UseTestServer();
		builder.Configuration.AddInMemoryCollection(new Dictionary<string, string?>
		{
			["OpxApiProtection:EndpointProxy:Enabled"] = "true",
			["OpxApiProtection:EndpointProxy:Mode"] = mode,
			["OpxApiProtection:EndpointProxy:ApiKey"] = "benchmark-secret",
			["OpxApiProtection:EndpointProxy:Routes:/_bench/a1"] = "/target/access"
		});
		builder.Services.AddOpxApiWeb(builder.Configuration);

		var app = builder.Build();
		app.UseOpxWebApiHandler();
		app.MapGet("/target/access", () => "access-log");
		await app.StartAsync();

		return app;
	}
}
