// Copyright (c) 2026 - opx
using System.Net;
using System.Text.Json;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.Configuration;
using NUnit.Framework;

namespace Opx.Api.Web.Tests;

[TestFixture]
public class OpxEndpointProxyTests
{
	[Test]
	public async Task EndpointProxy_RedirectMode_AutomaticallyMapsAlias()
	{
		await using var app = await CreateAppAsync(new Dictionary<string, string?>
		{
			["OpxApiProtection:EndpointProxy:Enabled"] = "true",
			["OpxApiProtection:EndpointProxy:Mode"] = "Redirect",
			["OpxApiProtection:EndpointProxy:Routes:/_sys/audit/a1"] = "/target/access"
		});
		var client = app.GetTestClient();

		var response = await client.GetAsync("/_sys/audit/a1?take=1");

		Assert.Multiple(() =>
		{
			Assert.That(response.StatusCode, Is.EqualTo(HttpStatusCode.Redirect));
			Assert.That(response.Headers.Location?.ToString(), Is.EqualTo("/target/access?take=1"));
		});
	}

	[Test]
	public async Task EndpointProxy_RewriteMode_ForwardsWithoutLocationHeader()
	{
		await using var app = await CreateAppAsync(new Dictionary<string, string?>
		{
			["OpxApiProtection:EndpointProxy:Enabled"] = "true",
			["OpxApiProtection:EndpointProxy:Mode"] = "Rewrite",
			["OpxApiProtection:EndpointProxy:Routes:/_sys/audit/a1"] = "/target/access"
		});
		var client = app.GetTestClient();

		var response = await client.GetAsync("/_sys/audit/a1?take=1");
		var content = await response.Content.ReadAsStringAsync();

		Assert.Multiple(() =>
		{
			Assert.That(response.StatusCode, Is.EqualTo(HttpStatusCode.OK));
			Assert.That(response.Headers.Location, Is.Null);
			Assert.That(content, Is.EqualTo("access-log"));
		});
	}

	[Test]
	public async Task EndpointProxy_WithApiKey_BlocksMissingKeyAndAllowsValidKey()
	{
		await using var app = await CreateAppAsync(new Dictionary<string, string?>
		{
			["OpxApiProtection:EndpointProxy:Enabled"] = "true",
			["OpxApiProtection:EndpointProxy:Mode"] = "Rewrite",
			["OpxApiProtection:EndpointProxy:ApiKey"] = "secret",
			["OpxApiProtection:EndpointProxy:Routes:/_sys/audit/a1"] = "/target/access"
		});
		var client = app.GetTestClient();

		var blocked = await client.GetAsync("/_sys/audit/a1");
		var blockedBody = await ReadJsonAsync(blocked);
		client.DefaultRequestHeaders.Add("X-Opx-Proxy-Key", "secret");
		var allowed = await client.GetAsync("/_sys/audit/a1");
		var allowedBody = await allowed.Content.ReadAsStringAsync();

		Assert.Multiple(() =>
		{
			Assert.That(blocked.StatusCode, Is.EqualTo(HttpStatusCode.OK));
			Assert.That(blockedBody.GetProperty("result").GetBoolean(), Is.False);
			Assert.That(blockedBody.GetProperty("statusCode").GetString(), Is.EqualTo(((int)HttpStatusCode.Unauthorized).ToString()));
			Assert.That(allowed.StatusCode, Is.EqualTo(HttpStatusCode.OK));
			Assert.That(allowedBody, Is.EqualTo("access-log"));
		});
	}

	[Test]
	public async Task EndpointProxy_RewriteMode_EnforcesTargetAuthorizationMetadata()
	{
		await using var app = await CreateAppAsync(new Dictionary<string, string?>
		{
			["OpxApiProtection:EndpointProxy:Enabled"] = "true",
			["OpxApiProtection:EndpointProxy:Mode"] = "Rewrite",
			["OpxApiProtection:EndpointProxy:ApiKey"] = "secret",
			["OpxApiProtection:EndpointProxy:Routes:/_sys/private/a1"] = "/target/private"
		}, mapPrivateEndpoint: true);
		var client = app.GetTestClient();
		client.DefaultRequestHeaders.Add("X-Opx-Proxy-Key", "secret");

		var response = await client.GetAsync("/_sys/private/a1");
		var body = await ReadJsonAsync(response);

		Assert.Multiple(() =>
		{
			Assert.That(response.StatusCode, Is.EqualTo(HttpStatusCode.OK));
			Assert.That(body.GetProperty("result").GetBoolean(), Is.False);
			Assert.That(body.GetProperty("statusCode").GetString(), Is.EqualTo(((int)HttpStatusCode.Unauthorized).ToString()));
			Assert.That(body.GetProperty("data").GetProperty("id").GetString(), Is.EqualTo("EndpointProxy"));
		});
	}

	private static async Task<WebApplication> CreateAppAsync(Dictionary<string, string?> values, bool mapPrivateEndpoint = false)
	{
		var builder = WebApplication.CreateBuilder();
		builder.WebHost.UseTestServer();
		builder.Configuration.AddInMemoryCollection(values);
		builder.Services.AddOpxApiWeb(builder.Configuration);

		var app = builder.Build();
		app.UseOpxWebApiHandler();
		app.MapGet("/target/access", () => "access-log");
		if (mapPrivateEndpoint)
		{
			app.MapGet("/target/private", () => "private-log").RequireAuthorization();
		}
		await app.StartAsync();

		return app;
	}

	private static async Task<JsonElement> ReadJsonAsync(HttpResponseMessage response)
	{
		await using var stream = await response.Content.ReadAsStreamAsync();
		using var document = await JsonDocument.ParseAsync(stream);
		return document.RootElement.Clone();
	}
}
