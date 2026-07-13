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
	public async Task EndpointProxy_NewSection_RedirectMode_AutomaticallyMapsAlias()
	{
		await using var app = await CreateAppAsync(new Dictionary<string, string?>
		{
			["OpxEndpointProxy:Enabled"] = "true",
			["OpxEndpointProxy:Mode"] = "Redirect",
			["OpxEndpointProxy:Routes:/_sys/audit/a1"] = "/target/access"
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

	[Test]
	public async Task EndpointProxy_RewriteMode_ForwardsRouteTemplateValues()
	{
		await using var app = await CreateAppAsync(new Dictionary<string, string?>
		{
			["OpxApiProtection:EndpointProxy:Enabled"] = "true",
			["OpxApiProtection:EndpointProxy:Mode"] = "Rewrite",
			["OpxApiProtection:EndpointProxy:Routes:/gw/music/artists/{id}/albums"] = "/target/artists/{id}/albums"
		}, mapTemplateEndpoint: true);
		var client = app.GetTestClient();

		var response = await client.GetAsync("/gw/music/artists/42/albums?take=1");
		var body = await response.Content.ReadAsStringAsync();

		Assert.Multiple(() =>
		{
			Assert.That(response.StatusCode, Is.EqualTo(HttpStatusCode.OK));
			Assert.That(response.Headers.Location, Is.Null);
			Assert.That(body, Is.EqualTo("artist:42"));
		});
	}

	[Test]
	public async Task EndpointProxy_ConfiguredMethods_AllowsPostGatewayAlias()
	{
		await using var app = await CreateAppAsync(new Dictionary<string, string?>
		{
			["OpxApiProtection:EndpointProxy:Enabled"] = "true",
			["OpxApiProtection:EndpointProxy:Mode"] = "Rewrite",
			["OpxApiProtection:EndpointProxy:Methods:0"] = "GET",
			["OpxApiProtection:EndpointProxy:Methods:1"] = "POST",
			["OpxApiProtection:EndpointProxy:Routes:/gw/music/artists/{id}/albums"] = "/target/artists/{id}/albums"
		}, mapTemplateEndpoint: true);
		var client = app.GetTestClient();

		var response = await client.PostAsync("/gw/music/artists/42/albums", null);
		var body = await response.Content.ReadAsStringAsync();

		Assert.Multiple(() =>
		{
			Assert.That(response.StatusCode, Is.EqualTo(HttpStatusCode.OK));
			Assert.That(body, Is.EqualTo("artist-post:42"));
		});
	}

	[Test]
	public async Task EndpointProxy_RewriteMode_MatchesConstrainedTargetRoute()
	{
		await using var app = await CreateAppAsync(new Dictionary<string, string?>
		{
			["OpxApiProtection:EndpointProxy:Enabled"] = "true",
			["OpxApiProtection:EndpointProxy:Mode"] = "Rewrite",
			["OpxApiProtection:EndpointProxy:Routes:/gw/music/artists/{id}"] = "/target/constrained-artists/{id}"
		}, mapConstrainedEndpoint: true);
		var client = app.GetTestClient();

		var response = await client.GetAsync("/gw/music/artists/42");
		var body = await response.Content.ReadAsStringAsync();

		Assert.Multiple(() =>
		{
			Assert.That(response.StatusCode, Is.EqualTo(HttpStatusCode.OK));
			Assert.That(body, Is.EqualTo("constrained-artist:42"));
		});
	}

	[Test]
	public async Task EndpointProxy_RedirectMode_ExpandsRouteTemplateValues()
	{
		await using var app = await CreateAppAsync(new Dictionary<string, string?>
		{
			["OpxApiProtection:EndpointProxy:Enabled"] = "true",
			["OpxApiProtection:EndpointProxy:Mode"] = "Redirect",
			["OpxApiProtection:EndpointProxy:Routes:/gw/music/artists/{id}"] = "/api/artists/{id}"
		});
		var client = app.GetTestClient();

		var response = await client.GetAsync("/gw/music/artists/42?take=1");

		Assert.Multiple(() =>
		{
			Assert.That(response.StatusCode, Is.EqualTo(HttpStatusCode.Redirect));
			Assert.That(response.Headers.Location?.ToString(), Is.EqualTo("/api/artists/42?take=1"));
		});
	}

	[Test]
	public async Task EndpointProxy_RouteMapPath_LoadsRoutesFromAppData()
	{
		var root = CreateTempDirectory();
		var appData = Path.Combine(root, "App_Data");
		Directory.CreateDirectory(appData);
		await File.WriteAllTextAsync(Path.Combine(appData, "opx-endpoint-routes.json"), """
		{
		  "Routes": [
		    {
		      "Enabled": true,
		      "Alias": "/gw/music/artists/{id}",
		      "Target": "/target/artists/{id}/albums",
		      "Methods": [ "GET" ]
		    }
		  ]
		}
		""");

		try
		{
			await using var app = await CreateAppAsync(new Dictionary<string, string?>
			{
				["OpxEndpointProxy:Enabled"] = "true",
				["OpxEndpointProxy:Mode"] = "Rewrite",
				["OpxEndpointProxy:RouteMapPath"] = "App_Data/opx-endpoint-routes.json"
			}, mapTemplateEndpoint: true, contentRootPath: root);
			var client = app.GetTestClient();

			var response = await client.GetAsync("/gw/music/artists/42");
			var body = await response.Content.ReadAsStringAsync();

			Assert.Multiple(() =>
			{
				Assert.That(response.StatusCode, Is.EqualTo(HttpStatusCode.OK));
				Assert.That(body, Is.EqualTo("artist:42"));
			});
		}
		finally
		{
			Directory.Delete(root, true);
		}
	}

	[Test]
	public void EndpointProxy_DuplicateAlias_WhenFailOnConflict_ThrowsOnStartup()
	{
		Assert.ThrowsAsync<InvalidOperationException>(async () =>
		{
			await using var app = await CreateAppAsync(new Dictionary<string, string?>
			{
				["OpxEndpointProxy:Enabled"] = "true",
				["OpxEndpointProxy:FailOnConflict"] = "true",
				["OpxEndpointProxy:Routes:0:Alias"] = "/gw/music/artists",
				["OpxEndpointProxy:Routes:0:Target"] = "/target/access",
				["OpxEndpointProxy:Routes:1:Alias"] = "/gw/music/artists",
				["OpxEndpointProxy:Routes:1:Target"] = "/target/other"
			});
		});
	}

	[Test]
	public void EndpointProxy_AliasOutsideAllowedPrefixes_WhenFailOnConflict_ThrowsOnStartup()
	{
		Assert.ThrowsAsync<InvalidOperationException>(async () =>
		{
			await using var app = await CreateAppAsync(new Dictionary<string, string?>
			{
				["OpxEndpointProxy:Enabled"] = "true",
				["OpxEndpointProxy:FailOnConflict"] = "true",
				["OpxEndpointProxy:AllowedAliasPrefixes:0"] = "/gw",
				["OpxEndpointProxy:Routes:/admin/raw"] = "/target/access"
			});
		});
	}

	[Test]
	public void EndpointProxy_AliasConflictsWithExistingEndpoint_WhenFailOnConflict_ThrowsOnStartup()
	{
		Assert.ThrowsAsync<InvalidOperationException>(async () =>
		{
			await using var app = await CreateAppAsync(new Dictionary<string, string?>
			{
				["OpxEndpointProxy:Enabled"] = "true",
				["OpxEndpointProxy:FailOnConflict"] = "true",
				["OpxEndpointProxy:Routes:/gw/music/artists"] = "/target/access"
			}, mapExistingAliasBeforeProxy: true);
		});
	}

	private static async Task<WebApplication> CreateAppAsync(Dictionary<string, string?> values, bool mapPrivateEndpoint = false, bool mapTemplateEndpoint = false, bool mapConstrainedEndpoint = false, string? contentRootPath = null, bool mapExistingAliasBeforeProxy = false)
	{
		var builder = WebApplication.CreateBuilder();
		builder.WebHost.UseTestServer();
		if (!string.IsNullOrWhiteSpace(contentRootPath))
		{
			builder.Environment.ContentRootPath = contentRootPath;
		}
		builder.Configuration.AddInMemoryCollection(values);
		builder.Services.AddOpxApiWeb(builder.Configuration);

		var app = builder.Build();
		if (mapExistingAliasBeforeProxy)
		{
			app.MapGet("/gw/music/artists", () => "custom-artists");
		}
		app.UseOpxWebApiHandler();
		app.MapGet("/target/access", () => "access-log");
		if (mapPrivateEndpoint)
		{
			app.MapGet("/target/private", () => "private-log").RequireAuthorization();
		}
		if (mapTemplateEndpoint)
		{
			app.MapGet("/target/artists/{id}/albums", (string id) => $"artist:{id}");
			app.MapPost("/target/artists/{id}/albums", (string id) => $"artist-post:{id}");
		}
		if (mapConstrainedEndpoint)
		{
			app.MapGet("/target/constrained-artists/{id:int}", (int id) => $"constrained-artist:{id}");
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

	private static string CreateTempDirectory()
	{
		var path = Path.Combine(Path.GetTempPath(), "opx-endpoint-proxy-tests", Guid.NewGuid().ToString("N"));
		Directory.CreateDirectory(path);
		return path;
	}
}
