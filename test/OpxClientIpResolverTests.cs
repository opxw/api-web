// Copyright (c) 2026 - opx
using System.Diagnostics;
using System.Net;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Configuration;
using NUnit.Framework;
using Opx.Api.Web.Protection;

namespace Opx.Api.Web.Tests;

[TestFixture]
public sealed class OpxClientIpResolverTests
{
	[Test]
	public void Resolve_DefaultConfiguration_IgnoresSpoofedForwardedHeader()
	{
		var context = CreateContext("198.51.100.10");
		context.Request.Headers["X-Forwarded-For"] = "203.0.113.99";

		var result = OpxClientIpResolver.Resolve(context, CreateConfiguration([]));

		Assert.That(result.Text, Is.EqualTo("198.51.100.10"));
	}

	[Test]
	public void Resolve_WhenForwardingDisabled_IgnoresHeaderFromTrustedProxy()
	{
		var configuration = CreateConfiguration(new()
		{
			["OpxApiProtection:ClientIp:TrustForwardedHeaders"] = "false",
			["OpxApiProtection:ClientIp:TrustedProxies:0"] = "10.0.0.5"
		});
		var context = CreateContext("10.0.0.5");
		context.Request.Headers["X-Real-IP"] = "203.0.113.10";

		var result = OpxClientIpResolver.Resolve(context, configuration);

		Assert.That(result.Text, Is.EqualTo("10.0.0.5"));
	}

	[Test]
	public void Resolve_CloudflareTunnelFromLoopback_UsesCloudflareConnectingIp()
	{
		var configuration = CreateConfiguration(new()
		{
			["OpxApiProtection:ClientIp:TrustForwardedHeaders"] = "true",
			["OpxApiProtection:ClientIp:HeaderNames:0"] = "CF-Connecting-IP"
		});
		var context = CreateContext("127.0.0.1");
		context.Request.Headers["CF-Connecting-IP"] = "203.0.113.10";

		var result = OpxClientIpResolver.Resolve(context, configuration);

		Assert.That(result.Text, Is.EqualTo("203.0.113.10"));
	}

	[Test]
	public void Resolve_DirectOriginRequestCannotSpoofCloudflareHeader()
	{
		var configuration = CreateConfiguration(new()
		{
			["OpxApiProtection:ClientIp:TrustForwardedHeaders"] = "true",
			["OpxApiProtection:ClientIp:HeaderNames:0"] = "CF-Connecting-IP"
		});
		var context = CreateContext("198.51.100.77");
		context.Request.Headers["CF-Connecting-IP"] = "203.0.113.10";

		var result = OpxClientIpResolver.Resolve(context, configuration);

		Assert.That(result.Text, Is.EqualTo("198.51.100.77"));
	}

	[Test]
	public void ResolveDetails_CloudflareTunnel_ReportsClientPeerAndSource()
	{
		var configuration = CreateConfiguration(new()
		{
			["OpxApiProtection:ClientIp:TrustForwardedHeaders"] = "true",
			["OpxApiProtection:ClientIp:HeaderNames:0"] = "CF-Connecting-IP"
		});
		var context = CreateContext("127.0.0.1");
		context.Request.Headers["CF-Connecting-IP"] = "203.0.113.15";

		var result = OpxClientIpResolver.ResolveDetails(context, configuration);

		Assert.Multiple(() =>
		{
			Assert.That(result.Text, Is.EqualTo("203.0.113.15"));
			Assert.That(result.PeerText, Is.EqualTo("127.0.0.1"));
			Assert.That(result.Source, Is.EqualTo("CF-Connecting-IP"));
		});
	}

	[Test]
	public void Resolve_TrustedProxy_UsesConfiguredRealIpHeader()
	{
		var configuration = TrustedConfiguration("10.0.0.5", "X-Real-IP");
		var context = CreateContext("10.0.0.5");
		context.Request.Headers["X-Real-IP"] = "203.0.113.10";

		var result = OpxClientIpResolver.Resolve(context, configuration);

		Assert.That(result.Text, Is.EqualTo("203.0.113.10"));
	}

	[Test]
	public void Resolve_TrustedNetwork_UsesForwardedHeader()
	{
		var configuration = CreateConfiguration(new()
		{
			["OpxApiProtection:ClientIp:TrustForwardedHeaders"] = "true",
			["OpxApiProtection:ClientIp:TrustedNetworks:0"] = "10.20.0.0/16",
			["OpxApiProtection:ClientIp:HeaderNames:0"] = "X-Forwarded-For"
		});
		var context = CreateContext("10.20.4.8");
		context.Request.Headers["X-Forwarded-For"] = "203.0.113.20";

		var result = OpxClientIpResolver.Resolve(context, configuration);

		Assert.That(result.Text, Is.EqualTo("203.0.113.20"));
	}

	[Test]
	public void Resolve_XForwardedForWithPrependedSpoof_SelectsNearestUntrustedHop()
	{
		var configuration = TrustedConfiguration("10.0.0.5", "X-Forwarded-For");
		var context = CreateContext("10.0.0.5");
		context.Request.Headers["X-Forwarded-For"] = "192.0.2.250, 203.0.113.25";

		var result = OpxClientIpResolver.Resolve(context, configuration);

		Assert.That(result.Text, Is.EqualTo("203.0.113.25"));
	}

	[Test]
	public void Resolve_XForwardedForWithMalformedNearestHop_FailsClosedToPeer()
	{
		var configuration = TrustedConfiguration("10.0.0.5", "X-Forwarded-For");
		var context = CreateContext("10.0.0.5");
		context.Request.Headers["X-Forwarded-For"] = "192.0.2.250, not-an-ip";

		var result = OpxClientIpResolver.Resolve(context, configuration);

		Assert.That(result.Text, Is.EqualTo("10.0.0.5"));
	}

	[Test]
	public void Resolve_XForwardedForWithMultipleTrustedProxies_SelectsClient()
	{
		var configuration = CreateConfiguration(new()
		{
			["OpxApiProtection:ClientIp:TrustForwardedHeaders"] = "true",
			["OpxApiProtection:ClientIp:TrustedNetworks:0"] = "10.0.0.0/8",
			["OpxApiProtection:ClientIp:HeaderNames:0"] = "X-Forwarded-For"
		});
		var context = CreateContext("10.0.0.5");
		context.Request.Headers["X-Forwarded-For"] = "203.0.113.30, 10.0.0.20, 10.0.0.10";

		var result = OpxClientIpResolver.Resolve(context, configuration);

		Assert.That(result.Text, Is.EqualTo("203.0.113.30"));
	}

	[Test]
	public void Resolve_ConfiguredHeaderOrder_PrefersCloudflareOverXForwardedFor()
	{
		var configuration = CreateConfiguration(new()
		{
			["OpxApiProtection:ClientIp:TrustForwardedHeaders"] = "true",
			["OpxApiProtection:ClientIp:HeaderNames:0"] = "CF-Connecting-IP",
			["OpxApiProtection:ClientIp:HeaderNames:1"] = "X-Forwarded-For"
		});
		var context = CreateContext("::1");
		context.Request.Headers["CF-Connecting-IP"] = "203.0.113.40";
		context.Request.Headers["X-Forwarded-For"] = "192.0.2.40";

		var result = OpxClientIpResolver.Resolve(context, configuration);

		Assert.That(result.Text, Is.EqualTo("203.0.113.40"));
	}

	[Test]
	public void Resolve_InvalidPreferredHeader_FallsBackToNextValidHeader()
	{
		var configuration = CreateConfiguration(new()
		{
			["OpxApiProtection:ClientIp:TrustForwardedHeaders"] = "true",
			["OpxApiProtection:ClientIp:HeaderNames:0"] = "CF-Connecting-IP",
			["OpxApiProtection:ClientIp:HeaderNames:1"] = "X-Real-IP"
		});
		var context = CreateContext("127.0.0.1");
		context.Request.Headers["CF-Connecting-IP"] = "not-an-ip";
		context.Request.Headers["X-Real-IP"] = "203.0.113.50";

		var result = OpxClientIpResolver.Resolve(context, configuration);

		Assert.That(result.Text, Is.EqualTo("203.0.113.50"));
	}

	[Test]
	public void Resolve_WhenEveryConfiguredHeaderNameIsInvalid_DoesNotUseDefaultHeader()
	{
		var configuration = CreateConfiguration(new()
		{
			["OpxApiProtection:ClientIp:TrustForwardedHeaders"] = "true",
			["OpxApiProtection:ClientIp:TrustedProxies:0"] = "10.0.0.5",
			["OpxApiProtection:ClientIp:HeaderNames:0"] = "Bad Header"
		});
		var context = CreateContext("10.0.0.5");
		context.Request.Headers["X-Forwarded-For"] = "203.0.113.55";

		var result = OpxClientIpResolver.Resolve(context, configuration);

		Assert.That(result.Text, Is.EqualTo("10.0.0.5"));
	}

	[TestCase("203.0.113.60:52120", "203.0.113.60")]
	[TestCase("[2001:db8::60]:52120", "2001:db8::60")]
	public void Resolve_ForwardedIpWithPort_ExtractsAddress(string value, string expected)
	{
		var configuration = TrustedConfiguration("10.0.0.5", "X-Real-IP");
		var context = CreateContext("10.0.0.5");
		context.Request.Headers["X-Real-IP"] = value;

		var result = OpxClientIpResolver.Resolve(context, configuration);

		Assert.That(result.Text, Is.EqualTo(expected));
	}

	[Test]
	public void Resolve_IPv4MappedPeer_NormalizesFallbackAddress()
	{
		var context = CreateContext("::ffff:198.51.100.80");

		var result = OpxClientIpResolver.Resolve(context, CreateConfiguration([]));

		Assert.That(result.Text, Is.EqualTo("198.51.100.80"));
	}

	[Test]
	public void Resolve_TrustAnyProxy_UsesNearestForwardedAddress()
	{
		var configuration = CreateConfiguration(new()
		{
			["OpxApiProtection:ClientIp:TrustForwardedHeaders"] = "true",
			["OpxApiProtection:ClientIp:TrustAnyProxy"] = "true",
			["OpxApiProtection:ClientIp:HeaderNames:0"] = "X-Forwarded-For"
		});
		var context = CreateContext("10.0.0.5");
		context.Request.Headers["X-Forwarded-For"] = "192.0.2.90, 203.0.113.90";

		var result = OpxClientIpResolver.Resolve(context, configuration);

		Assert.That(result.Text, Is.EqualTo("203.0.113.90"));
	}

	[Test]
	public void Resolve_WhenForwardedChainExceedsConfiguredLimit_FailsClosedToPeer()
	{
		var configuration = CreateConfiguration(new()
		{
			["OpxApiProtection:ClientIp:TrustForwardedHeaders"] = "true",
			["OpxApiProtection:ClientIp:TrustedNetworks:0"] = "10.0.0.0/8",
			["OpxApiProtection:ClientIp:HeaderNames:0"] = "X-Forwarded-For",
			["OpxApiProtection:ClientIp:MaxForwardedEntries"] = "2"
		});
		var context = CreateContext("10.0.0.5");
		context.Request.Headers["X-Forwarded-For"] = "203.0.113.95, 10.0.0.30, 10.0.0.20";

		var result = OpxClientIpResolver.Resolve(context, configuration);

		Assert.That(result.Text, Is.EqualTo("10.0.0.5"));
	}

	[Test]
	public void Resolve_WhenHeaderExceedsConfiguredLength_IgnoresIt()
	{
		var configuration = CreateConfiguration(new()
		{
			["OpxApiProtection:ClientIp:TrustForwardedHeaders"] = "true",
			["OpxApiProtection:ClientIp:TrustedProxies:0"] = "10.0.0.5",
			["OpxApiProtection:ClientIp:HeaderNames:0"] = "X-Forwarded-For",
			["OpxApiProtection:ClientIp:MaxHeaderValueLength"] = "64"
		});
		var context = CreateContext("10.0.0.5");
		context.Request.Headers["X-Forwarded-For"] = string.Concat(new string('1', 70), ", 203.0.113.96");

		var result = OpxClientIpResolver.Resolve(context, configuration);

		Assert.That(result.Text, Is.EqualTo("10.0.0.5"));
	}

	[Test]
	public void Resolve_AfterConfigurationReload_AppliesNewTrustSetting()
	{
		var configuration = (IConfigurationRoot)CreateConfiguration(new()
		{
			["OpxApiProtection:ClientIp:TrustForwardedHeaders"] = "false",
			["OpxApiProtection:ClientIp:TrustedProxies:0"] = "10.0.0.5",
			["OpxApiProtection:ClientIp:HeaderNames:0"] = "X-Real-IP"
		});
		var context = CreateContext("10.0.0.5");
		context.Request.Headers["X-Real-IP"] = "203.0.113.100";
		Assert.That(OpxClientIpResolver.Resolve(context, configuration).Text, Is.EqualTo("10.0.0.5"));

		configuration["OpxApiProtection:ClientIp:TrustForwardedHeaders"] = "true";
		configuration.Reload();

		Assert.That(OpxClientIpResolver.Resolve(context, configuration).Text, Is.EqualTo("203.0.113.100"));
	}

	[Test]
	public void Resolve_FiveThousandTrustedRequests_CompletesWithinOneSecond()
	{
		var configuration = TrustedConfiguration("10.0.0.5", "CF-Connecting-IP");
		var context = CreateContext("10.0.0.5");
		context.Request.Headers["CF-Connecting-IP"] = "203.0.113.110";
		_ = OpxClientIpResolver.Resolve(context, configuration);
		var stopwatch = Stopwatch.StartNew();

		for (var index = 0; index < 5000; index++)
		{
			_ = OpxClientIpResolver.Resolve(context, configuration);
		}

		stopwatch.Stop();
		TestContext.Out.WriteLine($"Client IP resolver 5000 trusted requests: {stopwatch.ElapsedMilliseconds} ms");
		Assert.That(stopwatch.Elapsed, Is.LessThan(TimeSpan.FromSeconds(1)));
	}

	[Test]
	public void Validate_InvalidTrustedNetworkAndForwardLimit_ReturnsErrors()
	{
		var configuration = CreateConfiguration(new()
		{
			["OpxApiProtection:ClientIp:TrustedNetworks:0"] = "10.0.0.0/88",
			["OpxApiProtection:ClientIp:MaxForwardedEntries"] = "0",
			["OpxApiProtection:ClientIp:MaxHeaderValueLength"] = "10",
			["OpxApiProtection:ClientIp:HeaderNames:0"] = "Bad Header"
		});

		var errors = OpxProtectionConfigurationValidator.Validate(configuration).ToArray();

		Assert.Multiple(() =>
		{
			Assert.That(errors.Any(error => error.Contains("TrustedNetworks", StringComparison.Ordinal)), Is.True);
			Assert.That(errors.Any(error => error.Contains("MaxForwardedEntries", StringComparison.Ordinal)), Is.True);
			Assert.That(errors.Any(error => error.Contains("MaxHeaderValueLength", StringComparison.Ordinal)), Is.True);
			Assert.That(errors.Any(error => error.Contains("invalid HTTP header", StringComparison.Ordinal)), Is.True);
		});
	}

	private static IConfiguration TrustedConfiguration(string proxy, string header)
	{
		return CreateConfiguration(new()
		{
			["OpxApiProtection:ClientIp:TrustForwardedHeaders"] = "true",
			["OpxApiProtection:ClientIp:TrustedProxies:0"] = proxy,
			["OpxApiProtection:ClientIp:HeaderNames:0"] = header
		});
	}

	private static DefaultHttpContext CreateContext(string remoteIp)
	{
		var context = new DefaultHttpContext();
		context.Connection.RemoteIpAddress = IPAddress.Parse(remoteIp);
		return context;
	}

	private static IConfiguration CreateConfiguration(Dictionary<string, string?> values)
	{
		return new ConfigurationBuilder().AddInMemoryCollection(values).Build();
	}
}
