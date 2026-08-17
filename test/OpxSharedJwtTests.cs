// Copyright (c) 2026 - opx
using System.IdentityModel.Tokens.Jwt;
using System.Net;
using System.Security.Claims;
using System.Text;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.IdentityModel.Tokens;
using NUnit.Framework;
using Opx.Api.Web.Jwt;

namespace Opx.Api.Web.Tests;

[TestFixture]
public class OpxSharedJwtTests
{
	private const string Secret = "opx-shared-jwt-test-secret-key-32-bytes-minimum";

	[Test]
	public void SharedJwtIssuer_CreatesSignedTokenWithSecurityAndDeviceClaims()
	{
		var settings = CreateSettings();
		using var services = new ServiceCollection()
			.AddOpxSharedJwtTokenIssuer(settings)
			.BuildServiceProvider();
		var issuer = services.GetRequiredService<IOpxSharedJwtTokenService>();
		var authenticatedAt = DateTimeOffset.UtcNow.AddMinutes(-1);

		var token = issuer.CreateToken(new OpxSharedJwtTokenRequest
		{
			Subject = "user-17",
			Name = "opx",
			SessionId = "session-mobile-1",
			Roles = ["admin", "auditor"],
			Scopes = ["sales.read", "reports.read"],
			LoginIpAddress = "203.0.113.10",
			Device = new OpxSharedJwtDeviceMetadata
			{
				DeviceId = "install-a91",
				DeviceType = "mobile",
				DeviceName = "OPX Phone",
				Platform = "Android",
				ClientApplication = "Trust Mobile",
				ClientVersion = "3.2.1"
			},
			Security = new OpxSharedJwtSecurityContext
			{
				AuthenticationMethods = ["pwd", "otp"],
				AuthenticationContext = "urn:opx:loa:2",
				AuthenticatedAt = authenticatedAt
			}
		});

		var principal = ValidateToken(token.AccessToken, settings);
		var jwt = new JwtSecurityTokenHandler().ReadJwtToken(token.AccessToken);
		var httpContext = new DefaultHttpContext
		{
			User = principal
		};
		httpContext.Connection.RemoteIpAddress = IPAddress.Parse("203.0.113.10");
		httpContext.Request.Headers["X-Request-ID"] = "request-shared-jwt-1";
		var requestContext = httpContext.GetOpxJwtRequestContext();

		Assert.Multiple(() =>
		{
			Assert.That(token.TokenType, Is.EqualTo("Bearer"));
			Assert.That(token.SessionId, Is.EqualTo("session-mobile-1"));
			Assert.That(token.JwtId, Is.Not.Empty);
			Assert.That(token.ExpiresAt, Is.GreaterThan(DateTimeOffset.UtcNow));
			Assert.That(principal.FindFirst(ClaimTypes.NameIdentifier)?.Value, Is.EqualTo("user-17"));
			Assert.That(principal.FindAll(ClaimTypes.Role).Select(claim => claim.Value), Is.EquivalentTo(new[] { "admin", "auditor" }));
			Assert.That(principal.FindFirst(OpxJwtClaimNames.Scope)?.Value, Is.EqualTo("sales.read reports.read"));
			Assert.That(jwt.Claims.Where(claim => claim.Type == OpxJwtClaimNames.AuthenticationMethod).Select(claim => claim.Value), Is.EquivalentTo(new[] { "pwd", "otp" }));
			Assert.That(jwt.Claims.First(claim => claim.Type == OpxJwtClaimNames.AuthenticationContext).Value, Is.EqualTo("urn:opx:loa:2"));
			Assert.That(principal.FindFirst(OpxJwtClaimNames.DeviceType)?.Value, Is.EqualTo("mobile"));
			Assert.That(principal.FindFirst(OpxJwtClaimNames.DeviceName)?.Value, Is.EqualTo("OPX Phone"));
			Assert.That(principal.FindFirst(OpxJwtClaimNames.LoginIpAddress)?.Value, Is.EqualTo("203.0.113.10"));
			Assert.That(jwt.Header.Alg, Is.EqualTo(SecurityAlgorithms.HmacSha256));
			Assert.That(requestContext.Subject, Is.EqualTo("user-17"));
			Assert.That(requestContext.SessionId, Is.EqualTo("session-mobile-1"));
			Assert.That(requestContext.AuthenticationMethods, Is.EquivalentTo(new[] { "pwd", "otp" }));
			Assert.That(requestContext.AuthenticationContext, Is.EqualTo("urn:opx:loa:2"));
			Assert.That(requestContext.AuthenticatedAt, Is.Not.Null);
			Assert.That(requestContext.DeviceId, Is.EqualTo("install-a91"));
			Assert.That(requestContext.LoginIpMatchesCurrent, Is.True);
			Assert.That(requestContext.RequestId, Is.EqualTo("request-shared-jwt-1"));
		});
	}

	[Test]
	public void SharedJwtIssuer_WhenIdsAreNotProvided_GeneratesUniqueSessionAndTokenIds()
	{
		using var services = new ServiceCollection()
			.AddOpxSharedJwtTokenIssuer(CreateSettings())
			.BuildServiceProvider();
		var issuer = services.GetRequiredService<IOpxSharedJwtTokenService>();

		var first = issuer.CreateToken(new OpxSharedJwtTokenRequest { Subject = "user-17" });
		var second = issuer.CreateToken(new OpxSharedJwtTokenRequest { Subject = "user-17" });

		Assert.Multiple(() =>
		{
			Assert.That(first.JwtId, Is.Not.EqualTo(second.JwtId));
			Assert.That(first.SessionId, Is.Not.EqualTo(second.SessionId));
			Assert.That(first.AccessToken, Is.Not.EqualTo(second.AccessToken));
		});
	}

	[Test]
	public void SharedJwtIssuer_WhenSecretIsWeak_RejectsTokenCreation()
	{
		var settings = CreateSettings();
		settings.SecretKey = "too-short";
		using var services = new ServiceCollection()
			.AddOpxSharedJwtTokenIssuer(settings)
			.BuildServiceProvider();
		var issuer = services.GetRequiredService<IOpxSharedJwtTokenService>();

		var exception = Assert.Throws<InvalidOperationException>(() =>
			issuer.CreateToken(new OpxSharedJwtTokenRequest { Subject = "user-17" }));

		Assert.That(exception!.Message, Does.Contain("at least 32 bytes"));
	}

	[Test]
	public void GetOpxJwtRequestContext_ReadsClaimsCurrentIpAndRequestId()
	{
		var authenticatedAt = DateTimeOffset.UtcNow.AddMinutes(-2).ToUnixTimeSeconds().ToString();
		var claims = new[]
		{
			new Claim(JwtRegisteredClaimNames.Sub, "user-17"),
			new Claim(JwtRegisteredClaimNames.Jti, "token-1"),
			new Claim(OpxJwtClaimNames.SessionId, "session-1"),
			new Claim(OpxJwtClaimNames.DeviceId, "install-a91"),
			new Claim(OpxJwtClaimNames.DeviceType, "desktop"),
			new Claim(OpxJwtClaimNames.DeviceName, "OFFICE-PC-01"),
			new Claim(OpxJwtClaimNames.Platform, "Windows"),
			new Claim(OpxJwtClaimNames.ClientApplication, "Trust Desktop"),
			new Claim(OpxJwtClaimNames.ClientVersion, "5.0.0"),
			new Claim(OpxJwtClaimNames.LoginIpAddress, "203.0.113.10"),
			new Claim(OpxJwtClaimNames.Scope, "sales.read reports.read"),
			new Claim(OpxJwtClaimNames.AuthenticationMethod, "pwd"),
			new Claim(OpxJwtClaimNames.AuthenticationMethod, "otp"),
			new Claim(OpxJwtClaimNames.AuthenticationContext, "urn:opx:loa:2"),
			new Claim(OpxJwtClaimNames.AuthenticationTime, authenticatedAt),
			new Claim(ClaimTypes.Role, "admin")
		};
		var context = new DefaultHttpContext
		{
			User = new ClaimsPrincipal(new ClaimsIdentity(claims, "Bearer"))
		};
		context.Connection.RemoteIpAddress = IPAddress.Parse("203.0.113.10");
		context.Request.Headers["X-Request-ID"] = "request-71";

		var result = context.GetOpxJwtRequestContext();

		Assert.Multiple(() =>
		{
			Assert.That(result.IsAuthenticated, Is.True);
			Assert.That(result.Subject, Is.EqualTo("user-17"));
			Assert.That(result.SessionId, Is.EqualTo("session-1"));
			Assert.That(result.JwtId, Is.EqualTo("token-1"));
			Assert.That(result.DeviceType, Is.EqualTo("desktop"));
			Assert.That(result.DeviceName, Is.EqualTo("OFFICE-PC-01"));
			Assert.That(result.Scopes, Is.EquivalentTo(new[] { "sales.read", "reports.read" }));
			Assert.That(result.AuthenticationMethods, Is.EquivalentTo(new[] { "pwd", "otp" }));
			Assert.That(result.CurrentIpAddress, Is.EqualTo("203.0.113.10"));
			Assert.That(result.LoginIpMatchesCurrent, Is.True);
			Assert.That(result.RequestId, Is.EqualTo("request-71"));
		});
	}

	private static JwtTokenValidationSetting CreateSettings()
	{
		return new JwtTokenValidationSetting
		{
			SecretKey = Secret,
			Issuer = "opx-auth",
			Audience = "opx-api",
			ExpirationSeconds = 900,
			Algorithm = SecurityAlgorithms.HmacSha256
		};
	}

	private static ClaimsPrincipal ValidateToken(string token, JwtTokenValidationSetting settings)
	{
		return new JwtSecurityTokenHandler().ValidateToken(token, new TokenValidationParameters
		{
			ValidateIssuerSigningKey = true,
			IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(settings.SecretKey)),
			ValidateIssuer = true,
			ValidIssuer = settings.Issuer,
			ValidateAudience = true,
			ValidAudience = settings.Audience,
			ValidateLifetime = true,
			RequireExpirationTime = true,
			ClockSkew = TimeSpan.FromSeconds(settings.ClockSkewSeconds),
			ValidAlgorithms = [settings.Algorithm]
		}, out _);
	}
}
