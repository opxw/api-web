// Copyright (c) 2026 - opx
using System.IdentityModel.Tokens.Jwt;
using System.Net;
using System.Security.Claims;
using System.Text;
using Microsoft.IdentityModel.Tokens;

namespace Opx.Api.Web.Jwt;

internal sealed class OpxSharedJwtTokenService : IOpxSharedJwtTokenService
{
	private readonly IJwtTokenValidationSetting _settings;

	public OpxSharedJwtTokenService(IJwtTokenValidationSetting settings)
	{
		_settings = settings;
	}

	public OpxSharedJwtToken CreateToken(OpxSharedJwtTokenRequest request)
	{
		ArgumentNullException.ThrowIfNull(request);
		var subject = RequireValue(request.Subject, nameof(request.Subject), 256);
		var algorithm = OpxJwtSecurity.ResolveHmacAlgorithm(_settings.Algorithm);
		var secretBytes = Encoding.UTF8.GetBytes(_settings.SecretKey ?? string.Empty);
		OpxJwtSecurity.ValidateSecretLength(secretBytes.Length, algorithm);

		var issuedAt = request.IssuedAt ?? DateTimeOffset.UtcNow;
		var lifetimeSeconds = _settings.ExpirationSeconds > 0 ? _settings.ExpirationSeconds : 900;
		var expiresAt = request.ExpiresAt ?? issuedAt.AddSeconds(lifetimeSeconds);
		if (expiresAt <= issuedAt)
		{
			throw new ArgumentException("Token expiration must be later than its issued time.", nameof(request));
		}

		var jwtId = CleanValue(request.JwtId, 128) ?? Guid.NewGuid().ToString("N");
		var sessionId = CleanValue(request.SessionId, 128) ?? Guid.NewGuid().ToString("N");
		var claims = new List<Claim>
		{
			new(JwtRegisteredClaimNames.Sub, subject),
			new(JwtRegisteredClaimNames.Jti, jwtId),
			new(OpxJwtClaimNames.SessionId, sessionId)
		};

		AddClaim(claims, JwtRegisteredClaimNames.Name, request.Name, 256);
		AddDistinctClaims(claims, ClaimTypes.Role, request.Roles, 128);
		var scopes = CleanValues(request.Scopes, 128);
		if (scopes.Count > 0)
		{
			claims.Add(new Claim(OpxJwtClaimNames.Scope, string.Join(' ', scopes)));
		}

		AddDeviceClaims(claims, request.Device);
		AddLoginIpClaim(claims, request.LoginIpAddress);
		AddSecurityClaims(claims, request.Security, issuedAt);

		var descriptor = new SecurityTokenDescriptor
		{
			Subject = new ClaimsIdentity(claims),
			Issuer = CleanValue(_settings.Issuer, 512),
			Audience = CleanValue(_settings.Audience, 512),
			IssuedAt = issuedAt.UtcDateTime,
			NotBefore = issuedAt.UtcDateTime,
			Expires = expiresAt.UtcDateTime,
			SigningCredentials = new SigningCredentials(new SymmetricSecurityKey(secretBytes), algorithm)
		};
		var handler = new JwtSecurityTokenHandler();
		var token = handler.CreateToken(descriptor);

		return new OpxSharedJwtToken(
			handler.WriteToken(token),
			"Bearer",
			expiresAt,
			jwtId,
			sessionId);
	}

	private static void AddDeviceClaims(List<Claim> claims, OpxSharedJwtDeviceMetadata? device)
	{
		if (device is null)
		{
			return;
		}

		claims.Add(new Claim(
			OpxJwtClaimNames.DeviceId,
			RequireValue(device.DeviceId, nameof(device.DeviceId), 128)));
		claims.Add(new Claim(
			OpxJwtClaimNames.DeviceType,
			RequireValue(device.DeviceType, nameof(device.DeviceType), 32)));
		AddClaim(claims, OpxJwtClaimNames.DeviceName, device.DeviceName, 128);
		AddClaim(claims, OpxJwtClaimNames.Platform, device.Platform, 64);
		AddClaim(claims, OpxJwtClaimNames.ClientApplication, device.ClientApplication, 128);
		AddClaim(claims, OpxJwtClaimNames.ClientVersion, device.ClientVersion, 64);
	}

	private static void AddLoginIpClaim(List<Claim> claims, string? loginIpAddress)
	{
		var cleanValue = CleanValue(loginIpAddress, 64);
		if (cleanValue is null)
		{
			return;
		}

		if (!IPAddress.TryParse(cleanValue, out var address))
		{
			throw new ArgumentException("Login IP address is invalid.", nameof(loginIpAddress));
		}

		claims.Add(new Claim(OpxJwtClaimNames.LoginIpAddress, NormalizeAddress(address).ToString()));
	}

	private static IPAddress NormalizeAddress(IPAddress address)
	{
		return address.IsIPv4MappedToIPv6 ? address.MapToIPv4() : address;
	}

	private static void AddSecurityClaims(
		List<Claim> claims,
		OpxSharedJwtSecurityContext? security,
		DateTimeOffset issuedAt)
	{
		if (security is null)
		{
			return;
		}

		AddDistinctClaims(
			claims,
			OpxJwtClaimNames.AuthenticationMethod,
			security.AuthenticationMethods,
			64);
		AddClaim(
			claims,
			OpxJwtClaimNames.AuthenticationContext,
			security.AuthenticationContext,
			128);
		var authenticatedAt = security.AuthenticatedAt ?? issuedAt;
		claims.Add(new Claim(
			OpxJwtClaimNames.AuthenticationTime,
			authenticatedAt.ToUnixTimeSeconds().ToString(System.Globalization.CultureInfo.InvariantCulture),
			ClaimValueTypes.Integer64));
	}

	private static void AddClaim(List<Claim> claims, string claimType, string? value, int maxLength)
	{
		var cleanValue = CleanValue(value, maxLength);
		if (cleanValue is not null)
		{
			claims.Add(new Claim(claimType, cleanValue));
		}
	}

	private static void AddDistinctClaims(
		List<Claim> claims,
		string claimType,
		IEnumerable<string> values,
		int maxLength)
	{
		foreach (var value in CleanValues(values, maxLength))
		{
			claims.Add(new Claim(claimType, value));
		}
	}

	private static IReadOnlyList<string> CleanValues(IEnumerable<string>? values, int maxLength)
	{
		return values?
			.Select(value => CleanValue(value, maxLength))
			.Where(value => value is not null)
			.Cast<string>()
			.Distinct(StringComparer.Ordinal)
			.ToArray()
			?? [];
	}

	private static string RequireValue(string? value, string parameterName, int maxLength)
	{
		return CleanValue(value, maxLength)
			?? throw new ArgumentException("Value is required.", parameterName);
	}

	private static string? CleanValue(string? value, int maxLength)
	{
		if (string.IsNullOrWhiteSpace(value))
		{
			return null;
		}

		var trimmed = value.Trim();
		if (trimmed.Length > maxLength)
		{
			throw new ArgumentException($"Value cannot exceed {maxLength} characters.");
		}

		return trimmed;
	}
}

internal static class OpxJwtSecurity
{
	public static string ResolveHmacAlgorithm(string? algorithm)
	{
		var resolved = string.IsNullOrWhiteSpace(algorithm)
			? SecurityAlgorithms.HmacSha256
			: algorithm.Trim();
		return resolved switch
		{
			SecurityAlgorithms.HmacSha256 => SecurityAlgorithms.HmacSha256,
			SecurityAlgorithms.HmacSha384 => SecurityAlgorithms.HmacSha384,
			SecurityAlgorithms.HmacSha512 => SecurityAlgorithms.HmacSha512,
			_ => throw new NotSupportedException(
				"Shared JWT supports only HS256, HS384, or HS512.")
		};
	}

	public static void ValidateSecretLength(int byteLength, string algorithm)
	{
		var minimumLength = algorithm switch
		{
			SecurityAlgorithms.HmacSha384 => 48,
			SecurityAlgorithms.HmacSha512 => 64,
			_ => 32
		};
		if (byteLength < minimumLength)
		{
			throw new InvalidOperationException(
				$"JWT secret must be at least {minimumLength} bytes for {algorithm}.");
		}
	}
}
