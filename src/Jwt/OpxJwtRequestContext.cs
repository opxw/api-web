// Copyright (c) 2026 - opx
using System.IdentityModel.Tokens.Jwt;
using System.Net;
using System.Security.Claims;
using Microsoft.Extensions.DependencyInjection;
using Opx.Api.Web.Middlewares;
using Opx.Api.Web.Protection;

namespace Opx.Api.Web.Jwt;

public sealed record OpxJwtRequestContext(
	bool IsAuthenticated,
	string? Subject,
	string? Name,
	string? SessionId,
	string? JwtId,
	IReadOnlyCollection<string> Roles,
	IReadOnlyCollection<string> Scopes,
	IReadOnlyCollection<string> AuthenticationMethods,
	string? AuthenticationContext,
	DateTimeOffset? AuthenticatedAt,
	string? DeviceId,
	string? DeviceType,
	string? DeviceName,
	string? Platform,
	string? ClientApplication,
	string? ClientVersion,
	string? LoginIpAddress,
	string CurrentIpAddress,
	bool? LoginIpMatchesCurrent,
	string RequestId);

public static class OpxJwtHttpContextExtensions
{
	private const string MappedAuthenticationMethod = "http://schemas.microsoft.com/claims/authnmethodsreferences";
	private const string MappedAuthenticationContext = "http://schemas.microsoft.com/claims/authnclassreference";
	private const string MappedAuthenticationTime = "http://schemas.microsoft.com/ws/2008/06/identity/claims/authenticationinstant";

	public static OpxJwtRequestContext GetOpxJwtRequestContext(
		this HttpContext context,
		IConfiguration? configuration = null)
	{
		ArgumentNullException.ThrowIfNull(context);
		if (configuration is null && context.RequestServices is { } requestServices)
		{
			configuration = requestServices.GetService<IConfiguration>();
		}
		var user = context.User;
		var loginIpAddress = FindValue(user, OpxJwtClaimNames.LoginIpAddress);
		var currentIpAddress = OpxClientIpResolver.Resolve(context, configuration).Text;

		return new OpxJwtRequestContext(
			user.Identity?.IsAuthenticated == true,
			FindValue(user, JwtRegisteredClaimNames.Sub, ClaimTypes.NameIdentifier),
			FindValue(user, JwtRegisteredClaimNames.Name, ClaimTypes.Name),
			FindValue(user, OpxJwtClaimNames.SessionId),
			FindValue(user, JwtRegisteredClaimNames.Jti),
			FindValues(user, ClaimTypes.Role, "role"),
			FindSpaceDelimitedValues(user, OpxJwtClaimNames.Scope),
			FindValues(user, OpxJwtClaimNames.AuthenticationMethod, MappedAuthenticationMethod),
			FindValue(user, OpxJwtClaimNames.AuthenticationContext, MappedAuthenticationContext),
			ReadUnixTime(user, OpxJwtClaimNames.AuthenticationTime, MappedAuthenticationTime),
			FindValue(user, OpxJwtClaimNames.DeviceId),
			FindValue(user, OpxJwtClaimNames.DeviceType),
			FindValue(user, OpxJwtClaimNames.DeviceName),
			FindValue(user, OpxJwtClaimNames.Platform),
			FindValue(user, OpxJwtClaimNames.ClientApplication),
			FindValue(user, OpxJwtClaimNames.ClientVersion),
			loginIpAddress,
			currentIpAddress,
			CompareIpAddresses(loginIpAddress, currentIpAddress),
			ResolveRequestId(context));
	}

	private static string ResolveRequestId(HttpContext context)
	{
		if (context.Items.TryGetValue(OpxRequestIdMiddleware.ItemName, out var item)
			&& item is string itemRequestId
			&& !string.IsNullOrWhiteSpace(itemRequestId))
		{
			return itemRequestId;
		}

		var requestId = context.Request.Headers["X-Request-ID"].FirstOrDefault();
		if (string.IsNullOrWhiteSpace(requestId))
		{
			requestId = context.Request.Headers["X-Correlation-ID"].FirstOrDefault();
		}

		return string.IsNullOrWhiteSpace(requestId)
			? context.TraceIdentifier
			: NormalizeRequestId(requestId, context.TraceIdentifier);
	}

	private static bool? CompareIpAddresses(string? loginIpAddress, string currentIpAddress)
	{
		if (string.IsNullOrWhiteSpace(loginIpAddress) || string.IsNullOrWhiteSpace(currentIpAddress))
		{
			return null;
		}

		if (IPAddress.TryParse(loginIpAddress, out var loginAddress)
			&& IPAddress.TryParse(currentIpAddress, out var currentAddress))
		{
			loginAddress = loginAddress.IsIPv4MappedToIPv6 ? loginAddress.MapToIPv4() : loginAddress;
			currentAddress = currentAddress.IsIPv4MappedToIPv6 ? currentAddress.MapToIPv4() : currentAddress;
			return loginAddress.Equals(currentAddress);
		}

		return string.Equals(loginIpAddress, currentIpAddress, StringComparison.OrdinalIgnoreCase);
	}

	private static string NormalizeRequestId(string requestId, string fallback)
	{
		var value = requestId.Trim();
		return value.Length is > 0 and <= 128 ? value : fallback;
	}

	private static DateTimeOffset? ReadUnixTime(ClaimsPrincipal user, params string[] claimTypes)
	{
		return long.TryParse(
			FindValue(user, claimTypes),
			System.Globalization.NumberStyles.Integer,
			System.Globalization.CultureInfo.InvariantCulture,
			out var seconds)
				? DateTimeOffset.FromUnixTimeSeconds(seconds)
				: null;
	}

	private static string? FindValue(ClaimsPrincipal user, params string[] claimTypes)
	{
		foreach (var claimType in claimTypes)
		{
			var value = user.FindFirst(claimType)?.Value;
			if (!string.IsNullOrWhiteSpace(value))
			{
				return value;
			}
		}

		return null;
	}

	private static IReadOnlyCollection<string> FindValues(
		ClaimsPrincipal user,
		params string[] claimTypes)
	{
		return claimTypes
			.SelectMany(user.FindAll)
			.Select(claim => claim.Value)
			.Where(value => !string.IsNullOrWhiteSpace(value))
			.Distinct(StringComparer.Ordinal)
			.ToArray();
	}

	private static IReadOnlyCollection<string> FindSpaceDelimitedValues(
		ClaimsPrincipal user,
		string claimType)
	{
		return user.FindAll(claimType)
			.SelectMany(claim => claim.Value.Split(
				' ',
				StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
			.Distinct(StringComparer.Ordinal)
			.ToArray();
	}
}
