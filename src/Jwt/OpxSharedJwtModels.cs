// Copyright (c) 2026 - opx
namespace Opx.Api.Web.Jwt;

public sealed class OpxSharedJwtDeviceMetadata
{
	public string? DeviceId { get; init; }
	public string? DeviceType { get; init; }
	public string? DeviceName { get; init; }
	public string? Platform { get; init; }
	public string? ClientApplication { get; init; }
	public string? ClientVersion { get; init; }
}

public sealed class OpxSharedJwtSecurityContext
{
	public IReadOnlyCollection<string> AuthenticationMethods { get; init; } = [];
	public string? AuthenticationContext { get; init; }
	public DateTimeOffset? AuthenticatedAt { get; init; }
}

public sealed class OpxSharedJwtTokenRequest
{
	public required string Subject { get; init; }
	public string? Name { get; init; }
	public string? SessionId { get; init; }
	public string? JwtId { get; init; }
	public IReadOnlyCollection<string> Roles { get; init; } = [];
	public IReadOnlyCollection<string> Scopes { get; init; } = [];
	public OpxSharedJwtDeviceMetadata? Device { get; init; }
	public OpxSharedJwtSecurityContext? Security { get; init; }
	public string? LoginIpAddress { get; init; }
	public DateTimeOffset? IssuedAt { get; init; }
	public DateTimeOffset? ExpiresAt { get; init; }
}

public sealed record OpxSharedJwtToken(
	string AccessToken,
	string TokenType,
	DateTimeOffset ExpiresAt,
	string JwtId,
	string SessionId);

public interface IOpxSharedJwtTokenService
{
	OpxSharedJwtToken CreateToken(OpxSharedJwtTokenRequest request);
}
