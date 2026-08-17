// Copyright (c) 2026 - opx
namespace Opx.Api.Web.Jwt;

public static class OpxJwtClaimNames
{
	public const string SessionId = "sid";
	public const string AuthenticationMethod = "amr";
	public const string AuthenticationContext = "acr";
	public const string AuthenticationTime = "auth_time";
	public const string Scope = "scope";
	public const string DeviceId = "device_id";
	public const string DeviceType = "device_type";
	public const string DeviceName = "device_name";
	public const string Platform = "platform";
	public const string ClientApplication = "client_app";
	public const string ClientVersion = "client_version";
	public const string LoginIpAddress = "login_ip";
}
