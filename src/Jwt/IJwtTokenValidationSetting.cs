namespace Opx.Api.Web.Jwt
{
	public interface IJwtTokenValidationSetting
	{
		string SecretKey { get; set; }
		string Issuer { get; set; }
		string Audience { get; set; }
		int ExpirationSeconds { get; set; }
		string Algorithm { get; set; }
	}
}