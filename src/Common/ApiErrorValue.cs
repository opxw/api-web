using System.Text.Json.Serialization;

namespace Opx.Api.Web.Common
{
	[Serializable]
	public class ApiErrorValue
	{
		[JsonPropertyName("message")]
		public string Message { get; set; } = "";
		[JsonPropertyName("id")]
		public string Id { get; set; } = "";
		[JsonPropertyName("objectName")]
		public string ObjectName { get; set; } = "";
	}
}
