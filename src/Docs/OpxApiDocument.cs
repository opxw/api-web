// Copyright (c) 2026 - opx
namespace Opx.Api.Web.Docs;

internal sealed class OpxApiDocument
{
	public DateTimeOffset GeneratedAt { get; set; }
	public List<OpxApiEndpoint> Endpoints { get; set; } = [];
}

internal sealed class OpxApiEndpoint
{
	public string Controller { get; set; } = "";
	public string Action { get; set; } = "";
	public string Method { get; set; } = "";
	public string Route { get; set; } = "";
	public List<OpxApiParameter> Parameters { get; set; } = [];
	public List<OpxApiOutput> Output { get; set; } = [];
}

internal sealed class OpxApiParameter
{
	public string Name { get; set; } = "";
	public string Source { get; set; } = "";
	public string Type { get; set; } = "";
	public bool Required { get; set; }
	public List<OpxApiParameterProperty> Properties { get; set; } = [];
}

internal sealed record OpxApiParameterProperty(string Name, string Type);

internal sealed record OpxApiOutput(int StatusCode, string Type);
