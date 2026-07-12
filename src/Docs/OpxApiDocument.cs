// Copyright (c) 2026 - opx
namespace Opx.Api.Web.Docs;

public sealed class OpxApiDocument
{
	public DateTimeOffset GeneratedAt { get; set; }
	public List<OpxApiEndpoint> Endpoints { get; set; } = [];
}

public sealed class OpxApiEndpoint
{
	public string Controller { get; set; } = "";
	public string Action { get; set; } = "";
	public string Method { get; set; } = "";
	public string Route { get; set; } = "";
	public List<OpxApiParameter> Parameters { get; set; } = [];
	public List<OpxApiOutput> Output { get; set; } = [];
}

public sealed class OpxApiParameter
{
	public string Name { get; set; } = "";
	public string Source { get; set; } = "";
	public string Type { get; set; } = "";
	public bool Required { get; set; }
	public List<OpxApiParameterProperty> Properties { get; set; } = [];
}

public sealed record OpxApiParameterProperty(string Name, string Type);

public sealed record OpxApiOutput(int StatusCode, string Type);
