// Copyright (c) 2026 - opx
namespace Opx.Api.Web.Options;

public sealed class OpxApiDocsOptions
{
	public bool Enabled { get; set; }
	public string OutputDirectory { get; set; } = "docs";
	public string FileName { get; set; } = "opx-api-docs";
	public bool GenerateJson { get; set; } = true;
	public bool GenerateMarkdown { get; set; } = true;
}

