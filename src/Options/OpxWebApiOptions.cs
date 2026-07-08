// Copyright (c) 2026 - opx
namespace Opx.Api.Web.Options;

public sealed class OpxWebApiOptions
{
	public OpxApiDocsOptions Docs { get; } = new();

	public OpxWebApiOptions GenerateDocs(
		string outputDirectory = "docs",
		string fileName = "opx-api-docs",
		bool json = true,
		bool markdown = true)
	{
		Docs.Enabled = true;
		Docs.OutputDirectory = outputDirectory;
		Docs.FileName = fileName;
		Docs.GenerateJson = json;
		Docs.GenerateMarkdown = markdown;

		return this;
	}
}

