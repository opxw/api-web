// Copyright (c) 2026 - opx
using System.Text.Json;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.DependencyInjection;
using NUnit.Framework;

namespace Opx.Api.Web.Tests;

[TestFixture]
public class OpxApiDocsGeneratorTests
{
	[Test]
	public async Task GenerateDocs_WhenApplicationStarts_WritesControllerEndpointDocs()
	{
		var outputDirectory = Path.Combine("opx-api-docs-tests", Guid.NewGuid().ToString("N"));
		var projectRootPath = FindProjectRootPath(AppContext.BaseDirectory)
			?? throw new DirectoryNotFoundException("Test project root not found.");
		var expectedOutputDirectory = Path.Combine(projectRootPath, outputDirectory);
		var builder = WebApplication.CreateBuilder();
		builder.WebHost.UseUrls("http://127.0.0.1:0");
		builder.Services
			.AddControllers()
			.AddApplicationPart(typeof(DocsTestController).Assembly);
		builder.Services.UseOpxWebApi(options => options.GenerateDocs(outputDirectory));

		await using var app = builder.Build();
		app.MapControllers();

		try
		{
			await app.StartAsync();
			await app.StopAsync();

			var jsonPath = Path.Combine(expectedOutputDirectory, "opx-api-docs.json");
			var markdownPath = Path.Combine(expectedOutputDirectory, "opx-api-docs.md");
			var json = await File.ReadAllTextAsync(jsonPath);
			using var document = JsonDocument.Parse(json);
			var endpoint = document.RootElement
				.GetProperty("Endpoints")
				.EnumerateArray()
				.Single(value => value.GetProperty("Controller").GetString() == "DocsTest");
			var parameters = endpoint.GetProperty("Parameters");

			Assert.Multiple(() =>
			{
				Assert.That(File.Exists(jsonPath), Is.True);
				Assert.That(File.Exists(markdownPath), Is.True);
				Assert.That(endpoint.GetProperty("Method").GetString(), Is.EqualTo("GET"));
				Assert.That(endpoint.GetProperty("Route").GetString(), Is.EqualTo("/api/docs-test/{id:int}"));
				Assert.That(parameters.EnumerateArray().Any(value => value.GetProperty("Name").GetString() == "id"), Is.True);
				Assert.That(parameters.EnumerateArray().Any(value => value.GetProperty("Name").GetString() == "filter"), Is.True);
				Assert.That(endpoint.GetProperty("Output")[0].GetProperty("Type").GetString(), Is.EqualTo(nameof(DocsTestOutput)));
			});
		}
		finally
		{
			if (Directory.Exists(expectedOutputDirectory))
			{
				Directory.Delete(expectedOutputDirectory, true);
			}
		}
	}

	private static string? FindProjectRootPath(string startPath)
	{
		var directory = new DirectoryInfo(startPath);

		while (directory is not null)
		{
			if (directory.EnumerateFiles("*.csproj").Any())
			{
				return directory.FullName;
			}

			directory = directory.Parent;
		}

		return null;
	}

}

[ApiController]
[Route("api/docs-test")]
public sealed class DocsTestController : ControllerBase
{
	[HttpGet("{id:int}")]
	[ProducesResponseType(typeof(DocsTestOutput), StatusCodes.Status200OK)]
	public ActionResult<DocsTestOutput> Get([FromRoute] int id, [FromQuery] DocsTestFilter filter)
	{
		return new DocsTestOutput(id, filter.Name);
	}
}

public sealed record DocsTestFilter(string? Name);

public sealed record DocsTestOutput(int Id, string? Name);
