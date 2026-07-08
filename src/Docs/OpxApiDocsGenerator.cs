// Copyright (c) 2026 - opx
using System.Reflection;
using System.Text;
using System.Text.Json;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.Abstractions;
using Microsoft.AspNetCore.Mvc.Controllers;
using Microsoft.AspNetCore.Routing;
using Opx.Api.Web.Options;

namespace Opx.Api.Web.Docs;

internal static class OpxApiDocsGenerator
{
	private static readonly JsonSerializerOptions JsonOptions = new()
	{
		WriteIndented = true
	};

	public static OpxApiDocument Generate(EndpointDataSource endpointDataSource, string contentRootPath, OpxApiDocsOptions options)
	{
		var document = CreateDocument(endpointDataSource);
		var outputDirectory = Path.IsPathRooted(options.OutputDirectory)
			? options.OutputDirectory
			: Path.Combine(GetProjectRootPath(contentRootPath), options.OutputDirectory);

		Directory.CreateDirectory(outputDirectory);

		if (options.GenerateJson)
		{
			var jsonPath = Path.Combine(outputDirectory, $"{options.FileName}.json");
			File.WriteAllText(jsonPath, JsonSerializer.Serialize(document, JsonOptions), Encoding.UTF8);
		}

		if (options.GenerateMarkdown)
		{
			var markdownPath = Path.Combine(outputDirectory, $"{options.FileName}.md");
			File.WriteAllText(markdownPath, CreateMarkdown(document), Encoding.UTF8);
		}

		return document;
	}

	private static string GetProjectRootPath(string contentRootPath)
	{
		var candidates = new[]
		{
			contentRootPath,
			Directory.GetCurrentDirectory(),
			AppContext.BaseDirectory
		};

		foreach (var candidate in candidates.Where(candidate => !string.IsNullOrWhiteSpace(candidate)))
		{
			var projectRootPath = FindProjectRootPath(candidate);

			if (!string.IsNullOrWhiteSpace(projectRootPath))
			{
				return projectRootPath;
			}
		}

		return contentRootPath;
	}

	private static string? FindProjectRootPath(string startPath)
	{
		var directory = Directory.Exists(startPath)
			? new DirectoryInfo(startPath)
			: new FileInfo(startPath).Directory;

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

	private static OpxApiDocument CreateDocument(EndpointDataSource endpointDataSource)
	{
		var endpoints = endpointDataSource.Endpoints
			.OfType<RouteEndpoint>()
			.Select(CreateEndpoint)
			.Where(endpoint => endpoint is not null)
			.Cast<OpxApiEndpoint>()
			.OrderBy(endpoint => endpoint.Controller)
			.ThenBy(endpoint => endpoint.Route)
			.ThenBy(endpoint => endpoint.Method)
			.ToList();

		return new OpxApiDocument
		{
			GeneratedAt = DateTimeOffset.Now,
			Endpoints = endpoints
		};
	}

	private static OpxApiEndpoint? CreateEndpoint(RouteEndpoint endpoint)
	{
		var action = endpoint.Metadata.GetMetadata<ControllerActionDescriptor>();

		if (action is null)
		{
			return null;
		}

		var methods = endpoint.Metadata.GetMetadata<HttpMethodMetadata>()?.HttpMethods ?? Array.Empty<string>();
		var responseTypes = endpoint.Metadata
			.OfType<ProducesResponseTypeAttribute>()
			.Select(metadata => new OpxApiOutput(metadata.StatusCode, GetFriendlyTypeName(metadata.Type)))
			.ToList();

		if (responseTypes.Count == 0)
		{
			responseTypes.Add(new OpxApiOutput(StatusCodes.Status200OK, GetFriendlyTypeName(action.MethodInfo.ReturnType)));
		}

		return new OpxApiEndpoint
		{
			Controller = action.ControllerName,
			Action = action.ActionName,
			Method = methods.Count == 0 ? "ANY" : string.Join(",", methods),
			Route = "/" + endpoint.RoutePattern.RawText?.TrimStart('/'),
			Parameters = action.Parameters.Select(CreateParameter).ToList(),
			Output = responseTypes
		};
	}

	private static OpxApiParameter CreateParameter(ParameterDescriptor parameter)
	{
		var source = parameter.BindingInfo?.BindingSource?.DisplayName ?? "Unknown";
		var type = parameter.ParameterType;

		return new OpxApiParameter
		{
			Name = parameter.Name,
			Source = source,
			Type = GetFriendlyTypeName(type),
			Required = !IsNullable(parameter),
			Properties = GetProperties(type)
		};
	}

	private static bool IsNullable(ParameterDescriptor parameter)
	{
		if (!parameter.ParameterType.IsValueType)
		{
			return true;
		}

		return Nullable.GetUnderlyingType(parameter.ParameterType) is not null;
	}

	private static List<OpxApiParameterProperty> GetProperties(Type type)
	{
		type = Nullable.GetUnderlyingType(type) ?? type;

		if (type == typeof(string) || type.IsPrimitive || type.IsEnum || type == typeof(decimal) || type == typeof(DateTime) || type == typeof(Guid))
		{
			return [];
		}

		if (TryGetEnumerableItemType(type, out var itemType))
		{
			type = itemType;
		}

		return type.GetProperties(BindingFlags.Public | BindingFlags.Instance)
			.Where(property => property.GetIndexParameters().Length == 0)
			.Select(property => new OpxApiParameterProperty(property.Name, GetFriendlyTypeName(property.PropertyType)))
			.ToList();
	}

	private static bool TryGetEnumerableItemType(Type type, out Type itemType)
	{
		if (type.IsArray)
		{
			itemType = type.GetElementType() ?? typeof(object);
			return true;
		}

		var enumerableType = type.IsGenericType && type.GetGenericTypeDefinition() == typeof(IEnumerable<>)
			? type
			: type.GetInterfaces().FirstOrDefault(interfaceType => interfaceType.IsGenericType && interfaceType.GetGenericTypeDefinition() == typeof(IEnumerable<>));

		if (enumerableType is not null && type != typeof(string))
		{
			itemType = enumerableType.GetGenericArguments()[0];
			return true;
		}

		itemType = typeof(object);
		return false;
	}

	private static string GetFriendlyTypeName(Type? type)
	{
		if (type is null || type == typeof(void) || type == typeof(Task))
		{
			return "void";
		}

		type = Nullable.GetUnderlyingType(type) ?? type;

		if (type.IsGenericType && type.GetGenericTypeDefinition() == typeof(Task<>))
		{
			return GetFriendlyTypeName(type.GetGenericArguments()[0]);
		}

		if (type.IsGenericType)
		{
			var name = type.Name[..type.Name.IndexOf('`')];
			var arguments = string.Join(", ", type.GetGenericArguments().Select(GetFriendlyTypeName));
			return $"{name}<{arguments}>";
		}

		if (type.IsArray)
		{
			return $"{GetFriendlyTypeName(type.GetElementType())}[]";
		}

		return type.Name;
	}

	private static string CreateMarkdown(OpxApiDocument document)
	{
		var builder = new StringBuilder();
		builder.AppendLine("# Opx API Docs");
		builder.AppendLine();
		builder.AppendLine($"Generated at: {document.GeneratedAt:yyyy-MM-dd HH:mm:ss zzz}");
		builder.AppendLine();

		foreach (var endpoint in document.Endpoints)
		{
			builder.AppendLine($"## {endpoint.Method} {endpoint.Route}");
			builder.AppendLine();
			builder.AppendLine($"Controller: `{endpoint.Controller}`");
			builder.AppendLine($"Action: `{endpoint.Action}`");
			builder.AppendLine();
			builder.AppendLine("### Parameters");
			builder.AppendLine();

			if (endpoint.Parameters.Count == 0)
			{
				builder.AppendLine("-");
			}
			else
			{
				builder.AppendLine("| Name | Source | Type | Required | Properties |");
				builder.AppendLine("| --- | --- | --- | --- | --- |");

				foreach (var parameter in endpoint.Parameters)
				{
					var properties = parameter.Properties.Count == 0
						? "-"
						: string.Join("<br>", parameter.Properties.Select(property => $"{property.Name}: {property.Type}"));

					builder.AppendLine($"| {parameter.Name} | {parameter.Source} | {parameter.Type} | {parameter.Required} | {properties} |");
				}
			}

			builder.AppendLine();
			builder.AppendLine("### Output");
			builder.AppendLine();
			builder.AppendLine("| StatusCode | Type |");
			builder.AppendLine("| --- | --- |");

			foreach (var output in endpoint.Output)
			{
				builder.AppendLine($"| {output.StatusCode} | {output.Type} |");
			}

			builder.AppendLine();
		}

		return builder.ToString();
	}
}
