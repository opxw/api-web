// Copyright (c) 2026 - opx
namespace Opx.Api.Web.Options;

public enum OpxApiHttpStatusMode
{
	Always200,
	Original
}

public sealed class OpxApiErrorResponseOptions
{
	public OpxApiHttpStatusMode HttpStatusMode { get; set; } = OpxApiHttpStatusMode.Always200;
}
