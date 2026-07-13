// Copyright (c) 2026 - opx
using BenchmarkDotNet.Running;

BenchmarkSwitcher.FromTypes([
	typeof(OpxEndpointProxyBenchmarks),
	typeof(OpxMiddlewareBenchmarks)
]).Run(args);
