# Yara-x dotnet

This library provides .NET bindings for [yara-x](https://github.com/VirusTotal/yara-x).

The bindings are designed to be safe from memory leaks using the `SafeHandle` pattern, multiple levels of abstraction are provided to allow both simple usage in quick projects as well as lightwight access to the underlying API for maximum performance.

The nuget package also provides binaries for the following platforms:
- Windows: x64
- Linux: x64, arm64
- Osx: x64, arm64

# Quick start

Install the nuget package: 
```
dotnet add package DefenceTechSecurity.Yarax
```

The quick bindings allow for convenient access to yara-x, these are similar to the python API:
```csharp
using DefenceTechSecurity.Yarax;

using var yrx = Yarax.Compile(""""
	rule ExampleRule {
		strings:
			$a = "example string"
		condition:
			$a
	}

	// More rules can be added here
"""");

var results = yrx.Scan(File.ReadAllBytes("sample.bin"));

foreach (var result in results)
{
    Console.WriteLine($"Matched rule {result.RuleName}");
	foreach (var match in result.Matches)
		Console.WriteLine($" -{match}");
}
```

# Advanced usage

The core classes that directly wrap the yara-x API are `YaraxCompilerHandlde`, `YaraxScannerHandle` and `YaraxRulesHandle`. These allow for proper multithreading usage and caching rules via the serialization API. Documentation for every class is provided in the form of XML documentation comments.

Any main handle that refers to a user-managed yara-x object is wrapped in a `SafeHandle`, every temporary object that is only returned inside a callback or a specific scope is wrapped in a [`ref struct`](https://learn.microsoft.com/en-us/dotnet/csharp/language-reference/builtin-types/ref-struct) so it can't escape the scope where it is valid.

For additional flexibility or better support for multithreading the lower level API can be used:
```csharp
using var compiler = YaraxCompilerHandle.Create();
compiler.SetNamespace("Examples");
compiler.AddFile("example.yar");

using var rules = compiler.Build();

Parallel.ForEach(Directory.GetFiles("to_scan/"), file =>
{
    // Just an example, in practice you might want to cache the scanner instances
    using var scanner = new YaraxScanner(rules);
    scanner.OnHit += OnHit;
    scanner.Scan(File.ReadAllBytes(file));
});

void OnHit(ref YaraxRuleHit hit)
{
    Console.WriteLine($"Matched rule {hit.Namespace}::{hit.Name}");
    foreach (var match in hit.Matches)
        Console.WriteLine($" -{match}");
};
```

See other usage examples in the [tests project](Yarax.Tests/YaraxExamples.cs) for more details.

# Testing and building from source

This repository contains the following projects:

- `Yarax`: The main nuget package. This is a meta-package that only references the two other packages.
- `Yarax.Managed`: This contains the main code of this library, it's a standalone .NET project that can be used with custom builds of yara-x.
- `Yarax.Native`: This builds a nuget package containing the prebuilt native binaries for yara-x. The yara-x project does not distribute capi binaries for all the platforms, so these are built from source via [Github Actions](https://github.com/DefenceTechSecurity/yara-x-dotnet-native) and included in this package.
- `Yarax.Tests`: This contains the unit tests and usage examples.

`Yarax.Tests` is set up in a way that allow easy testing and debugging from the Test Explorer in Visual Studio. It only includes the managed project as a reference so for testing it locally you will need to manually copy the native binary of yara-x for your platform to the build output folder of the tests project.

Publishing to the nuget feed is done automatically via Github Actions with Trusted Publishing on releases.