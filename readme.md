# Yara-x dotnet

This library provides .NET bindings for [yara-x](https://github.com/VirusTotal/yara-x).

The bindings are designed to be safe from memory leaks using the `SafeHandle` pattern, multiple levels of abstraction are provided to allow both simple usage in quick projects as well as lightwight access to the underlying API for maximum performance.

Native binaries for the most common .NET platforms are also provided via the nuget package.

# Quick start

Install the nuget package: 
```
dotnet add package DefenceTechSecurity.Yarax
```

Then you can use the quick bindings, these are very similar to the python bindings:
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
```

# Advanced usage

The core classes that directly wrap the yara-x API are `YaraxCompilerHandlde`, `YaraxScannerHandle` and `YaraxRulesHandle`. These allow for proper multithreading usage and caching rules via the serialization API.

Any main handle that refers to a user-managed yara-x object is wrapped in a `SafeHandle`, every temporary object that is only returned inside a callback or a specific scope is wrapped in a [`ref struct`](https://learn.microsoft.com/en-us/dotnet/csharp/language-reference/builtin-types/ref-struct) so it can't escape the scope where it is valid.

See the usage examples in the [tests project](Yarax.Tests/YaraxExamples.cs) for more details.

# Testing and building from source

This repository contains the following projects:

- `Yarax`: The main nuget package. This is a meta-package that only references the two other packages.
- `Yarax.Managed`: This contains the main code of this library, it's a standalone .NET project that can be used with custom builds of yara-x.
- `Yarax.Native`: This builds a nuget package containing the prebuilt native binaries for yara-x.
- `Yarax.Tests`: This contains the unit tests and usage examples.

`Yarax.Tests` is set up in a way that allow easy testing and debugging from the Test Explorer in Visual Studio. It only includes the managed project as a reference so for testing it locally you will need to manually copy the native binary of yara-x for your platform to the build output folder of the tests project.

Publishing to the nuget feed is done automatically via Github Actions with Trusted Publishing on releases.