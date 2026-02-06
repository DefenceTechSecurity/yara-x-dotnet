namespace DefenceTechSecurity.Yarax.Tests
{
    internal static class YaraxExamples
    {
        public static YaraxRulesHandle CompileRules() 
        {
            using var compiler = YaraxCompilerHandle.Create(CompilerFlags.None);
            
            // Set arbitrary namespaces to the next rules to be loaded
            compiler.SetNamespace("binary_rule");
            
            // Add rule via a file
            compiler.AddFile("Rules/binary_rule.yar");

            // Set a namespace for the next rules
            compiler.SetNamespace("text_rule");

            // Add rule via a string
            compiler.AddRuleString("example_origin", File.ReadAllText("Rules/url_rule.yar"));

            // Note that the returned rules stay valid even after the compiler is disposed.
            return compiler.Build();
        }

        public static byte[] SerializeRules() 
        {
            using var rules = CompileRules();
            // This serializes the rules to a byte array that can be used to quickly load them later without needing to compile them from scratch.
            return rules.Serialize();
        }

        public static YaraxRulesHandle DeserializeRules(byte[] serializedRules) 
        {
            // This deserializes the rules from a byte array previously produced by SerializeRules.
            return YaraxRulesHandle.FromSerializedRules(serializedRules);
        }

        public static Dictionary<string, List<YaraxMatchInfo>> ScanWithManagedScanner(YaraxRulesHandle rules, Span<byte> data)
        {
            // The YaraxScanner provides C# idiomatic access to scanning functionality.
            // See remarks about lifetime of the rules in the documentation comments.
            using var scanner = new YaraxScanner(rules);

            Dictionary<string, List<YaraxMatchInfo>> hits = [];
            scanner.OnHit += (ref YaraxRuleHit hit) => {
                // YaraxRuleHit caches results from the native api so calling the same property multiple times is efficient.
                var rule = hit.Name;

                if (hits.TryGetValue(rule, out var list))
                    list.AddRange(hit.Matches);
                else
                    hits[rule] = [.. hit.Matches];
            };

            scanner.Scan(data);

            return hits;
        }

        public static List<string> ScanWithBLockScanner(YaraxRulesHandle rules, Stream stream)
        {
            var result = new List<string>();

            // Block scanning mode does not need all the memory in a single buffer and can scan Streams. 
            // There are some limitations, see https://virustotal.github.io/yara-x/docs/api/c/c-/#limitations-of-the-block-scanning-mode
            using var scanner = new YaraxBlockScanner(rules);
            
            scanner.OnHit += (ref YaraxRuleHit hit) => { 
                result.Add(hit.Name);
            };

            scanner.ScanStream(stream, 1024);
            return result;
        }

        public static YaraxScannerHandle CreateNativeScanner(YaraxRulesHandle rules)
        {
            // The YaraxScannerHandle scanner provides low-level access to the native scanner API.
            // See remarks about lifetime of the rules in the documentation comments.
            return YaraxScannerHandle.Create(rules);
        }

        public static List<string> ScanWithNativeScanner(YaraxScannerHandle scanner, Span<byte> data)
        {
            var res = new List<string>();
            scanner.SetMatchingCallback((rule, _) => {
                // YaraxRuleRef is the raw reference to the matched rule.
                // It is only valid within this callback. The type is defined as a ref struct so it can't escape this scope.

                // Every access to properties of the rule will call into native code.
                res.Add(rule.Identifier);
            });

            scanner.Scan(data);

            // If the scanner is reused, clear the callback to avoid accidentally modifying res later
            scanner.SetMatchingCallback(null);

            return res;
        }

        public static async Task<List<string>> ScanWithBLockScannerAsync(YaraxRulesHandle rules, Stream stream)
        {
            var result = new List<string>();
            using var scanner = new YaraxBlockScanner(rules);

            scanner.OnHit += (ref YaraxRuleHit hit) => {
                result.Add(hit.Name);
            };

            await scanner.ScanStreamAsync(stream, cancellationToken: CancellationToken.None);
            return result;
        }
    }
}
