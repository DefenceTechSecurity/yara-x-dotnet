namespace Yarax.Tests
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

            compiler.SetNamespace("text_rule");

            // Add rule via a string
            compiler.AddRuleString("example_origin", File.ReadAllText("Rules/url_rule.yar"));

            return compiler.Build();
        }

        public static List<string> ScanWithNativeScanner(YaraxScannerHandle scanner, Span<byte> data)
        {
            var res = new List<string>();

            scanner.SetMatchingCallback((rule, _) => {
                res.Add(rule.Identifier);
            });

            scanner.Scan(data);

            // If the scanner is reused, clear the callback to avoid accidentally modifying res later
            scanner.SetMatchingCallback(null);

            return res;
        }

        public static byte[] SerializeRules() 
        {
            using var rules = CompileRules();
            // This serializes the rules to a byte array that can be used to quickly load them later without needing to compile them from scratch.
            return rules.Serialize();
        }

        public static Dictionary<string, List<YaraxMatchInfo>> ScanWithManagedScanner(YaraxRulesHandle rules, Span<byte> data)
        {
            Dictionary<string, List<YaraxMatchInfo>> hits = [];

            using var scanner = new YaraxScanner(rules);

            scanner.OnHit += (ref YaraxRuleHit hit) => {
                // YaraxRuleHit provides efficient access to properties of the hit
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

            // Block scanning mode has some limitations. See https://virustotal.github.io/yara-x/docs/api/c/c-/#limitations-of-the-block-scanning-mode
            using var scanner = new YaraxBlockScanner(rules);
            
            scanner.OnHit += (ref YaraxRuleHit hit) => { 
                result.Add(hit.Name);
            };

            scanner.ScanStream(stream, 1024);
            return result;
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
