using System.Diagnostics;

namespace Yarax.Tests
{
    // Tests for the raw wrappers of the native yarax API
    public class NativeTests
    {
        [Test]
        public void CompileRules() 
        {
            using var compiler = YaraxCompilerHandle.Create(CompilerFlags.None);
            var rules = Directory.GetFiles("Rules", "*.yar");
            Assert.That(rules.Length, Is.EqualTo(3));

            // This will produce a warning
            compiler.IgnoreModule("invalid_module");

            bool foundFailure = false;
            foreach (var rule in rules)
            {
                try
                {
                    compiler.SetNamespace(Path.GetFileNameWithoutExtension(rule));
                    compiler.AddFile(rule);
                }
                catch (YaraxException)
                {
                    var errors = compiler.GetErrorsJson();
                    Debug.WriteLine("Errors: " + errors);
                    Assert.That(String.IsNullOrWhiteSpace(errors), Is.False);

                    Assert.That(Path.GetFileName(rule), Is.EqualTo("error.yar"));
                    foundFailure = true;
                }
            }

            Assert.That(foundFailure, Is.True);

            var warnings = compiler.GetWarningsJson();
            Debug.WriteLine("Warnings: " + warnings);
            Assert.That(warnings, Does.Contain("invalid_module"));

            using var builtRules = compiler.Build();
            Assert.That(builtRules.IsInvalid, Is.False);
            Assert.That(builtRules.IsClosed, Is.False);
        }

        [Test]
        public void RuleSerialization()
        {
            byte[] data;

            using (var rules = YaraxExamples.CompileRules())
            {
                Assert.That(rules.IsInvalid, Is.False);
                Assert.That(rules.IsClosed, Is.False);
             
                data = rules.Serialize();
                Assert.That(data.Length, Is.Not.Zero);
            }

            using var deserialized = YaraxRulesHandle.FromSerializedRules(data);
            Assert.That(deserialized.IsInvalid, Is.False);
            Assert.That(deserialized.IsClosed, Is.False);
        }

        [Test]
        public void NativeScanner()
        {
            using var rules = YaraxExamples.CompileRules();
            using var scanner = YaraxScannerHandle.Create(rules);
            TestNativeScanner(scanner);
        }

        [Test]
        public void NativeScannerWithSerializedRules()
        {
            using var rules = YaraxRulesHandle.FromSerializedRules(YaraxExamples.SerializeRules());
            using var scanner = YaraxScannerHandle.Create(rules);
            TestNativeScanner(scanner);
        }

        void TestNativeScanner(YaraxScannerHandle scanner)
        {
            var hits = YaraxExamples.ScanWithNativeScanner(scanner, File.ReadAllBytes("Tests/links.txt"));
            Assert.That(hits, Is.EqualTo(new string[] { "example_link" }));

            hits = YaraxExamples.ScanWithNativeScanner(scanner, File.ReadAllBytes("Tests/file-sample_100kB.doc"));
            Assert.That(hits, Is.EqualTo(new string[] { "doc_file" }));

            hits = YaraxExamples.ScanWithNativeScanner(scanner, File.ReadAllBytes("Tests/file-sample_100kB.docx"));
            Assert.That(hits, Is.EqualTo(new string[] { "docx_file" }));

            hits = YaraxExamples.ScanWithNativeScanner(scanner, File.ReadAllBytes("Tests/zip_file.zip"));
            Assert.That(hits, Is.EqualTo(Array.Empty<string>()));

            hits = YaraxExamples.ScanWithNativeScanner(scanner, File.ReadAllBytes("Tests/file_example_XLSX_10.xlsx"));
            Assert.That(hits, Is.EqualTo(Array.Empty<string>()));
        }
    }
}
