namespace DefenceTechSecurity.Yarax.Tests
{
    // Managed classes add C# idiomatic helpers on top of some native yarax wrappers
    public class ManagedTests
    {
        [Test]
        public void ManagedScanner()
        {
            using var rules = YaraxExamples.CompileRules();

            var res = YaraxExamples.ScanWithManagedScanner(rules, File.ReadAllBytes("Tests/links.txt"));

            Assert.That(res.Count, Is.EqualTo(1));
            Assert.That(res.Keys.First, Is.EqualTo("example_link"));

            var match = res.Values.First();
            
            Assert.That(match.Count, Is.EqualTo(2));
            Assert.Multiple(() =>
            {
                Assert.That(match[0].PatternName, Is.EqualTo("$url"));
                Assert.That(match[1].PatternName, Is.EqualTo("$url"));

                // Ignore the start offset as it might change with line endings
                Assert.That(match[0].Length, Is.EqualTo(18));
                Assert.That(match[1].Length, Is.EqualTo(19));
            });
        }

        [Test]
        public void BlockScanner() 
        {
            using var rule = YaraxExamples.CompileRules();
            using var file = File.OpenRead("Tests/file-sample_100kB.docx");
            
            var hits = YaraxExamples.ScanWithBLockScanner(rule, file);

            Assert.That(hits, Is.EqualTo(new string[] { "docx_file" }));
        }

        [Test]
        public async Task BlockScannerAsync()
        {
            using var rule = YaraxExamples.CompileRules();
            using var file = File.OpenRead("Tests/file-sample_100kB.docx");

            var hits = await YaraxExamples.ScanWithBLockScannerAsync(rule, file);

            Assert.That(hits, Is.EqualTo(new string[] { "docx_file" }));
        }
    }
}