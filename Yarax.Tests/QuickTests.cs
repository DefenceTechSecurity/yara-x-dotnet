namespace DefenceTechSecurity.Yarax.Tests
{
    public class QuickTests
    {
        [Test]
        public void TestQuickScan() 
        {
            using var yarax = Yarax.Compile(File.ReadAllText("Rules/binary_rule.yar"));
            var data = File.ReadAllBytes("Tests/file-sample_100kB.docx");
            var results = yarax.Scan(data);

            Assert.That(results.Length, Is.EqualTo(1));
            Assert.That(results[0].RuleName, Is.EqualTo("docx_file"));
        }

        [Test]
        public void TestQuickScanString()
        {
            using var yarax = Yarax.Compile(File.ReadAllText("Rules/url_rule.yar"));

            var str = "the url is http://example.com";
            var results = yarax.Scan(str);

            Assert.That(results.Length, Is.EqualTo(1));
            Assert.That(results[0].RuleName, Is.EqualTo("example_link"));
            Assert.That(results[0].Matches.First().Offset, Is.EqualTo(str.IndexOf("http")));
        }

        [Test]
        public void TestCompilationError()
        {
            Assert.Throws<Yarax.CompilationException>(() => 
            {
                using var yarax = Yarax.Compile(""""
                rule invalid_rule {
                    strings:
                        $a = "test"
                    condition:
                        $a and undefined_variable
                }
                """");
            }); 
        }
    }
}
