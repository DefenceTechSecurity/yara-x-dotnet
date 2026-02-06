using System.Text;

namespace DefenceTechSecurity.Yarax
{
    /// <summary>
    /// A simple high-level wrapper around yara-x scanning functionality.
    /// </summary>
    public class Yarax : IDisposable
    {
        readonly YaraxRulesHandle Rules;
        readonly YaraxScanner Scanner;
        readonly object SyncRoot = new();

        readonly List<Hit> Hits = [];

        public class CompilationException(YaraxResult Result, string JsonError) : YaraxException(Result, "Compilation failed")
        {
            public readonly string JsonError = JsonError;
        }

        public record Hit(string Namespace, string RuleName, string[] RuleTags, List<YaraxMatchInfo> Matches);

        private Yarax(YaraxRulesHandle rules)
        {
            Rules = rules;
            Scanner = new YaraxScanner(rules);
            Scanner.OnHit += Scanner_OnHit;
        }

        /// <summary>
        /// Compiles the specified Yara-x source code into a <see cref="Yarax"/> instance.
        /// </summary>
        /// <exception cref="CompilationException"></exception>
        public static Yarax Compile(string source)
        {
            using var compiler = YaraxCompilerHandle.Create();
            
            try
            {
                compiler.AddRuleString($"{nameof(Yarax)}.{nameof(Compile)}", source);
            }
            catch (YaraxException ex) when (ex.Result is YaraxResult.SYNTAX_ERROR or YaraxResult.VARIABLE_ERROR)
            {
                var error = compiler.GetErrorsJson() ?? "";
                throw new CompilationException(ex.Result, error);
            }

            return new Yarax(compiler.Build());
        }

        private void Scanner_OnHit(ref YaraxRuleHit Hit)
        {
            Hits.Add(new Hit(
                Hit.Namespace,
                Hit.Name,
                Hit.Tags.ToArray(),
                Hit.Matches
            ));
        }

        /// <summary>
        /// Scans the specified data for pattern matches and returns the results.
        /// </summary>
        /// <remarks>This method is thread-safe. Each call blocks until any previous scans have been completed. For better multithreaded performances consider using <see cref="YaraxScanner"/>.</remarks>
        /// <returns>An array of <see cref="Hit"/> objects representing all matches found in the specified data. The array is
        /// empty if no matches are found.</returns>
        public Hit[] Scan(ReadOnlySpan<byte> data)
        {
            lock (SyncRoot)
            {
                Hits.Clear();
                Scanner.Scan(data);
                return Hits.ToArray();
            }
        }

        /// <summary>
        /// Scans the specified string for pattern matches and returns the results.
        /// </summary>
        /// <param name="str">The stirng to be scanned</param>
        /// <param name="encoding">The encoding used for the string. When this is not specified it defaults to UTF8.</param>
        /// <remarks>This method is thread-safe. Each call blocks until any previous scans have been completed. For better multithreaded performances consider using <see cref="YaraxScanner"/>.</remarks>
        /// <returns>An array of <see cref="Hit"/> objects representing all matches found in the specified data. The array is
        /// empty if no matches are found.</returns>
        public Hit[] Scan(string str, Encoding? encoding = null)
        {
            encoding ??= Encoding.UTF8;
            return Scan(encoding.GetBytes(str));
        }

        public void Dispose()
        {
            lock (SyncRoot)
            {
                Scanner.Dispose();
                Rules.Dispose();
            }
        }
    }
}