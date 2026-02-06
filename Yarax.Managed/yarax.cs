namespace DefenceTechSecurity.Yarax
{
    public abstract class BaseYaraxScanner : IDisposable
    {
        protected readonly YaraxScannerHandle Scanner;

        public delegate void OnRuleHitDelegate(ref YaraxRuleHit Hit);

        /// <summary>
        /// Occurs when a rule is triggered during evaluation.
        /// </summary>
        /// <remarks>
        /// Subscribe to this event to receive notifications whenever a rule is hit. The event receives a <see cref="YaraxRuleHit"/> object containing details about the matched rule. This object is only valid during the scope of the event invocation.
        /// </remarks>
        public event OnRuleHitDelegate? OnHit;

        public BaseYaraxScanner(YaraxRulesHandle rules)
        {
            Scanner = YaraxScannerHandle.Create(rules);
            Scanner.SetMatchingCallback(Callback);
        }

        void Callback(YaraxRuleRef rule, nint user_data)
        {
            var hit = new YaraxRuleHit(rule);
            OnHit?.Invoke(ref hit);
        }

        public void Dispose()
        {
            Scanner.Dispose();
        }
    }

    /// <summary>
    /// Convenience class to use <see cref="YaraxScannerHandle"/> in a more C# idiomatic way.
    /// </summary>
    /// <remarks>
    /// This class instantiates a scanner given the provided <see cref="YaraxRulesHandle"/>, this object must not be disposed for as long as an instance of this class is using it.
    /// It is safe to use the same Rules object with multiple instances of this class
    /// </remarks>
    public class YaraxScanner(YaraxRulesHandle Rules) : BaseYaraxScanner(Rules)
    {
        /// <summary>
        /// Scans a memory buffer.
        /// </summary>
        public void Scan(ReadOnlySpan<byte> data) => Scanner.Scan(data);
    }

    /// <summary>
    /// Convenience class to use <see cref="YaraxScannerHandle"/> in a more C# idiomatic way. Also enforces semantic correctness for block mode scanning.
    /// Block scanning mode has some limitations.See<see href="https://virustotal.github.io/yara-x/docs/api/c/c-/#limitations-of-the-block-scanning-mode"/>
    /// </summary>
    /// <remarks>
    /// This class instantiates a scanner given the provided <see cref="YaraxRulesHandle"/>, this object must not be disposed for as long as an instance of this class is using it.
    /// It is safe to use the same Rules object with multiple instances of this class
    /// </remarks>
    public class YaraxBlockScanner(YaraxRulesHandle Rules) : BaseYaraxScanner(Rules)
    {
        ulong Offset = 0;

        /// <summary>
        /// Processes a block of data and advances the current offset by the length of the data.
        /// </summary>
        /// <remarks>
        /// To obtain correct results, after all blocks have been added, <see cref="FinishScan"/> must be called to finalize the scanning process.
        /// </remarks>
        /// <param name="data">A read-only span of bytes representing the data block to process.</param>
        public void AddBlock(ReadOnlySpan<byte> data)
        {
            Scanner.ScanBlock(Offset, data);
            Offset += (ulong)data.Length;
        }

        /// <summary>
        /// Completes the current block scanning operation and resets the scanner object to its initial state.
        /// </summary>
        public void FinishScan()
        {
            Scanner.FinishScanBlocks();
            Offset = 0;
        }

        /// <summary>
        /// Scans a stream by reading chunks of the specified block size. This will also call <see cref="FinishScan"/> and reset the scanner to a clean state.
        /// </summary>
        /// <returns>
        /// The total number of bytes that have been read.
        /// </returns>
        public long ScanStream(Stream stream, int blockSize = 4096)
        {
            var total = 0L;
            var buffer = new byte[blockSize];

            while (true)
            {
                var read = stream.Read(buffer, 0, buffer.Length);
                if (read == 0)
                    break;

                total += read;

                var span = new Span<byte>(buffer, 0, read);
                AddBlock(span);
            }

            FinishScan();
            return total;
        }

        /// <summary>
        /// Asynchronously scans a stream by reading chunks of the specified block size. This will also call <see cref="FinishScan"/> and reset the scanner to a clean state.
        /// </summary>
        /// <remarks>
        /// Only consuming the stream is async, this function will block during native yara-x processing. 
        /// As for all the other Scanner functions this function is not thread safe either.
        /// Even when this function is cancelled <see cref="FinishScan"/> will always be called.
        /// </remarks>
        /// <returns>
        /// The total number of bytes that have been read.
        /// </returns>
        public async Task<long> ScanStreamAsync(Stream stream, int blockSize = 4096, CancellationToken cancellationToken = default)
        {
            var total = 0L;
            var buffer = new byte[blockSize];

            while (!cancellationToken.IsCancellationRequested)
            {
                int read;

                try
                {
                    read = await stream.ReadAsync(buffer, cancellationToken).ConfigureAwait(false);
                }
                catch (OperationCanceledException)
                {
                    break;
                }

                if (read == 0)
                    break;

                total += read;
                AddBlock(buffer.AsSpan(0, read));
            }
            FinishScan();

            return total;
        }
    }

    /// <summary>
    /// Represents information about a pattern match, including the pattern name and the position and length of the
    /// match within the input.
    /// </summary>
    public record struct YaraxMatchInfo(string PatternName, long Offset, long Length);

    /// <summary>
    /// Represents a yara-x rule match. Provides lazy cached access to the rule's properties and pattern matches.
    /// </summary>
    /// <remarks>
    /// Instances of this object are only valid during the scope of the callback that provides them. 
    /// </remarks>
    public ref struct YaraxRuleHit(YaraxRuleRef Rule)
    {
        public readonly YaraxRuleRef Rule = Rule;

        // Cached properties
        string? cachedName;
        string? cachedNamespace;
        List<YaraxMatchInfo>? cachedMatches;
        List<string>? cachedTags;

        /// <summary>
        /// Gets the name associated with the rule.
        /// </summary>
        public string Name => cachedName ??= Rule.Identifier;

        /// <summary>
        /// Gets the namespace associated with the current rule.
        /// </summary>
        public string Namespace => cachedNamespace ??= Rule.Namespace;

        /// <summary>
        /// Gets the collection of match results found by the parser.
        /// </summary>
        /// <remarks>
        /// Certain rules might trigger a rule hit event without providing the actual pattern matches. This list might be empty.
        /// Furthermore, the matches might not be in any specific order; use LINQ methods to sort or filter them as needed.
        /// </remarks>
        public List<YaraxMatchInfo> Matches => cachedMatches ??= GetMatches();

        /// <summary>
        /// Convenience property to get the offset of the first match in the Matches collection.
        /// </summary>
        public long FirstHitOffset => Matches.OrderBy(x => x.Offset).FirstOrDefault().Offset;

        /// <summary>
        /// Gets the collection of tags associated with the rule.
        /// </summary>
        public List<string> Tags => cachedTags ??= Rule.GetTags();

        readonly List<YaraxMatchInfo> GetMatches()
        {
            var matches = new List<YaraxMatchInfo>();
            Rule.IteratePatterns((pattern, _) =>
            {
                var name = pattern.Identifier;

                pattern.IterateMatches((pmatch, _) =>
                {
                    var m = pmatch.GetMatch();
                    matches.Add(new YaraxMatchInfo(name, m.Offset, m.Length));
                });
            });

            return matches;
        }

        /// <summary>
        /// Retrieves the list of all raw pattern matches found by the rule.
        /// </summary>
        /// <remarks>
        /// This method obtains only the raw match data without any additional context such as pattern names in order to reduce the overhead of string marshalling.
        /// </remarks>
        public readonly List<YaraxMatch> GetRawMatches()
        {
            var matches = new List<YaraxMatch>();
            Rule.IteratePatterns((pattern, _) =>
            {
                pattern.IterateMatches((pmatch, _) =>
                {
                    matches.Add(pmatch.GetMatch());
                });
            });

            return matches;
        }
    }
}
