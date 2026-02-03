using System.Runtime.InteropServices;
using DefenceTechSecurity.Yarax.Native;

namespace DefenceTechSecurity.Yarax.Native
{
    public partial class NativeMethods
    {
        [LibraryImport("yara_x_capi")]
        public static partial YaraxResult yrx_rules_serialize(YaraxRulesHandle rules, out YaraxBufferHandle buf);

        [LibraryImport("yara_x_capi")]
        public static partial YaraxResult yrx_rules_deserialize(in byte data, nuint lenght, out YaraxRulesHandle rules);

        [LibraryImport("yara_x_capi")]
        public static partial void yrx_rules_destroy(IntPtr rules);

        [LibraryImport("yara_x_capi")]
        public static partial YaraxResult yrx_rule_identifier(YaraxRuleRef rule, out IntPtr utf8, out nint size);

        [LibraryImport("yara_x_capi")]
        public static partial YaraxResult yrx_rule_namespace(YaraxRuleRef rule, out IntPtr utf8, out nint size);

        public delegate void YRX_PATTERN_CALLBACK(YaraxPatternRef pattern, nint user_data);

        [LibraryImport("yara_x_capi")]
        public static partial YaraxResult yrx_rule_iter_patterns(YaraxRuleRef rule, YRX_PATTERN_CALLBACK callback, nuint user_data = 0);

        public delegate void YRX_TAG_CALLBACK([MarshalAs(UnmanagedType.LPUTF8Str)] string tag, nint user_data);

        [LibraryImport("yara_x_capi")]
        public static partial YaraxResult yrx_rule_iter_tags(YaraxRuleRef rule, YRX_TAG_CALLBACK callback, nint user_data);

        [LibraryImport("yara_x_capi")]
        public static partial YaraxResult yrx_pattern_identifier(YaraxPatternRef pattern, out IntPtr utf8, out nint size);

        public delegate void YRX_MATCH_CALLBACK(YaraxMatchRef match, nint user_data);

        [LibraryImport("yara_x_capi")]
        public static partial YaraxResult yrx_pattern_iter_matches(YaraxPatternRef pattern, YRX_MATCH_CALLBACK callback, nint user_data = 0);
    }
}

namespace DefenceTechSecurity.Yarax
{ 
    /// <summary>
    /// Represents a safe handle for a native Yara-x rules object, providing methods to serialize and deserialize rule
    /// sets.
    /// </summary>
    /// <remarks>
    /// This class manages the lifetime of a native Yara-x rules resource and ensures proper cleanup
    /// when disposed. A single instance of this class can be shared across multiple <see cref="YaraxScannerHandle"/> instances
    /// </remarks>
    public class YaraxRulesHandle : SafeNativePtrHandle
    {
        /// <summary>
        /// Deserializes an instance of the <see cref="YaraxRulesHandle"/> class from a sequence of bytes produced by the <see cref="Serialize"/> method.
        /// </summary>
        public static YaraxRulesHandle FromSerializedRules(ReadOnlySpan<byte> data)
        {
            NativeMethods.yrx_rules_deserialize(in data[0], (nuint)data.Length, out var res).Assert();
            return res;
        }

        /// <summary>
        /// Serializes the rules as a sequence of bytes.
        /// </summary>
        /// <remarks>
        /// Yara rules might contain binary patterns that are also present in known malware. Storing this byte array on disk as-is might trigger antivirus alerts.
        /// </remarks>
        public byte[] Serialize() 
        {
            NativeMethods.yrx_rules_serialize(this, out var buffer).Assert();
            var data = buffer.ToArray();
            buffer.Dispose();
            return data;
        }

        protected override bool ReleaseHandle()
        {
            NativeMethods.yrx_rules_destroy(handle);
            return true;
        }
    }

    /// <summary>
    /// Represents a non-owning reference to a Yara-x rule within a ruleset.
    /// This object and any span returned from it is accessible only during the callback of the event that provides it.
    /// </summary>
    [StructLayout(LayoutKind.Explicit)]
    public readonly ref struct YaraxRuleRef 
    {
        // This pointer is owned by its parent Rule, don't let it escape the scope by making it a ref struct
        [FieldOffset(0)]
        readonly nint Ptr;

        /// <summary>
        /// The raw UTF-8 bytes representing the rule identifier. This string is owned by the native yara-x library and is only valid for the lifetime of this object.
        /// </summary>
        public unsafe ReadOnlySpan<byte> IdentifierUTF8Span        
        {
            get
            {
                NativeMethods.yrx_rule_identifier(this, out var utf8Ptr, out var size).Assert();
                return new ReadOnlySpan<byte>((byte*)utf8Ptr, checked((int)size));
            }
        }

        /// <summary>
        /// The identifier of this rule.
        /// </summary>
        public string Identifier => System.Text.Encoding.UTF8.GetString(IdentifierUTF8Span);

        /// <summary>
        /// The raw UTF-8 bytes representing the rule namespace. This string is owned by the native yara-x library and is only valid for the lifetime of this object.
        /// </summary>
        public unsafe ReadOnlySpan<byte> NamespaceUTF8Span
        {
            get
            {
                NativeMethods.yrx_rule_namespace(this, out var utf8Ptr, out var size).Assert();
                return new ReadOnlySpan<byte>((byte*)utf8Ptr, checked((int)size));
            }
        }

        /// <summary>
        /// The namespace of this rule.
        /// </summary>
        public string Namespace => System.Text.Encoding.UTF8.GetString(NamespaceUTF8Span);

        /// <summary>
        /// Iterates over the patterns in this rule, calling the callback with a <see cref="YaraxPatternRef"/> structure for each pattern.
        /// </summary>
        /// <remarks>
        /// The content of the <see cref="YaraxPatternRef"/> instances are only valid during the callback execution. Storing and accessing them outside of the callback will result in undefined behavior.
        /// </remarks>
        public void IteratePatterns(NativeMethods.YRX_PATTERN_CALLBACK callback, nuint userData = 0)
        {
            NativeMethods.yrx_rule_iter_patterns(this, callback, userData).Assert();
        }

        /// <summary>
        /// Retrieves a list of all tags associated with this rule.
        /// </summary>
        public List<string> GetTags() 
        {
            var result = new List<string>();
            NativeMethods.yrx_rule_iter_tags(this, (tag, userData) =>
            {
                result.Add(tag);
            }, 0).Assert();
            return result;
        }
    }

    /// <summary>
    /// Provides a non-owning reference to a compiled Yara-x pattern, enabling access to its identifier and iteration over
    /// its matches. This object and any span returned from it is accessible only during the callback of the event that provides it.
    /// </summary>
    [StructLayout(LayoutKind.Explicit)]
    public readonly ref struct YaraxPatternRef 
    {
        [FieldOffset(0)]
        readonly nint Ptr;

        /// <summary>
        /// The raw UTF-8 bytes representing the identifier of this pattern. This string is owned by the native yara-x library and is only valid for the lifetime of this object.
        /// </summary>
        public unsafe ReadOnlySpan<byte> IdentifierUTF8Span
        {
            get
            {
                NativeMethods.yrx_pattern_identifier(this, out var utf8Ptr, out var size).Assert();
                return new ReadOnlySpan<byte>((byte*)utf8Ptr, checked((int)size));
            }
        }

        /// <summary>
        /// The identifier of this pattern.
        /// </summary>
        public string Identifier => System.Text.Encoding.UTF8.GetString(IdentifierUTF8Span);

        /// <summary>
        /// Iterates over the matches of a pattern, calling the callback with a <see cref="YaraxMatchRef"/> structure for each pattern.
        /// </summary>
        /// <remarks>
        /// The content of the <see cref="YaraxMatchRef"/> instances are only valid during the callback execution. Storing and accessing them outside of the callback will result in undefined behavior.
        /// </remarks>
        public void IterateMatches(NativeMethods.YRX_MATCH_CALLBACK callback, nint userData = 0)
        {
            NativeMethods.yrx_pattern_iter_matches(this, callback, userData).Assert();
        }
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct YaraxMatch
    {
        public nint Offset;
        public nint Length;
    }

    /// <summary>
    /// Provides a non-owning reference to a Yara-x match object. The underlying match data is only valid during the callback of the event that generated it.
    /// </summary>
    [StructLayout(LayoutKind.Sequential)]
    public readonly ref struct YaraxMatchRef
    {
        readonly nint Ptr;

        /// <summary>
        /// Retrieves a managed copy of the match data.
        /// </summary>
        /// <remarks>
        /// Accessing <see cref="YaraxMatch"/> is always safe even after the <see cref="YaraxMatchRef"/> goes out of scope.
        /// </remarks>
        public YaraxMatch GetMatch() => Marshal.PtrToStructure<YaraxMatch>(Ptr);
    }
}
