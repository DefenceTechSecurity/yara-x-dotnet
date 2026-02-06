using System.Runtime.InteropServices;
using DefenceTechSecurity.Yarax.Native;

namespace DefenceTechSecurity.Yarax.Native
{
    public partial class NativeMethods
    {
        [LibraryImport("yara_x_capi")]
        public static partial YaraxResult yrx_scanner_create(YaraxRulesHandle rules, out YaraxScannerHandle scanner);

        [LibraryImport("yara_x_capi")]
        public static partial void yrx_scanner_destroy(IntPtr scanner);

        [LibraryImport("yara_x_capi")]
        public static partial YaraxResult yrx_scanner_scan(YaraxScannerHandle scanner, in byte data, nuint len);

        public delegate void YRX_RULE_CALLBACK(YaraxRuleRef rule, nint user_data);

        [LibraryImport("yara_x_capi")]
        public static partial YaraxResult yrx_scanner_on_matching_rule(YaraxScannerHandle scanner, nint callback, nint user_data);

        [LibraryImport("yara_x_capi")]
        // Refer to https://github.com/VirusTotal/yara-x/blob/f5f37ab131000099a19a58a58c4af02a42fe86d8/capi/src/scanner.rs#L321
        // THe documentation at has a wrong signature https://virustotal.github.io/yara-x/docs/api/c/c-/#yrx_scanner_scan_block
        public static partial YaraxResult yrx_scanner_scan_block(YaraxScannerHandle scanner, ulong base_address, in byte data, nuint len);

        [LibraryImport("yara_x_capi")]
        public static partial YaraxResult yrx_scanner_finish(YaraxScannerHandle scanner);
    }
}

namespace DefenceTechSecurity.Yarax
{
    /// <summary>
    /// Represents a safe handle for a Yara-x scanner instance, enabling scanning operations over memory blocks or
    /// buffers using specified rules. This class is not thread-safe, however you can create as many instances as needed from the same <see cref="YaraxRulesHandle"/> instance.
    /// </summary>
    /// <remarks>
    /// This class does not take ownership of the associated rules handle; ensure that the rules handle remains valid during the lifetime of this scanner.
    /// </remarks>
    public class YaraxScannerHandle : SafeNativePtrHandle
    {
        // Keep a reference to the rules to ensure they don't get disposed while the scanner is alive
        // We do not call dispose on this handle
        protected YaraxRulesHandle Rules { get; private set; } = null!;

        // Pin the callback so it doesn't get GC'd while native code might call it.
        GCHandle callbackHandle;

        public static YaraxScannerHandle Create(YaraxRulesHandle rules)
        {
            if (rules.IsInvalid || rules.IsClosed)
                throw new ArgumentException("The provided rules handle is invalid.");

            NativeMethods.yrx_scanner_create(rules, out YaraxScannerHandle scanner).Assert();

            scanner.Rules = rules;
            return scanner;
        }

        private void EnsureRulesValid()
        {
            if (Rules.IsClosed)
                throw new ObjectDisposedException("The Rules object of this scanner is not valid. The rules object must stay valid for the whole lifetime of this scanner object.");
        }

        /// <summary>
        /// Incrementally scans a block of data starting at the specified block offset.
        /// Once this method is called the scanner switches to block scanning mode, and <see cref="Scan(ReadOnlySpan{byte})"/> cannot be called anymore.
        /// After all blocks have been scanned, <see cref="FinishScanBlocks"/> must be called to finalize the scanning process.
        /// </summary>
        /// <param name="offsetInStream">The offset of the provided block in the virtual stream of data</param>
        /// <param name="data">The data to be scanned</param>
        public void ScanBlock(ulong offsetInStream, ReadOnlySpan<byte> data)
        {
            EnsureRulesValid();

            if (data.Length == 0)
                return;

            NativeMethods.yrx_scanner_scan_block(this, offsetInStream, in data[0], (nuint)data.Length).Assert();
        }

        /// <summary>
        /// Finalizes the block-scanning process and triggers any rule match events for matches found during block scanning.
        /// </summary>
        /// <remarks>
        /// Even after calling this method, the scanner remains in block scanning mode and cannot revert to normal scanning mode.
        /// </remarks>
        public void FinishScanBlocks()
        {
            EnsureRulesValid();
            NativeMethods.yrx_scanner_finish(this).Assert();
        }

        /// <summary>
        /// Scans a memory buffer.
        /// </summary>
        public void Scan(ReadOnlySpan<byte> data)
        {
            EnsureRulesValid();

            if (data.Length == 0)
                return;

            NativeMethods.yrx_scanner_scan(this, in data[0], (nuint)data.Length).Assert();
        }

        /// <summary>
        /// Sets a callback function that is called by the scanner for each rule that matched during a scan.
        /// </summary>
        /// <remarks>
        /// Setting the callback to null will remove the previous callback.
        /// </remarks>
        /// <param name="callback">The callback to be invoked</param>
        /// <param name="userData">An arbitrary value that is passed to the callback when it is invoked</param>
        public void SetMatchingCallback(NativeMethods.YRX_RULE_CALLBACK? callback, nint userData = 0)
        {
            ReleaseCurrentCallback();

            if (callback is null)
                return;

            callbackHandle = GCHandle.Alloc(callback, GCHandleType.Normal);
            NativeMethods.yrx_scanner_on_matching_rule(this, Marshal.GetFunctionPointerForDelegate(callback), userData).Assert();
        }

        void ReleaseCurrentCallback()
        {
            NativeMethods.yrx_scanner_on_matching_rule(this, IntPtr.Zero, IntPtr.Zero).Assert();

            if (callbackHandle.IsAllocated)
                callbackHandle.Free();

            callbackHandle = default;
        }

        protected override void Dispose(bool disposing)
        {
            if (disposing)
                ReleaseCurrentCallback();

            base.Dispose(disposing);
        }

        protected override bool ReleaseHandle()
        {
            NativeMethods.yrx_scanner_destroy(handle);
            return true;
        }
    }
}
