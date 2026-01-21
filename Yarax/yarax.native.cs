using System.Runtime.InteropServices;

namespace Yarax
{
    public enum YaraxResult
    {
        SUCCESS,
        SYNTAX_ERROR,
        VARIABLE_ERROR,
        SCAN_ERROR,
        SCAN_TIMEOUT,
        INVALID_ARGUMENT,
        INVALID_UTF8,
        SERIALIZATION_ERROR,
        NO_METADATA,
        YRX_NOT_SUPPORTED
    };

    public class YaraxException(YaraxResult Result, string Message) : Exception(Message)
    {
        readonly public YaraxResult Result = Result;

        public static YaraxException WithLastError(YaraxResult result)
        {
            var error = Native.NativeMethods.yrx_last_error();
            return new YaraxException(result, string.IsNullOrWhiteSpace(error) ? $"YaraX error: {result}" : error);
        }

        public YaraxException(YaraxResult result) : this(result, $"YaraX error: {result}") { }
    }
}

namespace Yarax.Native 
{
    public abstract class SafeNativePtrHandle : SafeHandle
    {
        public override bool IsInvalid => this.handle == nint.Zero;
        
        public SafeNativePtrHandle(nint handle, bool ownsHandle) : base(nint.Zero, ownsHandle)
        {
            this.SetHandle(handle);
        }

        protected SafeNativePtrHandle() : base(nint.Zero, true)
        {

        }
    }

    public partial class NativeMethods
    {
        [LibraryImport("yara_x_capi", EntryPoint = "yrx_last_error")]
        private static partial IntPtr _yrx_last_error();

        public static string? yrx_last_error()
        {
            var ptr = _yrx_last_error();
            if (ptr == IntPtr.Zero)
                return null;
            return Marshal.PtrToStringUTF8(ptr);
        }
    }

    public static class YaraExten
    {
        public static void Assert(this YaraxResult result)
        {
            if (result != YaraxResult.SUCCESS)
            {
                throw YaraxException.WithLastError(result);
            }
        }
    }
}
