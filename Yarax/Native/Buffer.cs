using System.Runtime.InteropServices;
using Yarax.Native;

namespace Yarax.Native
{
    public partial class NativeMethods
    {
        [LibraryImport("yara_x_capi")]
        public static partial void yrx_buffer_destroy(IntPtr buf);
    }
}

namespace Yarax
{
    public class YaraxBufferHandle : SafeNativePtrHandle
    {
        protected override bool ReleaseHandle()
        {
            NativeMethods.yrx_buffer_destroy(handle);
            return true;
        }

        [StructLayout(LayoutKind.Sequential)]
        struct YRX_BUFFER
        {
            public nint Data;
            public nuint Length;
        };

        /// <summary>
        /// Returns a byte array containing the data from the underlying buffer.
        /// </summary>
        /// <remarks>
        /// The returned array is a copy of the buffer's contents at the time of the call. This copy can be used after this buffer is disposed.
        /// </remarks>
        /// <returns>A byte array that contains the buffer's data. If the buffer is empty, returns an empty array.</returns>
        public byte[] ToArray() 
        {
            ObjectDisposedException.ThrowIf(IsInvalid, "This object is in an invalid state");

            var buf = Marshal.PtrToStructure<YRX_BUFFER>(this.handle);

            if (buf.Length == 0 || buf.Data == nint.Zero)
                return [];

            var result = new byte[buf.Length];
            Marshal.Copy(buf.Data, result, 0, (int)buf.Length);
            return result;
        }

        /// <summary>
        /// Returns a span representing the contents of the underlying buffer.
        /// </summary>
        /// <remarks>
        /// The returned span is valid only while the buffer is not disposed. Accessing the span
        /// after disposal may result in undefined behavior.
        /// </remarks>
        /// <returns>A <see cref="Span{byte}"/> containing the buffer's data.</returns>
        public unsafe Span<byte> AsSpan()
        {
            ObjectDisposedException.ThrowIf(IsInvalid, "This object is in an invalid state");

            var buf = Marshal.PtrToStructure<YRX_BUFFER>(this.handle);
            
            if (buf.Length == 0 || buf.Data == nint.Zero)
                return Span<byte>.Empty;

            return new Span<byte>(buf.Data.ToPointer(), (int)buf.Length);
        }
    }
}