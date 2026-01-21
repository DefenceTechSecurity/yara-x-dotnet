using System.Runtime.InteropServices;
using Yarax.Native;

namespace Yarax.Native
{
    public partial class NativeMethods
    {
        [LibraryImport("yara_x_capi")]
        public static partial YaraxResult yrx_compiler_create(CompilerFlags flags, out YaraxCompilerHandle compiler);

        [LibraryImport("yara_x_capi")]
        public static partial void yrx_compiler_destroy(IntPtr compiler);

        [LibraryImport("yara_x_capi")]
        public static partial YaraxResult yrx_compiler_add_source(YaraxCompilerHandle compiler,
            [MarshalAs(UnmanagedType.LPUTF8Str)] string src);

        [LibraryImport("yara_x_capi")]
        public static partial YaraxResult yrx_compiler_add_source_with_origin(YaraxCompilerHandle compiler,
                                            [MarshalAs(UnmanagedType.LPUTF8Str)] string src,
                                            [MarshalAs(UnmanagedType.LPUTF8Str)] string origin);

        [LibraryImport("yara_x_capi")]
        public static partial YaraxResult yrx_compiler_new_namespace(YaraxCompilerHandle compiler,
            [MarshalAs(UnmanagedType.LPUTF8Str)] string nameSpace);

        [LibraryImport("yara_x_capi")]
        public static partial YaraxResult yrx_compiler_errors_json(YaraxCompilerHandle compiler, out YaraxBufferHandle buf);

        [LibraryImport("yara_x_capi")]
        public static partial YaraxResult yrx_compiler_warnings_json(YaraxCompilerHandle compiler, out YaraxBufferHandle buf);

        [LibraryImport("yara_x_capi")]
        public static partial YaraxRulesHandle yrx_compiler_build(YaraxCompilerHandle compiler);

        [LibraryImport("yara_x_capi")]
        public static partial YaraxResult yrx_compiler_ignore_module(YaraxCompilerHandle compiler,
            [MarshalAs(UnmanagedType.LPUTF8Str)] string module);

        [LibraryImport("yara_x_capi")]
        public static partial YaraxResult yrx_compiler_ban_module(YaraxCompilerHandle compiler,
            [MarshalAs(UnmanagedType.LPUTF8Str)] string module,
            [MarshalAs(UnmanagedType.LPUTF8Str)] string error_title,
            [MarshalAs(UnmanagedType.LPUTF8Str)] string error_msg);
    }
}

namespace Yarax 
{
    [Flags]
    public enum CompilerFlags : uint
    {
        None = 0,
        COLORIZE_ERRORS = 1,
        RELAXED_RE_SYNTAX = 1 << 1,
        ERROR_ON_SLOW_PATTERN = 1 << 2,
        ERROR_ON_SLOW_LOOP = 1 << 3,
        YRX_ENABLE_CONDITION_OPTIMIZATION = 1 << 4,
        YRX_DISABLE_INCLUDES = 1 << 5
    }

    public class YaraxCompilerHandle : SafeNativePtrHandle
    {
        /// <summary>
        /// Creates a new instance of a YARA-X compiler handle with the specified compiler flags.
        /// </summary>
        /// <param name="flags">A bitwise combination of values that specify options for the compiler. The default is CompilerFlags.None.</param>
        /// <returns>A handle to the newly created YARA-X compiler instance.</returns>
        public static YaraxCompilerHandle Create(CompilerFlags flags = CompilerFlags.None)
        {
            NativeMethods.yrx_compiler_create(flags, out var compiler).Assert();
            return compiler;
        }

        /// <summary>
        /// Tells the compiler that a YARA module is not supported. Import statements for ignored modules will be ignored without errors but a warning will be issued. Any rule that make use of an ignored module will be ignored, while the rest of rules that don’t rely on that module will be correctly compiled.
        /// </summary>
        public void IgnoreModule(string moduleName) => 
            NativeMethods.yrx_compiler_ignore_module(this, moduleName).Assert();

        /// <summary>
        /// Tell the compiler that a YARA module can’t be used. Import statements for the banned module will cause an error. The error message can be customized by using the given error title and message. If this function is called multiple times with the same module name, the error title and message will be updated.
        /// </summary>
        public void BanModule(string moduleName, string errorTitle, string errorMsg) =>
            NativeMethods.yrx_compiler_ban_module(this, moduleName, errorTitle, errorMsg).Assert();

        /// <summary>
        /// Adds a YARA source code to be compiled, specifying an origin for the source code. 
        /// </summary>
        /// <param name="origin">A string that identifies the origin of the code. This is shown in error reports</param>
        /// <param name="content">Yara code to be compiled</param>
        public void AddRuleString(string origin, string content) =>
            NativeMethods.yrx_compiler_add_source_with_origin(this, content, origin).Assert();

        public void AddFile(string path)
        {
            var content = File.ReadAllText(path);
            AddRuleString(path, content);
        }

        /// <summary>
        /// Creates a new namespace. Further calls to <see cref="AddRuleString(string, string)"/> will put the rules under the newly created namespace.
        /// </summary>
        public void SetNamespace(string nameSpace)
        {
            NativeMethods.yrx_compiler_new_namespace(this, nameSpace).Assert();
        }

        /// <summary>
        /// Returns the errors encountered during the compilation in JSON format. Refer to yara-x documentation for the JSON schema.
        /// </summary>
        public string? GetErrorsJson()
        {
            NativeMethods.yrx_compiler_errors_json(this, out var buf).Assert();
            using (buf)
            {
                var span = buf.AsSpan();
                return System.Text.Encoding.UTF8.GetString(span);
            }
        }

        /// <summary>
        /// Returns the warnings encountered during the compilation in JSON format. Refer to yara-x documentation for the JSON schema.
        /// </summary>
        public string? GetWarningsJson()
        {
            NativeMethods.yrx_compiler_warnings_json(this, out var buf).Assert();
            using (buf)
            {
                var span = buf.AsSpan();
                return System.Text.Encoding.UTF8.GetString(span);
            }
        }

        /// <summary>
        /// Builds the source code previously added to the compiler, producing a <see cref="YaraxRulesHandle"/> object that can be used for scanning data. After calling this function the compiler is reset to its initial state, you can keep using it by adding more sources and calling this function again.
        /// </summary>
        public YaraxRulesHandle Build() 
        {
            return NativeMethods.yrx_compiler_build(this);
        }

        protected override bool ReleaseHandle()
        {
            NativeMethods.yrx_compiler_destroy(handle);
            return true;
        }
    }
}
