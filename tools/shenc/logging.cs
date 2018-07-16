using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Text;

namespace shenc
{
    partial class Program
    {
        #region TODO: use a real logging framework

        private static void Log(string text)
        {
            Console.WriteLine(text);
        }

        private static void Log(Exception ex)
        {
            try
            {
                var prefix = "";
                while (ex != null)
                {
                    var text = $@"{prefix}Exception: {ex.GetType().FullName}
Message: {ex.Message}
StackTrace: {ex.StackTrace}";
                    Console.Error.WriteLine(text);
                    DebugLog(text);
                    ex = ex.InnerException;
                    prefix = "Inner";
                }
            }
            catch (Exception L_ex)
            {
                Trace.TraceError($"{L_ex.Message}=>{L_ex.StackTrace}");
            }
        }

        private static void DebugLog(string text)
        {
            if (Debugger.IsAttached)
            {
                Trace.WriteLine($"{DateTime.UtcNow:o} [{_processId}] {text}");
            }
        }

        #endregion TODO: use a real logging framework

    }
}
