using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading.Tasks;
using static ProcessHollowing.NativeStructs;
using static ProcessHollowing.NativeFunctions;

namespace ProcessHollowing
{
    class Program
    {
        static void Main(string[] args)
        {
            string CreateProcess_path = @"C:\Windows\System32\mspaint.exe";
            string ProcessReplace_path = @"C:\Windows\System32\cmd.exe";
            ProcessHollow.CreateProcess_custom(CreateProcess_path, ProcessReplace_path);

        }
    }
}
