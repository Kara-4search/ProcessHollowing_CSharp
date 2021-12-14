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
            ProcessHollow.CreateProcess_custom();
        }
    }
}
