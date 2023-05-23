// RemoteFileMonitor (File: FileMonitorHook\InjectionEntryPoint.cs)
//
// Copyright (c) 2017 Justin Stenning
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
// 
// The above copyright notice and this permission notice shall be included in
// all copies or substantial portions of the Software.
// 
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
// THE SOFTWARE.
//
// Please visit https://easyhook.github.io for more information
// about the project, latest updates and other tutorials.

using EasyHook;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Net.NetworkInformation;
using System.Reflection;
using System.Runtime.InteropServices;
using System.Security.Permissions;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using static FileMonitorHook.InjectionEntryPoint;

namespace FileMonitorHook
{
    /// <summary>
    /// EasyHook will look for a class implementing <see cref="EasyHook.IEntryPoint"/> during injection. This
    /// becomes the entry point within the target process after injection is complete.
    /// </summary>
    public class InjectionEntryPoint: EasyHook.IEntryPoint
    {
        /// <summary>
        /// Reference to the server interface within FileMonitor
        /// </summary>
        ServerInterface _server = null;

        /// <summary>
        /// Message queue of all files accessed
        /// </summary>
        Queue<string> _messageQueue = new Queue<string>();

        string ChannelName { get; set; }

        /// <summary>
        /// EasyHook requires a constructor that matches <paramref name="context"/> and any additional parameters as provided
        /// in the original call to <see cref="EasyHook.RemoteHooking.Inject(int, EasyHook.InjectionOptions, string, string, object[])"/>.
        /// 
        /// Multiple constructors can exist on the same <see cref="EasyHook.IEntryPoint"/>, providing that each one has a corresponding Run method (e.g. <see cref="Run(EasyHook.RemoteHooking.IContext, string)"/>).
        /// </summary>
        /// <param name="context">The RemoteHooking context</param>
        /// <param name="channelName">The name of the IPC channel</param>
        public InjectionEntryPoint(
            RemoteHooking.IContext context,
            string channelName)
        {
            ChannelName = channelName;

            // Connect to server object using provided channel name
            _server = RemoteHooking.IpcConnectClient<ServerInterface>(channelName);

            // If Ping fails then the Run method will be not be called
            _server.Ping();
        }

        /// <summary>
        /// The main entry point for our logic once injected within the target process. 
        /// This is where the hooks will be created, and a loop will be entered until host process exits.
        /// EasyHook requires a matching Run method for the constructor
        /// </summary>
        /// <param name="context">The RemoteHooking context</param>
        /// <param name="channelName">The name of the IPC channel</param>
        public void Run(
            RemoteHooking.IContext context,
            string channelName)
        {
            // Injection is now complete and the server interface is connected
            _server.IsInstalled(RemoteHooking.GetCurrentProcessId());

            // Install hooks

            // CreateFile https://msdn.microsoft.com/en-us/library/windows/desktop/aa363858(v=vs.85).aspx
            var createFileHook = LocalHook.Create(
                LocalHook.GetProcAddress("kernel32.dll", "CreateFileW"),
                new CreateFile_Delegate(CreateFile_Hook),
                this);

            // ReadFile https://msdn.microsoft.com/en-us/library/windows/desktop/aa365467(v=vs.85).aspx
            var readFileHook = LocalHook.Create(
                LocalHook.GetProcAddress("kernel32.dll", "ReadFile"),
                new ReadFile_Delegate(ReadFile_Hook),
                this);

            // WriteFile https://msdn.microsoft.com/en-us/library/windows/desktop/aa365747(v=vs.85).aspx
            var writeFileHook = LocalHook.Create(
                LocalHook.GetProcAddress("kernel32.dll", "WriteFile"),
                new WriteFile_Delegate(WriteFile_Hook),
                this);

            var createProcessHook = LocalHook.Create(
                LocalHook.GetProcAddress("kernel32.dll", "CreateProcessW"),
                new CreateProcess_Delegate(CreateProcess_Hook),
                this);

            // Activate hooks on all threads except the current thread
            //createFileHook.ThreadACL.SetExclusiveACL(new Int32[] { 0 });
            //readFileHook.ThreadACL.SetExclusiveACL(new Int32[] { 0 });
            //writeFileHook.ThreadACL.SetExclusiveACL(new Int32[] { 0 });
            createProcessHook.ThreadACL.SetExclusiveACL(new Int32[] { 0 }); // Thread.CurrentThread.ManagedThreadId  ????

            _server.ReportMessage("CreateFile, ReadFile and WriteFile hooks installed");

            // Wake up the process (required if using RemoteHooking.CreateAndInject)
            RemoteHooking.WakeUpProcess();

            try
            {
                // Loop until FileMonitor closes (i.e. IPC fails)
                while (true)
                {
                    System.Threading.Thread.Sleep(500);

                    string[] queued = null;

                    lock (_messageQueue)
                    {
                        queued = _messageQueue.ToArray();
                        _messageQueue.Clear();
                    }

                    // Send newly monitored file accesses to FileMonitor
                    if (queued != null && queued.Length > 0)
                    {
                        _server.ReportMessages(queued);
                    }
                    else
                    {
                        _server.Ping();
                    }
                }
            }
            catch
            {
                // Ping() or ReportMessages() will raise an exception if host is unreachable
            }

            // Remove hooks
            createFileHook.Dispose();
            readFileHook.Dispose();
            writeFileHook.Dispose();
            createProcessHook.Dispose();

            // Finalise cleanup of hooks
            LocalHook.Release();
        }

        /// <summary>
        /// P/Invoke to determine the filename from a file handle
        /// https://msdn.microsoft.com/en-us/library/windows/desktop/aa364962(v=vs.85).aspx
        /// </summary>
        /// <param name="hFile"></param>
        /// <param name="lpszFilePath"></param>
        /// <param name="cchFilePath"></param>
        /// <param name="dwFlags"></param>
        /// <returns></returns>
        [DllImport("Kernel32.dll", SetLastError = true, CharSet = CharSet.Auto)]
        static extern uint GetFinalPathNameByHandle(IntPtr hFile, [MarshalAs(UnmanagedType.LPTStr)] StringBuilder lpszFilePath, uint cchFilePath, uint dwFlags);

        #region CreateFileW Hook

        /// <summary>
        /// The CreateFile delegate, this is needed to create a delegate of our hook function <see cref="CreateFile_Hook(string, uint, uint, IntPtr, uint, uint, IntPtr)"/>.
        /// </summary>
        /// <param name="filename"></param>
        /// <param name="desiredAccess"></param>
        /// <param name="shareMode"></param>
        /// <param name="securityAttributes"></param>
        /// <param name="creationDisposition"></param>
        /// <param name="flagsAndAttributes"></param>
        /// <param name="templateFile"></param>
        /// <returns></returns>
        [UnmanagedFunctionPointer(CallingConvention.StdCall,
                    CharSet = CharSet.Unicode,
                    SetLastError = true)]
        delegate IntPtr CreateFile_Delegate(
                    String filename,
                    UInt32 desiredAccess,
                    UInt32 shareMode,
                    IntPtr securityAttributes,
                    UInt32 creationDisposition,
                    UInt32 flagsAndAttributes,
                    IntPtr templateFile);

        /// <summary>
        /// Using P/Invoke to call original method.
        /// https://msdn.microsoft.com/en-us/library/windows/desktop/aa363858(v=vs.85).aspx
        /// </summary>
        /// <param name="filename"></param>
        /// <param name="desiredAccess"></param>
        /// <param name="shareMode"></param>
        /// <param name="securityAttributes"></param>
        /// <param name="creationDisposition"></param>
        /// <param name="flagsAndAttributes"></param>
        /// <param name="templateFile"></param>
        /// <returns></returns>
        [DllImport("kernel32.dll",
            CharSet = CharSet.Unicode,
            SetLastError = true, CallingConvention = CallingConvention.StdCall)]
        static extern IntPtr CreateFileW(
            String filename,
            UInt32 desiredAccess,
            UInt32 shareMode,
            IntPtr securityAttributes,
            UInt32 creationDisposition,
            UInt32 flagsAndAttributes,
            IntPtr templateFile);

        /// <summary>
        /// The CreateFile hook function. This will be called instead of the original CreateFile once hooked.
        /// </summary>
        /// <param name="filename"></param>
        /// <param name="desiredAccess"></param>
        /// <param name="shareMode"></param>
        /// <param name="securityAttributes"></param>
        /// <param name="creationDisposition"></param>
        /// <param name="flagsAndAttributes"></param>
        /// <param name="templateFile"></param>
        /// <returns></returns>
        IntPtr CreateFile_Hook(
            String filename,
            UInt32 desiredAccess,
            UInt32 shareMode,
            IntPtr securityAttributes,
            UInt32 creationDisposition,
            UInt32 flagsAndAttributes,
            IntPtr templateFile)
        {
            try
            {
                lock (this._messageQueue)
                {
                    if (this._messageQueue.Count < 1000)
                    {
                        string mode = string.Empty;
                        switch (creationDisposition)
                        {
                            case 1:
                                mode = "CREATE_NEW";
                                break;
                            case 2:
                                mode = "CREATE_ALWAYS";
                                break;
                            case 3:
                                mode = "OPEN_ALWAYS";
                                break;
                            case 4:
                                mode = "OPEN_EXISTING";
                                break;
                            case 5:
                                mode = "TRUNCATE_EXISTING";
                                break;
                        }

                        // Add message to send to FileMonitor
                        this._messageQueue.Enqueue(
                            string.Format("[{0}:{1}]: CREATE ({2}) \"{3}\"",
                            RemoteHooking.GetCurrentProcessId(),
                            RemoteHooking.GetCurrentThreadId(),
                            mode,
                            filename));
                    }
                }
            }
            catch
            {
                // swallow exceptions so that any issues caused by this code do not crash target process
            }

            var retValue = new IntPtr(0);
            // now call the original API...
            try
            {
                retValue = CreateFileW(
                    filename,
                    desiredAccess,
                    shareMode,
                    securityAttributes,
                    creationDisposition,
                    flagsAndAttributes,
                    templateFile);
                return retValue;
            }
            catch (Exception e)
            {
                lock (this._messageQueue)
                {
                    this._messageQueue.Enqueue(
                            string.Format("[{0}:{1}]: ERROR ({2}, {3}) \"{4}\"",
                            RemoteHooking.GetCurrentProcessId(),
                            RemoteHooking.GetCurrentThreadId(),
                            e.Message,
                            retValue,
                            filename));
                }
                throw;
            }
            finally
            {
                lock (this._messageQueue)
                {
                    this._messageQueue.Enqueue(
                                string.Format("[{0}:{1}]: ERROR ({2}, {3}) \"{4}\"",
                                RemoteHooking.GetCurrentProcessId(),
                                RemoteHooking.GetCurrentThreadId(),
                                Marshal.GetLastWin32Error(),
                                retValue,
                                filename));
                }
            }
        }

        #endregion

        #region ReadFile Hook

        /// <summary>
        /// The ReadFile delegate, this is needed to create a delegate of our hook function <see cref="ReadFile_Hook(IntPtr, IntPtr, uint, out uint, IntPtr)"/>.
        /// </summary>
        /// <param name="hFile"></param>
        /// <param name="lpBuffer"></param>
        /// <param name="nNumberOfBytesToRead"></param>
        /// <param name="lpNumberOfBytesRead"></param>
        /// <param name="lpOverlapped"></param>
        /// <returns></returns>
        [UnmanagedFunctionPointer(CallingConvention.StdCall, SetLastError = true)]
        delegate bool ReadFile_Delegate(
            IntPtr hFile,
            IntPtr lpBuffer,
            uint nNumberOfBytesToRead,
            out uint lpNumberOfBytesRead,
            IntPtr lpOverlapped);

        /// <summary>
        /// Using P/Invoke to call the orginal function
        /// </summary>
        /// <param name="hFile"></param>
        /// <param name="lpBuffer"></param>
        /// <param name="nNumberOfBytesToRead"></param>
        /// <param name="lpNumberOfBytesRead"></param>
        /// <param name="lpOverlapped"></param>
        /// <returns></returns>
        [DllImport("kernel32.dll", SetLastError = true, CallingConvention = CallingConvention.StdCall)]
        static extern bool ReadFile(
            IntPtr hFile, 
            IntPtr lpBuffer,
            uint nNumberOfBytesToRead, 
            out uint lpNumberOfBytesRead, 
            IntPtr lpOverlapped);

        /// <summary>
        /// The ReadFile hook function. This will be called instead of the original ReadFile once hooked.
        /// </summary>
        /// <param name="hFile"></param>
        /// <param name="lpBuffer"></param>
        /// <param name="nNumberOfBytesToRead"></param>
        /// <param name="lpNumberOfBytesRead"></param>
        /// <param name="lpOverlapped"></param>
        /// <returns></returns>
        bool ReadFile_Hook(
            IntPtr hFile,
            IntPtr lpBuffer,
            uint nNumberOfBytesToRead,
            out uint lpNumberOfBytesRead,
            IntPtr lpOverlapped)
        {
            bool result = false;
            //lpNumberOfBytesRead = 0;

            // Call original first so we have a value for lpNumberOfBytesRead
            result = ReadFile(hFile, lpBuffer, nNumberOfBytesToRead, out lpNumberOfBytesRead, lpOverlapped);

            try
            {
                lock (this._messageQueue)
                {
                    if (this._messageQueue.Count < 1000)
                    {
                        // Retrieve filename from the file handle
                        StringBuilder filename = new StringBuilder(255);
                        GetFinalPathNameByHandle(hFile, filename, 255, 0);

                        // Add message to send to FileMonitor
                        this._messageQueue.Enqueue(
                            string.Format("[{0}:{1}]: READ ({2} bytes) \"{3}\"",
                            EasyHook.RemoteHooking.GetCurrentProcessId(), EasyHook.RemoteHooking.GetCurrentThreadId()
                            , filename, filename));
                    }
                }
            }
            catch
            {
                // swallow exceptions so that any issues caused by this code do not crash target process
            }

            return result;
        }

        #endregion

        #region WriteFile Hook

        /// <summary>
        /// The WriteFile delegate, this is needed to create a delegate of our hook function <see cref="WriteFile_Hook(IntPtr, IntPtr, uint, out uint, IntPtr)"/>.
        /// </summary>
        /// <param name="hFile"></param>
        /// <param name="lpBuffer"></param>
        /// <param name="nNumberOfBytesToWrite"></param>
        /// <param name="lpNumberOfBytesWritten"></param>
        /// <param name="lpOverlapped"></param>
        /// <returns></returns>
        [UnmanagedFunctionPointer(CallingConvention.StdCall, CharSet = CharSet.Unicode, SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        delegate bool WriteFile_Delegate(
            IntPtr hFile,
            IntPtr lpBuffer,
            uint nNumberOfBytesToWrite,
            out uint lpNumberOfBytesWritten,
            IntPtr lpOverlapped);

        /// <summary>
        /// Using P/Invoke to call original WriteFile method
        /// </summary>
        /// <param name="hFile"></param>
        /// <param name="lpBuffer"></param>
        /// <param name="nNumberOfBytesToWrite"></param>
        /// <param name="lpNumberOfBytesWritten"></param>
        /// <param name="lpOverlapped"></param>
        /// <returns></returns>
        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true, CallingConvention = CallingConvention.StdCall)]
        [return: MarshalAs(UnmanagedType.Bool)]
        static extern bool WriteFile(
            IntPtr hFile,
            IntPtr lpBuffer,
            uint nNumberOfBytesToWrite,
            out uint lpNumberOfBytesWritten,
            IntPtr lpOverlapped);

        /// <summary>
        /// The WriteFile hook function. This will be called instead of the original WriteFile once hooked.
        /// </summary>
        /// <param name="hFile"></param>
        /// <param name="lpBuffer"></param>
        /// <param name="nNumberOfBytesToWrite"></param>
        /// <param name="lpNumberOfBytesWritten"></param>
        /// <param name="lpOverlapped"></param>
        /// <returns></returns>
        bool WriteFile_Hook(
            IntPtr hFile,
            IntPtr lpBuffer,
            uint nNumberOfBytesToWrite,
            out uint lpNumberOfBytesWritten,
            IntPtr lpOverlapped)
        {
            bool result = false;

            // Call original first so we get lpNumberOfBytesWritten
            result = WriteFile(hFile, lpBuffer, nNumberOfBytesToWrite, out lpNumberOfBytesWritten, lpOverlapped);

            try
            {
                lock (this._messageQueue)
                {
                    if (this._messageQueue.Count < 1000)
                    {
                        // Retrieve filename from the file handle
                        StringBuilder filename = new StringBuilder(255);
                        GetFinalPathNameByHandle(hFile, filename, 255, 0);

                        // Add message to send to FileMonitor
                        this._messageQueue.Enqueue(
                            string.Format("[{0}:{1}]: WRITE ({2} bytes) \"{3}\"",
                            RemoteHooking.GetCurrentProcessId(),
                            RemoteHooking.GetCurrentThreadId(),
                            lpNumberOfBytesWritten, filename));
                    }
                }
            }
            catch
            {
                // swallow exceptions so that any issues caused by this code do not crash target process
            }

            return result;
        }

        #endregion

        #region CreateProcess Hook

        /// <summary>
        /// The CreateProcess delegate, this is needed to create a delegate of our hook function <see cref="CreateProcess_Hook(IntPtr, IntPtr, uint, out uint, IntPtr)"/>.
        /// </summary>
        /// <param name="hFile"></param>
        /// <param name="lpBuffer"></param>
        /// <param name="nNumberOfBytesToWrite"></param>
        /// <param name="lpNumberOfBytesWritten"></param>
        /// <param name="lpOverlapped"></param>
        /// <returns></returns>
        [UnmanagedFunctionPointer(CallingConvention.StdCall, CharSet = CharSet.Unicode, SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        delegate bool CreateProcess_Delegate(
            string lpApplicationName,
            string lpCommandLine,
            ref SECURITY_ATTRIBUTES lpProcessAttributes,
            ref SECURITY_ATTRIBUTES lpThreadAttributes,
            bool bInheritHandles,
            uint dwCreationFlags,
            IntPtr lpEnvironment,
            string lpCurrentDirectory,
            [In] ref STARTUPINFOEX lpStartupInfo,
            out PROCESS_INFORMATION lpProcessInformation);

        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.SysUInt)]
        static extern uint ResumeThread(IntPtr hThread);

        /// <summary>
        /// Using P/Invoke to call original CreateProcessW method
        /// </summary>
        /// <param name="hFile"></param>
        /// <param name="lpBuffer"></param>
        /// <param name="nNumberOfBytesToWrite"></param>
        /// <param name="lpNumberOfBytesWritten"></param>
        /// <param name="lpOverlapped"></param>
        /// <returns></returns>
        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true, CallingConvention = CallingConvention.StdCall)]
        [return: MarshalAs(UnmanagedType.Bool)]
        static extern bool CreateProcessW(
            string lpApplicationName,
            string lpCommandLine,
            ref SECURITY_ATTRIBUTES lpProcessAttributes,
            ref SECURITY_ATTRIBUTES lpThreadAttributes,
            bool bInheritHandles,
            uint dwCreationFlags,
            IntPtr lpEnvironment,
            string lpCurrentDirectory,
            [In] ref STARTUPINFOEX lpStartupInfo,
            out PROCESS_INFORMATION lpProcessInformation);

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        struct STARTUPINFO
        {
            public Int32 cb;
            public string lpReserved;
            public string lpDesktop;
            public string lpTitle;
            public Int32 dwX;
            public Int32 dwY;
            public Int32 dwXSize;
            public Int32 dwYSize;
            public Int32 dwXCountChars;
            public Int32 dwYCountChars;
            public Int32 dwFillAttribute;
            public Int32 dwFlags;
            public Int16 wShowWindow;
            public Int16 cbReserved2;
            public IntPtr lpReserved2;
            public IntPtr hStdInput;
            public IntPtr hStdOutput;
            public IntPtr hStdError;
        }

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        struct STARTUPINFOEX
        {
            public STARTUPINFO StartupInfo;
            public IntPtr lpAttributeList;
        }

        [StructLayout(LayoutKind.Sequential)]
        internal struct PROCESS_INFORMATION
        {
            public IntPtr hProcess;
            public IntPtr hThread;
            public int dwProcessId;
            public int dwThreadId;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct SECURITY_ATTRIBUTES
        {
            public int nLength;
            public IntPtr lpSecurityDescriptor;
            public int bInheritHandle;
        }

        public static class DwCreationFlags
        {
            public static uint CREATE_SUSPENDED = 0x00000004U;
        }

        /// <summary>
        /// The WriteFile hook function. This will be called instead of the original WriteFile once hooked.
        /// </summary>
        /// <param name="hFile"></param>
        /// <param name="lpBuffer"></param>
        /// <param name="nNumberOfBytesToWrite"></param>
        /// <param name="lpNumberOfBytesWritten"></param>
        /// <param name="lpOverlapped"></param>
        /// <returns></returns>
        bool CreateProcess_Hook(
            string lpApplicationName,
            string lpCommandLine,
            ref SECURITY_ATTRIBUTES lpProcessAttributes,
            ref SECURITY_ATTRIBUTES lpThreadAttributes,
            bool bInheritHandles,
            uint dwCreationFlags,
            IntPtr lpEnvironment,
            string lpCurrentDirectory,
            [In] ref STARTUPINFOEX lpStartupInfo,
            out PROCESS_INFORMATION lpProcessInformation)
        {
            //
            //
            //
            //
            // TODO: Create an alternative to EasyHook's CreateAndInject that only takes in CreateProcessW inputs, and exposes them all the way to its interanl CreateProcessW call.
            //
            //
            //
            //
            //


            // The process should stay suspended iff the original execution called for it to be suspended.
            // Otherwise, the injection should unsuspend the process.
            bool leaveSuspended = (dwCreationFlags & DwCreationFlags.CREATE_SUSPENDED) > 0;

            lpStartupInfo.StartupInfo.wShowWindow = 1;

            // Start the process suspended
            var result = CreateProcessW(
                lpApplicationName,
                lpCommandLine,
                ref lpProcessAttributes,
                ref lpThreadAttributes,
                bInheritHandles,
                dwCreationFlags | DwCreationFlags.CREATE_SUSPENDED,
                lpEnvironment,
                lpCurrentDirectory,
                ref lpStartupInfo,
                out lpProcessInformation);

            string dllFullPath = Assembly.GetAssembly(GetType()).Location;

            MethodInfo dynMethod = typeof(RemoteHooking).GetMethod("InjectEx", BindingFlags.NonPublic | BindingFlags.Static);
            dynMethod.Invoke(null, new object[] {
                NativeAPI.GetCurrentProcessId(),
                lpProcessInformation.dwProcessId,
                lpProcessInformation.dwThreadId,
                0x20000000,
                dllFullPath,
                dllFullPath,
                /*InjectionOptions.NoWOW64Bypass*/ false,
                /*InjectionOptions.NoService*/ true,
                /*InjectionOptions.DoNotRequireStrongName*/ true,
                new object[] {ChannelName }
            });

            // Inject the hooking DLL (and resume the process)
            RemoteHooking.Inject(
                lpProcessInformation.dwProcessId,
                InjectionOptions.Default,
                dllFullPath,
                dllFullPath,
                // Custom arguments
                ChannelName);

            /*if (!leaveSuspended)
            {
                ResumeThread(lpProcessInformation.hThread);
            }*/

            try
            {
                lock (this._messageQueue)
                {
                    if (this._messageQueue.Count < 1000)
                    {
                        // Add message to send to FileMonitor
                        this._messageQueue.Enqueue(
                            string.Format("[{0}:{1}]: CREATE_PROCESS ({2}) \"{3} {4}\"",
                            RemoteHooking.GetCurrentProcessId(),
                            RemoteHooking.GetCurrentThreadId(),
                            lpProcessInformation.dwProcessId,
                            lpApplicationName,
                            lpCommandLine));
                    }
                }
            }
            catch
            {
                // swallow exceptions so that any issues caused by this code do not crash target process
            }

            return result;
        }

        #endregion
    }
}
