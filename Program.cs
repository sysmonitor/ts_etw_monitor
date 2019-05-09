// Inspired by
// https://blogs.msdn.microsoft.com/vancem/2013/03/09/using-traceevent-to-mine-information-in-os-registered-etw-providers/
// and modified a bit
// Truesec Detect, www.truesec.se

using Diagnostics.Tracing;
using Diagnostics.Tracing.Parsers;
using System;
using System.IO;
using System.Diagnostics;
using System.Net;
using System.Globalization;
using System.Runtime.InteropServices;
using System.Linq;

namespace ETWMonitor
{
    // The main program monitors processes (and image loads) using ETW.  
    class Program
    {
        public const int INVALID_HANDLE_VALUE = -1;

        //inner struct used only internally
        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Auto)]
        private struct PROCESSENTRY32
        {
            const int MAX_PATH = 260;
            internal UInt32 dwSize;
            internal UInt32 cntUsage;
            internal UInt32 th32ProcessID;
            internal IntPtr th32DefaultHeapID;
            internal UInt32 th32ModuleID;
            internal UInt32 cntThreads;
            internal UInt32 th32ParentProcessID;
            internal Int32 pcPriClassBase;
            internal UInt32 dwFlags;
            [MarshalAs(UnmanagedType.ByValTStr, SizeConst = MAX_PATH)]
            internal string szExeFile;
        }

        [DllImport("kernel32", SetLastError = true, CharSet = System.Runtime.InteropServices.CharSet.Auto)]
        static extern IntPtr CreateToolhelp32Snapshot([In]UInt32 dwFlags, [In]UInt32 th32ProcessID);

        [DllImport("kernel32", SetLastError = true, CharSet = System.Runtime.InteropServices.CharSet.Auto)]
        static extern bool Process32First([In]IntPtr hSnapshot, ref PROCESSENTRY32 lppe);

        [DllImport("kernel32", SetLastError = true, CharSet = System.Runtime.InteropServices.CharSet.Auto)]
        static extern bool Process32Next([In]IntPtr hSnapshot, ref PROCESSENTRY32 lppe);

        [DllImport("kernel32", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool CloseHandle([In] IntPtr hObject);

        static Process GetProcByID(int id)
        {
            try
            {
                Process[] processlist = Process.GetProcesses();
                return processlist.FirstOrDefault(pr => pr.Id == id);
            }
            catch(Exception)
            {
                return null;
            }
        }

        static Process GetProcByID2(int id)
        {
            try
            {
                return Process.GetProcessById(id);
            }
            catch(Exception)
            {
                return null;
            }
        }

        static int GetParentProcessID(int pid)
        {
            IntPtr handleToSnapshot = IntPtr.Zero;
            try
            {
                PROCESSENTRY32 procEntry = new PROCESSENTRY32();
                procEntry.dwSize = (UInt32)Marshal.SizeOf(typeof(PROCESSENTRY32));
                handleToSnapshot = CreateToolhelp32Snapshot((uint)0x02, 0);
                if ((int)handleToSnapshot == INVALID_HANDLE_VALUE)
                    return 0;

                if (Process32First(handleToSnapshot, ref procEntry))
                {
                    do
                    {
                        if (pid == procEntry.th32ProcessID)
                        {
                            CloseHandle(handleToSnapshot);
                            return (int)procEntry.th32ParentProcessID;
                        }
                    } while (Process32Next(handleToSnapshot, ref procEntry));
                }
                else
                {
                    CloseHandle(handleToSnapshot);
                    return 0; 
                }
            }
            catch (Exception)
            {
                CloseHandle(handleToSnapshot);
                return 0;
                
            }

            CloseHandle(handleToSnapshot);
            return 0;
        }

        // This is a demo of using TraceEvent to activate a 'real time' provider that is listening to 
        // the MyEventSource above.   Normally this event source would be in a differnet process,  but 
        // it also works if this process generate the evnets and I do that here for simplicity.    
        static int Main(string[] args)
        {

            bool bNetConnect = false, bNetTransfer = false, bProcess = false, bThread = false, bImageLoad = false;
            bool bDns = false, bSysmon = false, bRegistry = false, bFile = false;

            if (args.Length == 0)
            {
				Console.WriteLine("\nTruesec Detect ETWMonitor, www.truesec.se");
				Console.WriteLine("\nUsage: ETWMonitor [net_connect | net_transfer | process | thread | imageload | memory | registry | dns | sysmon]\n");
                Console.WriteLine("net_connect  : Show new TCP connections");
                Console.WriteLine("net_transfer : Show network transfers");
                Console.WriteLine("process      : Show process creations and exits");
                Console.WriteLine("thread       : Show suspicious thread creation (cross-process)");
                Console.WriteLine("imageload    : Show image loading");
                Console.WriteLine("file         : Show file activity");
                Console.WriteLine("registry     : Show registry details");
                Console.WriteLine("dns          : Show DNS requests");
                Console.WriteLine("sysmon       : Show entries from Sysmon");
                return 1;
            }

            if (args[0] == "net_connect")
            {
                Console.WriteLine("\nShowing new network connections");
                bNetConnect = true;
            }
            else if (args[0] == "net_transfer")
            {
                Console.WriteLine("\nShowing network transfers");
                bNetTransfer = true;
            }
            else if (args[0] == "process")
            {
                Console.WriteLine("\nShowing process creation and exits");
                bProcess = true;
            }
            else if (args[0] == "thread")
            {
                Console.WriteLine("\nShowing suspicious thread creations (cross-process)");
                bThread = true;
            }
            else if (args[0] == "imageload")
            {
                Console.WriteLine("\nShowing image loads");
                bImageLoad = true;
            }
            else if (args[0] == "file")
            {
                Console.WriteLine("\nShowing file system activity");
                bFile = true;
            }
            else if (args[0] == "registry")
            {
                Console.WriteLine("\nShowing registry details");
                bRegistry = true;
            }
            else if (args[0] == "dns")
            {
                Console.WriteLine("\nShowing DNS requests");
                bDns = true;
            }
            else if (args[0] == "sysmon")
            {
                Console.WriteLine("\nShowing Sysmon entries");
                bSysmon = true;
            }
            else
            {
                Console.WriteLine("\nInvalid option");
                return 1;
            }

            // Today you have to be Admin to turn on ETW events (anyone can write ETW events).   
            if (!(TraceEventSession.IsElevated() ?? false))
            {
                Console.WriteLine("To turn on ETW events you need to be Administrator, please run from an Admin process.");
                return -1;
            }

            var sessionName = "";

            if (bNetConnect)
                sessionName = "NetConnectSession";
            else if (bNetTransfer)
                sessionName = "NetTransferSession";
            else if (bProcess)
                sessionName = "ProcessSession";
            else if (bThread)
                sessionName = "ThreadSession";
            else if (bImageLoad)
                sessionName = "ImageLoadSession";
            else if (bFile)
                sessionName = "FileSession";
            else if (bRegistry)
                sessionName = "RegistrySession";
            else if (bDns)
                sessionName = "DnsSession";
            else if (bSysmon)
                sessionName = "SysmonSession";
            else
            {
                Console.WriteLine("Error");
                return -1;
            }

            using (var session = new TraceEventSession(sessionName, null))  // the null second parameter means 'real time session'
            {
                // Note that sessions create a OS object (a session) that lives beyond the lifetime of the process
                // that created it (like Filles), thus you have to be more careful about always cleaning them up. 
                // An importanty way you can do this is to set the 'StopOnDispose' property which will cause the session to 
                // stop (and thus the OS object will die) when the TraceEventSession dies.   Because we used a 'using'
                // statement, this means that any exception in the code below will clean up the OS object.   
                session.StopOnDispose = true;

                // By default, if you hit Ctrl-C your .NET objects may not be disposed, so force it to.  It is OK if dispose is called twice.
                Console.CancelKeyPress += delegate (object sender, ConsoleCancelEventArgs e) { session.Dispose(); };

                // prepare to read from the session, connect the ETWTraceEventSource to the session
                using (var source = new ETWTraceEventSource(sessionName, TraceEventSourceType.Session))
                {
                    Action<TraceEvent> action = delegate (TraceEvent data)
                    {
                        var taskName = data.TaskName;
                        var EventName = data.EventName;

                        if (bProcess)
                        {
                            if (EventName == "Process/DCStart" || EventName == "Process/Start")
                            {
                                ProcessTraceData startprocdata = (ProcessTraceData)data;

                                string exe = (string)data.PayloadByName("ImageFileName");

                                Console.Write(DateTime.Now.ToString("yyyy-MM-dd HH:mm:ss ") + EventName);
                                Console.Write(" PPID: " + startprocdata.ParentID.ToString() + " PID: " + startprocdata.ProcessID.ToString());
                                Console.Write(" Name: " + exe);

                                Process PName = GetProcByID2(startprocdata.ParentID);

                                if (PName != null)
                                    Console.Write(" ParentName: " + PName.ProcessName);

                                Console.WriteLine(" CommandLine: " + startprocdata.CommandLine);

                            }
                            else if (EventName == "Process/End")
                            {
                                ProcessTraceData exitprocdata = (ProcessTraceData)data;
                                string exe = (string)data.PayloadByName("ImageFileName");

                                Console.Write(DateTime.Now.ToString("yyyy-MM-dd HH:mm:ss ") + EventName);
                                Console.WriteLine(" PPID: " + exitprocdata.ParentID.ToString() + " PID: " + exitprocdata.ProcessID.ToString() + " " + exe);
                            }
                        }
                        else if (bNetConnect)
                        {
                            if (taskName == "TcpRequestConnect")
                            {
                                int threadID = data.ThreadID;
                                int processID = data.ProcessID;

                                byte[] local_addr = (byte[])data.PayloadByName("LocalAddress");
                                byte[] remote_addr = (byte[])data.PayloadByName("RemoteAddress");

                                if (local_addr == null || remote_addr == null)
                                    Console.WriteLine("Null addr!");

                                // First two bytes are address family: 2 for ipv4, 10 for ipv6 
                                // Next two bytes are the port

                                var family = new byte[2];

                                family[0] = local_addr[0];
                                family[1] = local_addr[1];

                                ushort family_nr = BitConverter.ToUInt16(family, 0);

                                if (family_nr == 2)
                                {
                                    var local_port = new byte[2];
                                    var remote_port = new byte[2];

                                    local_port[0] = local_addr[2];
                                    local_port[1] = local_addr[3];

                                    Array.Reverse(local_port); // Need to reverse port

                                    remote_port[0] = remote_addr[2];
                                    remote_port[1] = remote_addr[3];

                                    Array.Reverse(remote_port); // Need to reverse port

                                    ushort local_port_nr = BitConverter.ToUInt16(local_port, 0);
                                    ushort remote_port_nr = BitConverter.ToUInt16(remote_port, 0);

                                    Process proc;
                                    string processname = "<not found>";

                                    if (processID > 0)
                                    {
                                        proc = GetProcByID(processID);
                                        if (proc != null)
                                            processname = proc.MainModule.ModuleName;
                                    }

                                    Console.Write(data.TimeStamp.ToString("yyyy-MM-dd HH:mm:ss") + " " + taskName + " PID: " + processID);

                                    int parentid = GetParentProcessID(processID);

                                    if (parentid != 0)
                                        Console.Write(" PPID: " + parentid);
                                    else
                                        Console.Write(" PPID: (null)");

                                    Console.Write(" TID: " + threadID + " Name: " + processname);

                                    proc = GetProcByID(parentid);

                                    if (proc != null)
                                        Console.Write(" Parent Name: " + proc.ProcessName);
                                    else
                                        Console.Write(" Parent Name: (null)");

                                    string local_ip = local_addr[4] + "." + local_addr[5] + "." + local_addr[6] + "." + local_addr[7];
                                    string remote_ip = remote_addr[4] + "." + remote_addr[5] + "." + remote_addr[6] + "." + remote_addr[7];

                                    Console.Write(" " + local_ip + ":" + local_port_nr + "->");
                                    Console.WriteLine(remote_ip + ":" + remote_port_nr + " ");

                                }
                                else if (family_nr == 0x10)
                                    Console.WriteLine("IPV6");
                            }
                        }
                        else if (bNetTransfer)
                        {
                            if (EventName == "TcpIp/Send" || EventName == "TcpIp/Recv")
                            {

                                Console.Write(data.TimeStamp.ToString("yyyy-MM-dd HH:mm:ss") + " " + EventName + " PID: " + data.ProcessID);

                                Process processname;

                                processname = GetProcByID(data.ProcessID);

                                if (processname != null)
                                    Console.Write(" Name: " + processname.ProcessName);
                                else
                                    Console.Write(" Name: (null)");

                                IPAddress saddr = (IPAddress)data.PayloadByName("saddr");
                                IPAddress daddr = (IPAddress)data.PayloadByName("daddr");
                                int sport = (int)data.PayloadByName("sport");
                                int dport = (int)data.PayloadByName("dport");
                                int size = (int)data.PayloadByName("size");

                                Console.Write(" Src: " + saddr.ToString() + ":" + sport + " Dst: " + daddr.ToString() + ":" + dport);
                                Console.WriteLine(" Size: " + size);
                            }
                        }
                        else if (bThread) // try to catch remote thread injections only
                        {
                            if (taskName == "ThreadStart")
                            {
                                int destProcessID = (int)data.PayloadByName("ProcessID");
                                int parentid;
                                Process processname;

                                if (data.ProcessID != destProcessID && data.ProcessID != 4)
                                {
                                    // check if destpid is not a child of srcpid, otherwise we have a problem!
                                    // check the parentpid of srcpid

                                    int destThreadID = (int)data.PayloadByName("ThreadID");
                                    int srcThreadID = data.ThreadID;

                                    parentid = GetParentProcessID(destProcessID);
                                    if (parentid != 0 && parentid != data.ProcessID)
                                    {
                                        Console.Write(data.TimeStamp.ToString("yyyy-MM-dd HH:mm:ss") + " POSSIBLE THREAD INJECTION: ");
                                        Console.Write(taskName + " TID: " + destThreadID + " SrcTID: " + srcThreadID + " SrcPID: " + data.ProcessID);
                                        Console.Write(" DestPID: " + destProcessID);

                                        processname = GetProcByID(data.ProcessID);

                                        if (processname != null)
                                            Console.Write(" SrcName: " + processname.ProcessName);
                                        else
                                            Console.Write(" SrcName: (null)");

                                        processname = GetProcByID(destProcessID);

                                        if (processname != null)
                                            Console.WriteLine(" DestName: " + processname.ProcessName);
                                        else
                                            Console.WriteLine(" DestName: (null)");

                                        Console.WriteLine("\nDetailed information:\n" + data.ToString());
                                    }
                                }

                            }
                        }
                        else if (bImageLoad)
                        {
                            if (EventName == "Image/DCStart" || EventName == "Image/Load" || EventName == "Image/Unload")
                            {
                                int pid = (int)data.ProcessID;
                                Console.Write(data.TimeStamp.ToString("yyyy-MM-dd HH:mm:ss ") + EventName);
                                Console.Write(" PID: " + pid);

                                Process processname;

                                processname = GetProcByID(pid);

                                if (processname != null)
                                    Console.Write(" Name: " + processname.ProcessName);
                                else
                                    Console.Write(" Name: (null)");

                                string filename = (string)data.PayloadByName("FileName");
                                Console.WriteLine(" FileName: " + filename);

                            }
                        }
                        else if (bFile)
                        {
                            if (EventName == "CreateNewFile" || EventName == "DeletePath" || EventName == "NameDelete")
                            {
                                int pid = (int)data.ProcessID;
                                Console.Write(data.TimeStamp.ToString("yyyy-MM-dd HH:mm:ss ") + EventName);
                                Console.Write(" PID: " + pid);

                                Process processname;

                                processname = GetProcByID(pid);

                                if (processname != null)
                                    Console.Write(" Name: " + processname.ProcessName);
                                else
                                    Console.Write(" Name: (null)");

                                string filename = "";

                                if (EventName == "DeletePath")
                                    filename = (string)data.PayloadByName("FilePath");
                                else
                                    filename = (string)data.PayloadByName("FileName");

                                Console.WriteLine(" File: " + filename);
                            }

                        }
                        else if (bRegistry)
                        {
                            if (EventName == "EventID(1)/CreateKey" || EventName == "EventID(5)/SetValueKey" || EventName == "EventID(3)/DeleteKey" || EventName == "EventID(6)/DeleteValueKey")
                            {
                                int pid = (int)data.ProcessID;
                                Console.Write(data.TimeStamp.ToString("yyyy-MM-dd HH:mm:ss ") + EventName);
                                Console.Write(" PID: " + pid);

                                Process processname;

                                processname = GetProcByID(pid);

                                if (processname != null)
                                    Console.Write(" Name: " + processname.ProcessName);
                                else
                                    Console.Write(" Name: (null)");

                                if (EventName == "EventID(1)/CreateKey")
                                {
                                    string RelativeName = (string)data.PayloadByName("RelativeName");
                                    int status = (int)data.PayloadByName("Status");
                                    Console.WriteLine(" Status: " + status + " RelativeName: " + RelativeName);
                                }
                                else if (EventName == "EventID(3)/DeleteKey")
                                {
                                    int status = (int)data.PayloadByName("Status");
                                    Console.WriteLine(" Status: " + status);
                                }
                                else if (EventName == "EventID(5)/SetValueKey")
                                {
                                    string ValueName = (string)data.PayloadByName("ValueName");
                                    int status = (int)data.PayloadByName("Status");
                                    Console.WriteLine(" Status: " + status + " ValueName: " + ValueName);
                                }
                                else if (EventName == "EventID(6)/DeleteValueKey")
                                {
                                    string ValueName = (string)data.PayloadByName("ValueName");
                                    int status = (int)data.PayloadByName("Status");
                                    Console.WriteLine(" Status: " + status + " ValueName: " + ValueName);
                                }
                            }
                        }
                        else if (bDns)
                        {
                            int pid = (int)data.ProcessID;
                            Console.Write(data.TimeStamp.ToString("yyyy-MM-dd HH:mm:ss ") + EventName);
                            Console.Write(" PID: " + pid);

                            Process processname;

                            processname = GetProcByID(pid);

                            if (processname != null)
                                Console.Write(" Name: " + processname.ProcessName);
                            else
                                Console.Write(" Name: (null)");

                            string QueryName = (string)data.PayloadByName("QueryName");
                            Console.WriteLine(" QueryName: " + QueryName);
                        }
                        else if (bSysmon)
                        {
                            Console.WriteLine(data.ToString());
                        }
                    };

                    // You can also simply use 'logman query providers' to find out the GUID yourself and wire it in. 

                    Guid processProviderGuid;

                    if (bProcess)
                        session.EnableKernelProvider(KernelTraceEventParser.Keywords.Process);
                    else if (bNetConnect)
                    {
                        processProviderGuid = TraceEventSession.GetProviderByName("Microsoft-Windows-TCPIP");
                        session.EnableProvider(processProviderGuid, TraceEventLevel.Informational, 0x80);  // ut:TcpipDiagnosis seems to do the job
                    }
                    else if (bNetTransfer)
                    {
                        session.EnableKernelProvider(KernelTraceEventParser.Keywords.NetworkTCPIP);
                    }
                    else if (bThread)
                    {
                        processProviderGuid = TraceEventSession.GetProviderByName("Microsoft-Windows-Kernel-Process");
                        session.EnableProvider(processProviderGuid, TraceEventLevel.Informational, 0x20);  // WINEVENT_KEYWORD_THREAD
                    }
                    else if(bImageLoad)
                    {
                        session.EnableKernelProvider(KernelTraceEventParser.Keywords.ImageLoad);
                    }
                    else if(bFile)
                    {
                        processProviderGuid = TraceEventSession.GetProviderByName("Microsoft-Windows-Kernel-File");
                        session.EnableProvider(processProviderGuid, TraceEventLevel.Informational, 0x0000000000001410); // KERNEL_FILE_KEYWORD_CREATE_NEW_FILE, KERNEL_FILE_KEYWORD_DELETE_PATH, KERNEL_FILE_KEYWORD_FILENAME
                    }
                    else if(bRegistry)
                    {
                        processProviderGuid = TraceEventSession.GetProviderByName("Microsoft-Windows-Kernel-Registry");
                        session.EnableProvider(processProviderGuid, TraceEventLevel.Informational, 0x0000000000005300); // SetValueKey, CreateKey, DeleteKey, DeleteValueKey
                    }
                    else if(bDns)
                    {
                        processProviderGuid = TraceEventSession.GetProviderByName("Microsoft-Windows-DNS-Client");
                        session.EnableProvider(processProviderGuid, TraceEventLevel.Informational, 0x8000000000000000);  //
                    }
                    else if(bSysmon)
                    {
                        processProviderGuid = TraceEventSession.GetProviderByName("Microsoft-Windows-Sysmon");
                        session.EnableProvider(processProviderGuid, TraceEventLevel.Informational, 0x8000000000000000);  // KERNEL_MEM_KEYWORD_MEMINFO
                    }
                    else
                    {
                        Console.WriteLine("Error");
                        return -1;
                    }

                    // We use different parsers depending on the events. For TCP/IP stuff we need to 
                    // use another since we want to register not only ProcessID but also ThreadID for each event
                    if (bNetConnect || bThread || bFile || bRegistry || bDns || bSysmon)
                    {
                        // Hook up the parser that knows about Any EventSources regsitered with windows.  (e.g. the OS ones). 
                        var registeredParser = new RegisteredTraceEventParser(source);
                        registeredParser.All += action;
                    }
                    else
                    {
                        // Hook up the parser that knows about kernel traces 
                        var KernelParser = new KernelTraceEventParser(source);
                        KernelParser.All += action;
                    }

                    Console.WriteLine("Starting Listening for events");
                    // go into a loop processing events can calling the callbacks.  Because this is live data (not from a file)
                    // processing never completes by itself, but only because someone called 'source.Close()'.  
                    source.Process();
                    Console.WriteLine();
                    Console.WriteLine("Stopping Listening for events");
                }
            }
            return 0;
        }
    }
}

