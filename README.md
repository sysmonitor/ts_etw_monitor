**Windows Event Tracing Monitor**

See Windows Event Traces in realtime sessions.
Requires files TraceEvent.dll and TraceEvent.xml (included in repo)
Requires .Net 4
  
Truesec Detect ETWMonitor, www.truesec.se  

Usage: ETWMonitor [net_connect | net_transfer | process | thread | imageload | memory | registry | dns | sysmon]  

    net_connect  : Show new TCP connections
    net_transfer : Show network transfers
    process      : Show process creations and exits
    thread       : Show suspicious thread creation (cross-process)
    imageload    : Show image loading
    file         : Show file activity
    registry     : Show registry details
    dns          : Show DNS requests
    sysmon       : Show entries from Sysmon
