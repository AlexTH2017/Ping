unit IcmpUtils;
////////////////////////////////////////////////////////////////////////////////
//
//   Unit        :  IcmpUtils
//   Author      :  rllibby
//   Date        :  07.18.2006  -  Original
//                  06.19.2008  -  Update to allow for async pinging as well
//                  reverse DNS name lookup, address -> string conversion.
//   Description :  Set of ICMP utility routines based off the iphlpapi library
//                  in Windows. Exposes the following:
//
//                  -  Ability to get inbound / outbound ICMP statistics
//                  -  Ping
//                  -  TraceRoute
//
////////////////////////////////////////////////////////////////////////////////
interface

////////////////////////////////////////////////////////////////////////////////
//   Include units
////////////////////////////////////////////////////////////////////////////////
uses
  Windows, SysUtils, Classes, WinSock;

///////////////////////////////////////////////////////////////////////////////
//   ICMP library constants
////////////////////////////////////////////////////////////////////////////////
const
  IPHLPAPI_LIBRARY        =  'iphlpapi.dll';

  /////////////////////////////////////////////////
  // This can optionally be set to use the icmp.dll
  /////////////////////////////////////////////////
  ICMP_LIBRARY            =  IPHLPAPI_LIBRARY;

////////////////////////////////////////////////////////////////////////////////
//   ICMP error constants
////////////////////////////////////////////////////////////////////////////////
const
  IP_SUCCESS              =  ERROR_SUCCESS;
  IP_STATUS_BASE          =  11000;
  IP_BUF_TOO_SMALL        =  (IP_STATUS_BASE + 1);
  IP_DEST_NET_UNREACHABLE =  (IP_STATUS_BASE + 2);
  IP_DEST_HOST_UNREACHABLE=  (IP_STATUS_BASE + 3);
  IP_DEST_PROT_UNREACHABLE=  (IP_STATUS_BASE + 4);
  IP_DEST_PORT_UNREACHABLE=  (IP_STATUS_BASE + 5);
  IP_NO_RESOURCES         =  (IP_STATUS_BASE + 6);
  IP_BAD_OPTION           =  (IP_STATUS_BASE + 7);
  IP_HW_ERROR             =  (IP_STATUS_BASE + 8);
  IP_PACKET_TOO_BIG       =  (IP_STATUS_BASE + 9);
  IP_REQ_TIMED_OUT        =  (IP_STATUS_BASE + 10);
  IP_BAD_REQ              =  (IP_STATUS_BASE + 11);
  IP_BAD_ROUTE            =  (IP_STATUS_BASE + 12);
  IP_TTL_EXPIRED_TRANSIT  =  (IP_STATUS_BASE + 13);
  IP_TTL_EXPIRED_REASSEM  =  (IP_STATUS_BASE + 14);
  IP_PARAM_PROBLEM        =  (IP_STATUS_BASE + 15);
  IP_SOURCE_QUENCH        =  (IP_STATUS_BASE + 16);
  IP_OPTION_TOO_BIG       =  (IP_STATUS_BASE + 17);
  IP_BAD_DESTINATION      =  (IP_STATUS_BASE + 18);

////////////////////////////////////////////////////////////////////////////////
//   ICMP option types
////////////////////////////////////////////////////////////////////////////////
const
  IP_OPT_EOL              =  $00;  // End of list option
  IP_OPT_NOP              =  $01;  // No operation
  IP_OPT_SECURITY         =  $82;  // Security option.
  IP_OPT_LSRR             =  $83;  // Loose source route.
  IP_OPT_SSRR             =  $89;  // Strict source route.
  IP_OPT_RR               =  $07;  // Record route.
  IP_OPT_TS               =  $44;  // Timestamp.
  IP_OPT_SID              =  $88;  // Stream ID (obsolete)

const
  MAX_OPT_SIZE            =  40;

////////////////////////////////////////////////////////////////////////////////
//   ICMP structures
////////////////////////////////////////////////////////////////////////////////
type
  ICMP_OPTION_INFORMATION =  packed record
     Ttl:                 u_char;
     Tos:                 u_char;
     Flags:               u_char;
     OptionsSize:         u_char;
     OptionsData:         Pointer;
  end;
  PICMP_OPTION_INFORMATION=  ^ICMP_OPTION_INFORMATION;
  TICMPOptionInformation  =  ICMP_OPTION_INFORMATION;
  PICMPOptionInformation  =  ^TICMPOptionInformation;

type
  ICMP_ECHO_REPLY         =  packed record
     Address:             u_long;
     Status:              u_long;
     RTTime:              u_long;
     DataSize:            u_short;
     Reserved:            u_short;
     Data:                Pointer;
     Options:             TICMPOptionInformation;
  end;
  PICMPP_ECHO_REPLY       =  ^ICMP_ECHO_REPLY;
  TICMPEchoReply          =  ICMP_ECHO_REPLY;
  PICMPEchoReply          =  ^TICMPEchoReply;

////////////////////////////////////////////////////////////////////////////////
//   ICMP statistics structures
////////////////////////////////////////////////////////////////////////////////
type
  MIBICMPSTATS            =  packed record
     dwMsgs:              DWORD;   // number of messages
     dwErrors:            DWORD;   // number of errors
     dwDestUnreachs:      DWORD;   // destination unreachable messages
     dwTimeExcds:         DWORD;   // time-to-live exceeded messages
     dwParmProbs:         DWORD;   // parameter problem messages
     dwSrcQuenchs:        DWORD;   // source quench messages
     dwRedirects:         DWORD;   // redirection messages
     dwEchos:             DWORD;   // echo requests
     dwEchoReps:          DWORD;   // echo replies
     dwTimestamps:        DWORD;   // time-stamp requests
     dwTimestampReps:     DWORD;   // time-stamp replies
     dwAddrMasks:         DWORD;   // address mask requests
     dwAddrMaskReps:      DWORD;   // address mask replies
  end;
  LPMIBICMPSTATS          =  ^MIBICMPSTATS;
  TMIBIcmpStats           =  MIBICMPSTATS;
  PMIBIcmpStats           =  ^TMIBIcmpStats;

  MIBICMPINFO             =  packed record
     icmpInStats:         MIBICMPSTATS;
     icmpOutStats:        MIBICMPSTATS;
  end;
  LPMIBICMPINFO           =  ^MIBICMPINFO;
  TMIBIcmpInfo            =  MIBICMPINFO;
  PMIBIcmpInfo            =  ^TMIBIcmpInfo;

  MIB_ICMP                =  packed record
     stats:               MIBICMPINFO;
  end;
  LPMIB_ICMP              =  ^MIB_ICMP;
  TMIBIcmp                =  MIB_ICMP;
  PMIBIcmp                =  ^TMIBIcmp;

////////////////////////////////////////////////////////////////////////////////
//   Threaded ping structure
////////////////////////////////////////////////////////////////////////////////
type
  PPingRequest            =  ^TPingRequest;
  TPingRequest            =  packed record
     hwndNotify:          HWND;
     msgID:               UINT;
     dwAddr:              DWORD;
     dwTimeout:           DWORD;
  end;

////////////////////////////////////////////////////////////////////////////////
//   Ping constants
////////////////////////////////////////////////////////////////////////////////
const
  PING_DEF_TIMEOUT        =  5000;

////////////////////////////////////////////////////////////////////////////////
//   ICMP imported functions
////////////////////////////////////////////////////////////////////////////////
function   IcmpCreateFile: THandle; stdcall; external ICMP_LIBRARY;
function   IcmpCloseHandle(icmpHandle: THandle): BOOL; stdcall; external ICMP_LIBRARY;
function   IcmpSendEcho(icmpHandle: THandle; DestinationAddress: TInAddr; RequestData: Pointer; RequestSize: Word; RequestOptions: Pointer; ReplyBuffer: Pointer; ReplySize, Timeout: DWORD): DWORD; stdcall; external ICMP_LIBRARY;
function   GetIcmpStatistics(pStats: LPMIB_ICMP): DWORD; stdcall; external IPHLPAPI_LIBRARY;

////////////////////////////////////////////////////////////////////////////////
//
//   AddressToStr
//
//      Address  =  [in] The binary address of the host system to return the
//               dotted name for.
//
//      Returns
//
//         Returns the ip address in the dotted name format of x.x.x.x on success,
//         an empty string on failure
//
////////////////////////////////////////////////////////////////////////////////
function   AddressToString(Address: DWORD): String;

////////////////////////////////////////////////////////////////////////////////
//
//   GetLocalIPAddress
//
//      Returns
//
//         Returns the local ip address string in the form of x.x.x.x if
//         successful, an empty string on failure.
//
////////////////////////////////////////////////////////////////////////////////
function   GetLocalIPAddress: String;

////////////////////////////////////////////////////////////////////////////////
//
//   GetTraceRoute
//
//      HostName =  [in] The name of the host system to trace a route to. The
//                  name can be in either DNS format, or dotted name notation.
//
//      List     =  [in] A TStrings or descendant class to fill in with the
//                  result of the trace route to the specified host name. The
//                  string values in the list will contain the IP address in
//                  x.x.x.x notation, and the Objects[x] property for each list
//                  item will be the integer value for round trip time.
//
//      Returns
//
//         If the trace completes, an ERROR_SUCCESS will be returned. Otherwise,
//         the error code causing the failure will be returned.
//
////////////////////////////////////////////////////////////////////////////////
function   GetTraceRoute(HostName: String; List: TStrings): Integer;

////////////////////////////////////////////////////////////////////////////////
//
//   Ping
//
//      HostName =  [in] The name of the host system to get the network address
//                  for. The name can be in either DNS format, or dotted name
//                  notation.
//
//      TimeOut  =  [in/out] On input, determines how long to wait (in ms) for
//                  an echo reply from the host system. If zero is passed, the
//                  default timeout of PING_DEF_TIMEOUT is used. On return, this
//                  will be filled in with the roundtrip time (in ms) to the host.
//
//      Returns
//
//         Returns ERROR_SUCCESS if the host replied to the echo command, else
//         the error code indicating the failure.
//
////////////////////////////////////////////////////////////////////////////////
function   Ping(HostName: String; var Timeout: DWORD): Integer;

////////////////////////////////////////////////////////////////////////////////
//
//   PingAync
//
//      Notify   =  [in] The handle of the window that will be notified when the
//                  ping is complete.
//
//      MsgID    =  [in] The user defined message ID that the ping results will
//                  be messaged back on.
//
//      HostName =  [in] The name of the host system to get the network address
//                  for. The name can be in either DNS format, or dotted name
//                  notation.
//
//      TimeOut  =  [in] Determines how long to wait (in ms) for an echo reply
//                  from the host system. If zero is passed, the default timeout
//                  of PING_DEF_TIMEOUT is used.
//
//      Returns
//
//         Returns ERROR_SUCCESS if the ping request is created (thread). When
//         the ping request comlpetes, a message of MsgID will be sent back to the
//         window specified by Notify. The WParam will be the address that was
//         pinged (name can be reversed using ResolveName) and the LParam will be
//         the results of the ping request.
//
//
////////////////////////////////////////////////////////////////////////////////
function   PingAsync(Notify: HWND; MsgID: UINT; HostName: String; Timeout: DWORD): Integer;

////////////////////////////////////////////////////////////////////////////////
//
//   ResolveAddress
//
//      HostName =  [in] The name of the host system to get the network address
//                  for. The name can be in either DNS format, or dotted name
//                  notation.
//
//      Address  =  [out] The binary address of the host system on success.
//
//      Returns
//
//         Returns ERROR_SUCCESS if the host name was converted to a binary ip
//         address, else the error code indicating the failure. On success, the
//         Address param will be filled in with the binary ip address.
//
////////////////////////////////////////////////////////////////////////////////
function   ResolveAddress(HostName: String; out Address: DWORD): Integer;

////////////////////////////////////////////////////////////////////////////////
//
//   ResolveName
//
//      Address  =  [in] The binary address of the host system to get the name
//                  for.
//
//      Returns
//
//         Returns the (reverse) DNS if the address was looked up and a hostent
//         structure returned, otherwise the dotted name format x.x.x.x for the
//         address is returned.
//
////////////////////////////////////////////////////////////////////////////////
function   ResolveName(Address: PDWORD): String;

////////////////////////////////////////////////////////////////////////////////
//
//   TraceRoute
//
//      HostName =  [in] The name of the host system to trace a route to. The
//                  name can be in either DNS format, or dotted name notation.
//
//      CallBack =  [in] The function to callback when an address hop is
//                  resolved. This is not a required param, but if passed in,
//                  returning a False result from the callback will cause the
//                  trace to complete with a result of ERROR_CANCELLED.
//
//      lParam   =  [in] Specifies a 32-bit, application-defined value to be
//                  passed to the callback function.
//
//      Returns
//
//         If the trace completes, an ERROR_SUCCESS will be returned. Otherwise,
//         the error code causing the failure will be returned.
//
////////////////////////////////////////////////////////////////////////////////
type
  TTraceCallback    =  function(HopNumber: Byte; Address: PChar; RoundTripTime: Cardinal; lParam: Integer): Boolean;

function   TraceRoute(HostName: String; CallBack: TTraceCallback; lParam: Integer): Integer;

implementation

////////////////////////////////////////////////////////////////////////////////
//   Protected variables
////////////////////////////////////////////////////////////////////////////////
var
  lpData:           TWSAData;

function PingThreadFunc(PingRequest: PPingRequest): DWORD; stdcall;
var  lpSend:        Array [0..7] of Integer;
     lpReply:       PICMPEchoReply;
     icmpHandle:    THandle;
     dwTTL:         DWORD;
begin

  // Set default result
  result:=ERROR_SUCCESS;

  // Resource protection
  try
     // Resource protection
     try
        // Resource protection
        try
           // Open an icmp handle
           icmpHandle:=IcmpCreateFile;
           // Check handle
           if not(icmpHandle = INVALID_HANDLE_VALUE) then
           begin
              // Resource protection
              try
                 // Allocate memory for reply
                 lpReply:=AllocMem(SizeOf(ICMP_ECHO_REPLY) * 2 + SizeOf(lpSend));
                 // Resource protection
                 try
                    // Get timeout value
                    if (PingRequest^.dwTimeout = 0) then
                       // Use default
                       dwTTL:=PING_DEF_TIMEOUT
                    else
                       // Use passed value
                       dwTTL:=PingRequest^.dwTimeout;
                    // Send echo to the host
                    if (IcmpSendEcho(icmpHandle, in_addr(PingRequest^.dwAddr), @lpSend, SizeOf(lpSend), nil, lpReply, SizeOf(ICMP_ECHO_REPLY) + SizeOf(lpSend), dwTTL) = 1) then
                       // Return the status
                       result:=lpReply^.Status
                    else
                       // Request timed out
                       result:=IP_REQ_TIMED_OUT;
                 finally
                    // Free memory
                    FreeMem(lpReply);
                 end;
              finally
                 // Close handle
                 IcmpCloseHandle(icmpHandle);
              end;
           end
           else
              // Failed to open icmp handle, return last error
              result:=GetLastError;
        finally
           // Check notification window
           if IsWindow(PingRequest^.hwndNotify) then
           begin
              // Notify window of completed request
              PostMessage(PingRequest^.hwndNotify, PingRequest^.msgID, PingRequest^.dwAddr, result);
           end;
        end;
     finally
        // Free the passed memory
        FreeMem(PingRequest);
     end;
  finally
     // Exit the thread
     ExitThread(result);
  end;

end;

function PingAsync(Notify: HWND; MsgID: UINT; HostName: String; Timeout: DWORD): Integer;
var  lpRequest:     PPingRequest;
     dwAddress:     DWORD;
     dwThread:      DWORD;
begin

  // Set multi threaded state
  IsMultiThread:=True;

  // Convert the address
  result:=ResolveAddress(HostName, dwAddress);

  // Check result
  if (result = ERROR_SUCCESS) then
  begin
     // Create structure for the thread request
     lpRequest:=AllocMem(SizeOf(TPingRequest));
     // Fill in the request fields
     lpRequest^.hwndNotify:=Notify;
     lpRequest^.msgID:=MsgID;
     lpRequest^.dwAddr:=dwAddress;
     lpRequest^.dwTimeout:=Timeout;
     // Create the ping request thread
     if (CreateThread(nil, 0, @PingThreadFunc, lpRequest, 0, dwThread) = 0) then
     begin
        // Failed to create listening thread
        result:=GetLastError;
        // Free memory block
        FreeMem(lpRequest);
     end
     else
        // Success
        result:=ERROR_SUCCESS;
  end;

end;

function AddressToString(Address: DWORD): String;
var  lpszAddr:      PAnsiChar;
begin

  // Get the ip address in the dotted name format
  lpszAddr:=inet_ntoa(in_addr(Address));

  // Check result
  if Assigned(lpszAddr) then
     // Return string
     SetString(result, lpszAddr, StrLen(lpszAddr))
  else
     // Return empty string
     SetLength(result, 0);

end;

function ResolveName(Address: PDWORD): String;
var  lpHost:        PHostEnt;
begin

  // Get host by address
  lpHost:=gethostbyaddr(Address, SizeOf(DWORD), AF_INET);

  // Check host ent
  if Assigned(lpHost) and Assigned(lpHost^.h_name) then
     // Return the host name
     SetString(result, lpHost^.h_name, StrLen(lpHost^.h_name))
  else
     // Convert address to dotted format
     result:=AddressToString(Address^)

end;

function ResolveAddress(HostName: String; out Address: DWORD): Integer;
var  lpHost:        PHostEnt;
begin

  // Set default address
  Address:=DWORD(INADDR_NONE);

  // Resource protection
  try
     // Check host name length
     if (Length(HostName) > 0) then
     begin
        // Try converting the hostname
        Address:=( inet_addr( PAnsiChar( HostName ) ) );
        // Check address
        if (DWORD(Address) = DWORD(INADDR_NONE)) then
        begin
           // Attempt to get host by name
           lpHost:=gethostbyname(PAnsiChar(HostName));
           // Check host ent structure for valid ip address
           if Assigned(lpHost) and Assigned(lpHost^.h_addr_list^) then
           begin
              // Get the address from the list
              Address:=u_long(PLongInt(lpHost^.h_addr_list^)^);
           end;
        end;
     end;
  finally
     // Check result address
     if (DWORD(Address) = DWORD(INADDR_NONE)) then
        // Invalid host specified
        result:=IP_BAD_DESTINATION
     else
        // Converted correctly
        result:=ERROR_SUCCESS;
  end;

end;

function GetTraceRouteCallback(HopNumber: Byte; Address: PChar; RoundTripTime: Cardinal; lParam: Integer): Boolean;
begin

  // Resource protection
  try
     // Add address and round trip time to list
     TStrings(lParam).AddObject(Address, Pointer(RoundTripTime));
  finally
     // Keep enumerating
     result:=True;
  end;

end;

function GetTraceRoute(HostName: String; List: TStrings): Integer;
begin

  // Check the passed list
  if Assigned(List) then
  begin
     // Lock the list
     List.BeginUpdate;
     // Resource protection
     try
        // Clear the list
        List.Clear;
        // Perform the trace route
        result:=TraceRoute(HostName, GetTraceRouteCallback, Integer(List));
     finally
        // Unlock the list
        List.EndUpdate;
     end;
  end
  else
     // List must be passed
     result:=ERROR_INVALID_PARAMETER;

end;

function Ping(HostName: String; var Timeout: Cardinal): Integer;
var  lpSend:        Array [0..7] of Integer;
     lpReply:       PICMPEchoReply;
     icmpHandle:    THandle;
     dwAddress:     DWORD;
     dwTTL:         DWORD;
begin

  // Convert the address
  result:=ResolveAddress(HostName, dwAddress);

  // Check result
  if (result = ERROR_SUCCESS) then
  begin
     // Open an icmp handle
     icmpHandle:=IcmpCreateFile;
     // Check handle
     if not(icmpHandle = INVALID_HANDLE_VALUE) then
     begin
        // Resource protection
        try
           // Allocate memory for reply
           lpReply:=AllocMem(SizeOf(ICMP_ECHO_REPLY) * 2 + SizeOf(lpSend));
           // Resource protection
           try
              // Get timeout value
              if (Timeout = 0) then
                 // Use default
                 dwTTL:=PING_DEF_TIMEOUT
              else
                 // Use passed value
                 dwTTL:=Timeout;
              // Send echo to the host
              if (IcmpSendEcho(icmpHandle, in_addr(dwAddress), @lpSend, SizeOf(lpSend), nil, lpReply, SizeOf(ICMP_ECHO_REPLY) + SizeOf(lpSend), dwTTL) = 1) then
              begin
                 // Fill in the round trip time
                 Timeout:=lpReply^.RTTime;
                 // Return the status
                 result:=lpReply^.Status;
              end
              else
                 // Request timed out
                 result:=IP_REQ_TIMED_OUT;
           finally
              // Free memory
              FreeMem(lpReply);
           end;
        finally
           // Close handle
           IcmpCloseHandle(icmpHandle);
        end;
     end
     else
        // Failed to open icmp handle, return last error
        result:=GetLastError;
  end;

end;

function TraceRoute(HostName: String; CallBack: TTraceCallback; lParam: Integer): Integer;
var  lpSend:        Array [0..7] of Integer;
     lpAddr:        Array [0..255] of Char;
     lpOpts:        TICMPOptionInformation;
     lpReply:       PICMPEchoReply;
     icmpHandle:    THandle;
     dwAddress:     DWORD;
     dwAttempt:     Integer;
     dwTTL:         Integer;
begin

  // Convert the address
  result:=ResolveAddress(HostName, dwAddress);

  // Check result
  if (result = ERROR_SUCCESS) then
  begin
     // Open an icmp handle
     icmpHandle:=IcmpCreateFile;
     // Check handle
     if not(icmpHandle = INVALID_HANDLE_VALUE) then
     begin
        // Resource protection
        try
           // Clear option structure
           FillChar(lpOpts, SizeOf(lpOpts), 0);
           // Allocate memory for reply
           lpReply:=AllocMem(SizeOf(ICMP_ECHO_REPLY) * 2 + SizeOf(lpSend));
           // Resource protection
           try
              // Set starting TTL count
              dwTTL:=1;
              // Perform the trace route
              while (dwTTL < 256) do
              begin
                 // Set option time to live
                 lpOpts.Ttl:=AnsiChar(dwTTL);
                 // Set starting attempt
                 dwAttempt:=0;
                 // Retry up to 3 times
                 while (dwAttempt < 3) do
                 begin
                    // Send 32 bytes of data, break on success
                    if (IcmpSendEcho(icmpHandle, in_addr(dwAddress), @lpSend, SizeOf(lpSend), @lpOpts, lpReply, SizeOf(ICMP_ECHO_REPLY) + SizeOf(lpSend), 1000) = 1) then break;
                    // Increment the attempt
                    Inc(dwAttempt);
                 end;
                 // Check attempt counter
                 if (dwAttempt = 3) then
                 begin
                    // Set result
                    result:=IP_REQ_TIMED_OUT;
                    // Done
                    break;
                 end;
                 // Check callback
                 if Assigned(Callback) then
                 begin
                    // Copy address
                    StrLCopy(@lpAddr, inet_ntoa(in_addr(lpReply^.Address)), Pred(SizeOf(lpAddr)));
                    // If false is returned then we need to stop the trace route
                    if not(Callback(Ord(dwTTL), lpAddr, lpReply^.RTTime, lParam)) then
                    begin
                       // Set result
                       result:=ERROR_CANCELLED;
                       // Done
                       break;
                    end;
                 end;
                 // Check reply status, if IP_SUCCESS then we have reached the desired host
                 if (lpReply^.Status = IP_SUCCESS) then break;
                 // Increment the time to live
                 Inc(dwTTL);
              end;
           finally
              // Free memory
              FreeMem(lpReply);
           end;
        finally
           // Close handle
           IcmpCloseHandle(icmpHandle);
        end;
     end
     else
        // Failed to open icmp handle, return last error
        result:=GetLastError;
  end;

end;

function GetLocalIPAddress: String;
var  lpszName:      Array [0..MAX_PATH] of Char;
     lpHost:        PHostEnt;
begin

  // Get host name
  if (gethostname(@lpszName, SizeOf(lpszName)) = 0) then
  begin
     // Get host ent structure from remote name
     lpHost:=gethostbyname(@lpszName);
     // Check host ent structure for valid ip address
     if Assigned(lpHost) and Assigned(lpHost^.h_addr_list^) then
        // Convert to dot notation string
        result:=inet_ntoa(in_addr(PLongInt(lpHost^.h_addr_list^)^))
     else
        // Failed to resolve name
        SetLength(result, 0);
  end
  else
     // Failed to get name
     SetLength(result, 0);

end;

initialization

  // Initialize winsock
  WSAStartup(MakeWord(1, 1), lpData);

finalization

  // Cleanup winsock
  WSACleanup;

end.

