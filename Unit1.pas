unit Unit1;

interface

uses
  Winapi.Windows, Winapi.Messages, System.SysUtils, System.Variants,
  System.Classes, Vcl.Graphics, Vcl.Controls, Vcl.Forms, Vcl.Dialogs,
  IdBaseComponent, IdComponent, IdRawBase, IdRawClient, IdIcmpClient,
  Vcl.ExtCtrls, Vcl.StdCtrls, Vcl.Mask, Vcl.Buttons, IcmpUtils, ActiveX, ComObj;
const
  WM_PINGDONE       =  WM_USER + 10;
type
  TForm1 = class(TForm)
    Timer1: TTimer;
    Button1: TButton;
    Memo1: TMemo;
    ComboBox1: TComboBox;
    procedure Button1Click(Sender: TObject);
    procedure FormCreate(Sender: TObject);
    procedure FormCloseQuery(Sender: TObject; var CanClose: Boolean);
  private
   Num             : Integer;
   PacketsReceived : Integer;
   ReceiveTimeMinimum         : Integer;
   ReceiveTimeMaximum         : Integer;
   ReceiveTimeAverage         : Integer;
   FCount          : Integer;
   Mask_DateAndTime,
   User,
   Pass,
   Power,
   RL,
   FL,
   IP               : string;
   FlgStart:Boolean;
    { Private declarations }
  public

    { Public declarations }
  end;
 TMyThread = class(TThread)
  private
  Address:^string;
  BufferSize:^Word;
  public
   constructor Create(var VAddress : string; var VBufferSize: Word);
   destructor Destroy; override;
  protected
   procedure Execute; override;
 end;

var
  Form1: TForm1;
     MSG: string;
implementation
{$R *.dfm}
function GetStatusCodeStr(statusCode:integer) : string;
begin
  case statusCode of
    0     : Result:='Success';
    11001 : Result:='Buffer Too Small';
    11002 : Result:='Destination Net Unreachable';
    11003 : Result:='Destination Host Unreachable';
    11004 : Result:='Destination Protocol Unreachable';
    11005 : Result:='Destination Port Unreachable';
    11006 : Result:='No Resources';
    11007 : Result:='Bad Option';
    11008 : Result:='Hardware Error';
    11009 : Result:='Packet Too Big';
    11010 : Result:='Request Timed Out';
    11011 : Result:='Bad Request';
    11012 : Result:='Bad Route';
    11013 : Result:='TTL expired in transit.';//TimeToLive Expired Transit
    11014 : Result:='TimeToLive Expired Reassembly';
    11015 : Result:='Parameter Problem';
    11016 : Result:='Source Quench';
    11017 : Result:='Option Too Big';
    11018 : Result:='Bad Destination';
    11032 : Result:='Negotiating IPSEC';
    11050 : Result:='General Failure'
    else
    result:='Unknow';
  end;
end;
//********************************************
//The form of the Address parameter can be either the computer name (wxyz1234),
//IPv4 address (192.168.177.124), or IPv6 address (2010:836B:4179::836B:4179).


constructor TMyThread.Create(var VAddress : string; var VBufferSize: Word);
begin
 inherited Create(True);
 FreeOnTerminate := True;
 Address := @VAddress;
 BufferSize:=@VBufferSize;
end;

destructor TMyThread.Destroy;
begin
 Address^ := Form1.ComboBox1.Text;

 inherited Destroy;
end;

procedure TMyThread.Execute;
begin

end;

//The form of the Address parameter can be either the computer name (wxyz1234), IPv4 address (192.168.177.124), or IPv6 address (2010:836B:4179::836B:4179).
function Ping(const Address:string;BufferSize:Word):Boolean;
var
  FSWbemLocator : OLEVariant;
  FWMIService   : OLEVariant;
  FWbemObjectSet: OLEVariant;
  FWbemObject   : OLEVariant;
  oEnum         : IEnumvariant;
  iValue        : LongWord;
  i             : Integer;
  IsPing: Boolean;
begin;
 IsPing:=False;
 // Writeln(Format('Pinging %s with %d bytes of data:',[Address,BufferSize]));
  FSWbemLocator := CreateOleObject('WbemScripting.SWbemLocator');
  FWMIService   := FSWbemLocator.ConnectServer('localhost', 'root\CIMV2', '', '');
  //FWMIService   := FSWbemLocator.ConnectServer('192.168.52.130', 'root\CIMV2', 'user', 'password');
  FWbemObjectSet:= FWMIService.ExecQuery(Format('SELECT * FROM Win32_PingStatus where Address=%s AND BufferSize=%d',[QuotedStr(Address),BufferSize]),'WQL',0);
  oEnum         := IUnknown(FWbemObjectSet._NewEnum) as IEnumVariant;
  if oEnum.Next(1, FWbemObject, iValue) = 0 then
   begin
    if FWbemObject.StatusCode=0 then
      begin
       IsPing:=True;
        if FWbemObject.ResponseTime>0 then
          MSG:=(Format('Reply from %s: bytes=%s time=%sms TTL=%s',[FWbemObject.ProtocolAddress,FWbemObject.ReplySize,FWbemObject.ResponseTime,FWbemObject.TimeToLive]))
        else
          MSG:=(Format('Reply from %s: bytes=%s time=<1ms TTL=%s',[FWbemObject.ProtocolAddress,FWbemObject.ReplySize,FWbemObject.TimeToLive]));
      end
    else
     if not VarIsNull(FWbemObject.StatusCode) then
      MSG:=(Format('Reply from %s: %s',[FWbemObject.ProtocolAddress,GetStatusCodeStr(FWbemObject.StatusCode)]))
     else
      MSG:=(Format('Reply from %s: %s',[Address,'Error processing request']));
   end;
  FWbemObject:=Unassigned;
  FWbemObjectSet:=Unassigned;
   //Sleep(500);
   Result:=IsPing;
end;

{ Writeln(Format('Ping statistics for %s:',[Address]));
  Writeln(Format('    Packets: Sent = %d, Received = %d, Lost = %d (%d%% loss),',[Retries,PacketsReceived,Retries-PacketsReceived,Round((Retries-PacketsReceived)*100/Retries)]));
  if PacketsReceived>0 then
  begin
   Writeln('Approximate round trip times in milli-seconds:');
   Writeln(Format('    Minimum = %dms, Maximum = %dms, Average = %dms',[Minimum,Maximum,Round(Average/PacketsReceived)]));
  end;
end;}
 //***********************
procedure TForm1.Button1Click(Sender: TObject);
var
 i: Integer;
 IsPing: Boolean;
begin
 if Button1.Caption = 'Ping' then
  begin
   FlgStart:=True;
   Button1.Caption := 'Stop';
  end
 else
  begin
   FlgStart:=False;                                                     -
   Button1.Caption := 'Pivar Address : string; var BufferSize: Wordng';
  end;

//  TMyThread.Create(Value).Start;

while FlgStart do

 try
    CoInitialize(nil);
    try
      IsPing:= Ping(Trim(ComboBox1.Text), 32);
//      Application.ProcessMessages;
      if IsPing then
       Memo1.Color:=clGreen
      else
       Memo1.Color:=$000000A6;
      Memo1.Lines.Add(MSG);

//      Ping('theroadtodelphi.wordpress.com',4,32);
    finally
      CoUninitialize;
    end;
 except
    on E:Exception do
    Form1.Memo1.Lines.Add(E.Classname+ ':'+ E.Message);
//        Writeln(E.Classname, ':', E.Message);
 end;

end;


procedure TForm1.FormCloseQuery(Sender: TObject; var CanClose: Boolean);
begin
 FlgStart:=False;
end;

procedure TForm1.FormCreate(Sender: TObject);
begin
  PacketsReceived:=0;
  ReceiveTimeMinimum        :=0;
  ReceiveTimeMaximum        :=0;
  ReceiveTimeAverage        :=0;
end;

end.
