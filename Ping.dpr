program Ping;

uses
  Vcl.Forms,
  Unit1 in 'Unit1.pas' {Form1},
  IcmpUtils in 'IcmpUtils.pas',
  networkfunctions in 'networkfunctions.pas';

{$R *.res}

begin
  Application.Initialize;
  Application.MainFormOnTaskbar := True;
  Application.CreateForm(TForm1, Form1);
  Application.Run;
end.
