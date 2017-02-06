object Form1: TForm1
  Left = 0
  Top = 0
  Caption = 'Ping'
  ClientHeight = 638
  ClientWidth = 382
  Color = clBtnFace
  Font.Charset = DEFAULT_CHARSET
  Font.Color = clWindowText
  Font.Height = -11
  Font.Name = 'Tahoma'
  Font.Style = []
  OldCreateOrder = False
  OnCloseQuery = FormCloseQuery
  OnCreate = FormCreate
  PixelsPerInch = 96
  TextHeight = 13
  object Button1: TButton
    Left = 0
    Top = 21
    Width = 382
    Height = 25
    Align = alTop
    Caption = 'Ping'
    TabOrder = 0
    OnClick = Button1Click
  end
  object Memo1: TMemo
    Left = 0
    Top = 46
    Width = 382
    Height = 592
    Align = alClient
    Color = clBlack
    Font.Charset = DEFAULT_CHARSET
    Font.Color = clYellow
    Font.Height = 12
    Font.Name = 'Tahoma'
    Font.Style = [fsBold]
    ParentFont = False
    ReadOnly = True
    ScrollBars = ssBoth
    TabOrder = 1
  end
  object ComboBox1: TComboBox
    Left = 0
    Top = 0
    Width = 382
    Height = 21
    Align = alTop
    TabOrder = 2
    Text = '8.8.8.8'
    Items.Strings = (
      '8.8.8.8'
      '4.2.2.4'
      '10.253.1.161'
      '10.253.1.1'
      '10.251.24.17')
  end
  object Timer1: TTimer
    Left = 240
    Top = 280
  end
end
