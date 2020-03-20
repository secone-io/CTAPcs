﻿using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Data;
using System.Windows.Documents;
using System.Windows.Input;
using System.Windows.Media;
using System.Windows.Media.Imaging;
using System.Windows.Navigation;
using System.Windows.Shapes;
using System.Windows.Threading;
using g.FIDO2.CTAP.BLE;

namespace Test01
{
    /// <summary>
    /// MainWindow.xaml の相互作用ロジック
    /// </summary>
    public partial class MainWindow : Window
    {
        BLEAuthenticatorScanner scanner;
        ulong bleAddress = 0;
        BLEAuthenticatorConnector con;

        private void addLog(string message)
        {
            Console.WriteLine($"{message}");
            // UIスレッドで実行するおまじない
            var ignored = this.Dispatcher.BeginInvoke(DispatcherPriority.Normal, (Action)(() => {
                textLog.Text += message + Environment.NewLine;
            }));
        }

        private void LogResponse(g.FIDO2.CTAP.DeviceStatus devSt, g.FIDO2.CTAP.CTAPResponse res)
        {
            addLog($"- DeviceStatus = {devSt.ToString()}");
            addLog($"- CTAP Status = 0x{res?.Status.ToString("X")}");
            addLog($"- CTAP StatusMsg = {res?.StatusMsg}");
            addLog($"- CTAP SendPayloadJson = {res?.SendPayloadJson}");
            addLog($"- CTAP ResponseDataJson = {res?.ResponsePayloadJson}");
            addLog("");
        }

        private void OnFindDevice(object sender, g.FIDO2.CTAP.BLE.BLEAuthenticatorScanner.FindDeviceEventArgs e)
        {

            addLog($"<OnFindDevice>");
            scanner.Stop();

            addLog($"- BluetoothAddress = {e.BluetoothAddress}");
            addLog($"- CompanyId = 0x{e.CompanyId.ToString("X")}");
            addLog($"- ManufacturerData = 0x{g.FIDO2.Common.BytesToHexString(e.ManufacturerData)}");

            bleAddress = e.BluetoothAddress;

            ButtonConnect_Click(null, null);
        }

        private void OnConnectedDevice(object sender, EventArgs e)
        {
            addLog($"<OnConnectedDevice>");
        }

        private void OnDisconnectedDevice(object sender, EventArgs e)
        {
            addLog($"<OnDisconnectedDevice>");
        }

        private void OnKeepAlive(object sender, EventArgs e)
        {
            addLog($"<OnKeppAlive>");
            addLog($"- touch authenticator!");
        }

        public MainWindow()
        {
            InitializeComponent();
        }

        private void ButtonStartScan_Click(object sender, RoutedEventArgs e)
        {
            scanner = new BLEAuthenticatorScanner();
            scanner.FindDevice += OnFindDevice;
            if (scanner.Start()) {
                addLog("Scan Start.BLE FIDOキーをONにしてください");
                addLog("");
            } else {
                addLog("Scan Start Error");
                addLog("");
            }
        }

        private void ButtonStopScan_Click(object sender, RoutedEventArgs e)
        {
            addLog("<Scan Stop>");
            scanner.Stop();
        }

        private async void ButtonConnect_Click(object sender, RoutedEventArgs e)
        {
            try {
                addLog("<Connect>");

                con = new BLEAuthenticatorConnector();
                //con.PacketSizeByte = 155;       // AllinPass
                con.ConnectedDevice += OnConnectedDevice;
                con.DisconnectedDevice += OnDisconnectedDevice;
                con.KeepAlive += OnKeepAlive;
                var result = await con.ConnectAsync(this.bleAddress);
                if (result == false) {
                    addLog("- Connect Error");
                }
            } catch (Exception ex) {
                addLog($"- Connect Error Exception{ex.Message}");
            }
        }

        private void ButtonDiscon_Click(object sender, RoutedEventArgs e)
        {
            addLog("<Disconnect>");
            con.Disconnect();
        }

        private async void ButtonGetInfo_Click(object sender, RoutedEventArgs e)
        {
            addLog("<GetInfo>");
            var res = await con.GetInfoAsync();
            LogResponse(res.DeviceStatus, res.CTAPResponse);
        }

        private async void ButtonClientPINgetRetries_Click(object sender, RoutedEventArgs e)
        {
            {
                addLog("<ClientPIN getRetries>");
                var res = await con.ClientPINgetRetriesAsync();
                LogResponse(res.DeviceStatus, res.CTAPResponse);
            }

            {
                addLog("<ClientPIN getPINToken>");
                var res = await con.ClientPINgetPINTokenAsync("1234");
                LogResponse(res.DeviceStatus, res.CTAPResponse);
            }
        }

        private async void ButtonGetAssertion_Click(object sender, RoutedEventArgs e)
        {
            addLog("<getAssertion>");

            var rpid = "BLEtest.com";
            var challenge = Encoding.ASCII.GetBytes("this is challenge");
            var creid = g.FIDO2.Common.HexStringToBytes("037999FF2CBF4509988ADF17621BBA58");

            var param = new g.FIDO2.CTAP.CTAPCommandGetAssertionParam(rpid,challenge,creid);

            param.Option_up = false;
            param.Option_uv = true;

            //var res = await con.GetAssertion(param);
            var res = await con.GetAssertionAsync(param, "");
            LogResponse(res.DeviceStatus, res.CTAPResponse);

            if (res?.CTAPResponse?.Assertion?.NumberOfCredentials > 0) {
                for (int intIc = 0; intIc < res.CTAPResponse.Assertion.NumberOfCredentials - 1; intIc++) {
                    var next = await con.GetNextAssertionAsync();
                    LogResponse(next.DeviceStatus,next.CTAPResponse);
                }
            }
        }

        private async void ButtonMakeCredential_Click(object sender, RoutedEventArgs e)
        {
            addLog("<makeCredential>");

            var rpid = "BLEtest.com";
            var challenge = Encoding.ASCII.GetBytes("this is challenge");

            var param = new g.FIDO2.CTAP.CTAPCommandMakeCredentialParam(rpid,challenge, new byte[0]);
            param.RpName = "BLEtest name";
            param.UserName = "testUserName";
            param.UserDisplayName = "testUserDisplayName";
            param.Option_rk = false;
            param.Option_uv = true;

            string pin = "";

            var res = await con.MakeCredentialAsync(param, pin);
            LogResponse(res.DeviceStatus, res.CTAPResponse);

            if (res?.CTAPResponse?.Attestation != null) {
                var creid = g.FIDO2.Common.BytesToHexString(res.CTAPResponse.Attestation.CredentialId);
                addLog($"- CredentialID = {creid}");
            }

        }
    }
}
