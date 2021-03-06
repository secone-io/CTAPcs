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
using g.FIDO2;
using g.FIDO2.Util;

namespace xServer
{
    /// <summary>
    /// Page4.xaml の相互作用ロジック
    /// </summary>
    public partial class Page4 : Page
    {
        private static Page5 page5 = null;
        private byte[] credentialID;
        private string publicKey;

        public Page4(byte[] creid,string pubkey)
        {
            InitializeComponent();

            credentialID = creid;
            publicKey = pubkey;

            if(creid!=null) this.TextCredentialID.Text = Common.BytesToHexString(creid);
            if(pubkey!=null) this.TextPublickKey.Text = pubkey;
        }

        private void ButtonNext_Click(object sender, RoutedEventArgs e)
        {
            if (page5 == null) {
                page5 = new Page5(credentialID,publicKey);
            }
            this.NavigationService.Navigate(page5);

        }
    }
}
