﻿using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace g.FIDO2.CTAP.HID
{
    internal class CTAPHIDSender
    {
        public event EventHandler KeepAlive;

        public CTAPHIDSender() { }

        public async Task<(DeviceStatus devSt, byte[] ctapRes)> SendCommandandResponseAsync(List<HidParam> hidParams,byte[] payload, int timeoutms)
        {
            if (CTAPHID.find(hidParams) == null) {
                Logger.Err("Connect Error");
                return (DeviceStatus.NotConnected, null);
            }

            var res = await CTAPHID.SendCommandandResponse(hidParams,payload, timeoutms,KeepAlive);
            if (res == null) {
                Logger.Err("Response Error");
                return (DeviceStatus.Unknown,null);
            }
            if (res.isTimeout) {
                Logger.Err("Wait Response Timeout");
                return (DeviceStatus.Timeout,null);
            }
            return (DeviceStatus.Ok,res.responseData);
        }

    }
}
