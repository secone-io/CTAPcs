﻿using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using PeterO.Cbor;
using g.FIDO2;

namespace g.FIDO2.CTAP
{
    public class CTAPResponseGetAssertion : CTAPResponse
    {
        public Assertion Assertion { get; private set; }

        public CTAPResponseGetAssertion(CTAPResponse obj) : base(obj) { }
        public CTAPResponseGetAssertion() : base() { }

        public override void Parse(byte[] byteresponse)
        {
            if (byteresponse == null) return;

            this.Assertion = new Assertion();

            var cbor = this.decodeFromBytes(byteresponse);
            if (cbor == null) return;

            foreach (var key in cbor.Keys) {
                var keyVal = key.ToObject<byte>();
                if (keyVal == 0x01) {
                    // 0x01:credential
                    parseCredential(cbor[key]);
                } else if (keyVal == 0x02) {
                    parseAuthData(cbor[key].GetByteString());
                } else if (keyVal == 0x03) {
                    // 0x03:signature
                    Assertion.Signature = cbor[key].GetByteString();
                } else if (keyVal == 0x04) {
                    parsePublicKeyCredentialUserEntity(cbor[key]);
                } else if (keyVal == 0x05) {
                    // 0x05:numberOfCredentials
                    Assertion.NumberOfCredentials = cbor[key].ToObject<UInt16>();
                }
            }
        }

        private void parseAuthData(byte[] data)
        {
            Logger.Log($"GOT EXTENSION DATA: {data.ToHexString()}");

            try {
                int index = 0;

                // rpIdHash	(32)
                Assertion.RpIdHash = data.Skip(index).Take(32).ToArray();
                index = index + 32;

                Logger.Log($"GOT RPIDHASH VALUE: {Assertion.RpIdHash.ToHexString()}");

                // flags(1)
                {
                    byte flags = data[index];

                    Logger.Log($"GOT FLAGS BYTE: {flags}");

                    index++;
                    Assertion.Flags_UserPresentResult = Common.GetBit(flags, 0);
                    Assertion.Flags_UserVerifiedResult = Common.GetBit(flags, 2);
                    Assertion.Flags_AttestedCredentialDataIncluded = Common.GetBit(flags, 6);
                    Assertion.Flags_ExtensionDataIncluded = Common.GetBit(flags, 7);

                    Logger.Log($"GOT EXTENSION DATA INCLUDED: {Assertion.Flags_ExtensionDataIncluded}");
                }

                // signCount(4)
                {
                    Assertion.SignCount = Common.ToInt32(data, index, true);
                    index = index + 4;
                    
                    Logger.Log($"GOT SIGNCOUNT VALUE: {Assertion.SignCount}");

                }

                // aaguid	16
                Assertion.Aaguid = data.Skip(index).Take(16).ToArray();
                index = index + 16;

                Logger.Log($"GOT AAGUID VALUE: {Assertion.Aaguid.ToHexString()}");

                Logger.Log($"REMAINING EXTENSION DATA: {data.Skip(index).ToArray().ToHexString()}");

            } catch (Exception ex) {
                Logger.Err(ex, "parseAuthData");
            }
            Assertion.AuthData = data;
        }

        private void parsePublicKeyCredentialUserEntity(CBORObject cbor)
        {
            try {
                foreach (var key in cbor.Keys) {
                    var keyVal = key.AsString();
                    if (keyVal == "id") {
                        Assertion.User_Id = cbor[key].GetByteString();
                    } else if (keyVal == "name") {
                        Assertion.User_Name = cbor[key].AsString();
                    } else if (keyVal == "displayName") {
                        Assertion.User_DisplayName = cbor[key].AsString();
                    }
                }
            } catch (Exception ex) {
                Logger.Err(ex, "parsePublicKeyCredentialUserEntity");
            }
        }

        private void parseCredential(CBORObject cbor)
        {
            try {
                foreach (var key in cbor.Keys) {
                    var keyVal = key.AsString();
                    if (keyVal == "id") {
                        Assertion.CredentialId = cbor[key].GetByteString();
                    } else if (keyVal == "type") {
                    }
                }
            } catch (Exception ex) {
                Logger.Err(ex, "parseCredential");
            }
        }

    }
}
