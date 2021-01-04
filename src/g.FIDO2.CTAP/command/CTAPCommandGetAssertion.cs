using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using PeterO.Cbor;

namespace g.FIDO2.CTAP
{
    public class CTAPCommandGetAssertionParam
    {
        public string RpId { get; set; }
        public byte[] ClientDataHash { get; set; }
        public byte[] AllowList_CredentialId { get; set; }
        public bool Option_up { get; set; }
        public bool Option_uv { get; set; }
        public bool UseHmacExtension { get; set; }

        public CTAPCommandGetAssertionParam(string rpid,byte[] challenge,byte[] credentialid=null)
        {
            if(rpid != null) this.RpId = rpid;
            if( challenge != null) this.ClientDataHash = Common.CreateClientDataHash(challenge);
            if (credentialid != null) this.AllowList_CredentialId = credentialid.ToArray();
        }
    }

    internal class CTAPCommandGetAssertion : CTAPCommand
    {
        private CTAPCommandGetAssertionParam param { get; set; }
        private byte[] pinAuth { get; set; }
        private COSE_Key keyAgreement { get; set; }

        public CTAPCommandGetAssertion(CTAPCommandGetAssertionParam param, byte[] pinAuth)
        {
            this.param = param;
            this.pinAuth = pinAuth?.ToArray();
        }

        public CTAPCommandGetAssertion(CTAPCommandGetAssertionParam param, byte[] pinAuth, COSE_Key keyAgreement)
        {
            this.param = param;
            this.pinAuth = pinAuth?.ToArray();
            this.keyAgreement = keyAgreement;
        }

        public override byte[] CreatePayload()
        {
            var cbor = CBORObject.NewMap();

            // 0x01 : rpid
            cbor.Add(0x01, param.RpId);

            // 0x02 : clientDataHash
            cbor.Add(0x02, param.ClientDataHash);

            // 0x03 : allowList
            if (param.AllowList_CredentialId != null) {
                var pubKeyCredParams = CBORObject.NewMap();
                pubKeyCredParams.Add("id", param.AllowList_CredentialId);
                pubKeyCredParams.Add("type", "public-key");
                cbor.Add(0x03, CBORObject.NewArray().Add(pubKeyCredParams));
            }

            // 0x04 : extensions
            if (param.UseHmacExtension && this.keyAgreement != null)
            {
                var extensions = CBORObject.NewMap();
                var hmac = CBORObject.NewMap();

                hmac.Add(0x01, new byte[]);


                extensions.Add("hmac-secret", hmac);
            }

            // 0x05 : options
            {
                var opt = CBORObject.NewMap();
                opt.Add("up", param.Option_up);
                opt.Add("uv", param.Option_uv);
                cbor.Add(0x05, opt);
            }

            if (pinAuth != null) {
                // pinAuth(0x06)
                cbor.Add(0x06, pinAuth);
                // 0x07:pinProtocol
                cbor.Add(0x07, 1);
            }

            return (create(CTAPCommandType.authenticatorGetAssertion, cbor));
        }

    }

}
