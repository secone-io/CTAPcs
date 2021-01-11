using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
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
        private byte[] sharedSecret { get; set; }
        
        //temp - for testing purposes only
        private static readonly byte[] salt = {
            0x78, 0x1c, 0x78, 0x60, 0xad, 0x88, 0xd2, 0x63,
            0x32, 0x62, 0x2a, 0xf1, 0x74, 0x5d, 0xed, 0xb2,
            0xe7, 0xa4, 0x2b, 0x44, 0x89, 0x29, 0x39, 0xc5,
            0x56, 0x64, 0x01, 0x27, 0x0d, 0xbb, 0xc4, 0x49,
        };


        public CTAPCommandGetAssertion(CTAPCommandGetAssertionParam param, byte[] pinAuth)
        {
            this.param = param;
            this.pinAuth = pinAuth?.ToArray();
        }

        public CTAPCommandGetAssertion(CTAPCommandGetAssertionParam param, byte[] pinAuth, COSE_Key keyAgreement, byte[] sharedSecret)
        {
            this.param = param;
            this.pinAuth = pinAuth?.ToArray();
            this.keyAgreement = keyAgreement;
            this.sharedSecret = sharedSecret;
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

                //keyAgreement(0x01): public key of platformKeyAgreementKey, "bG".
                hmac.Add(0x01, keyAgreement.ToCbor());

                //saltEnc(0x02): Encrypt one or two salts(Called salt1(32 bytes) and salt2(32 bytes))
                var saltEnc = AES256CBC.Encrypt(sharedSecret, salt);
                hmac.Add(0x02, saltEnc);

                //saltAuth(0x03): LEFT(HMAC-SHA-256(sharedSecret, saltEnc), 16).
                using (var hmacsha256 = new HMACSHA256(sharedSecret))
                {
                    var dgst = hmacsha256.ComputeHash(saltEnc);
                    hmac.Add(0x03, dgst.ToList().Take(16).ToArray());
                }

                extensions.Add("hmac-secret", hmac);
                cbor.Add(0x04, extensions);
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
