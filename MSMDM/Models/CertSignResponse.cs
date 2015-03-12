using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace MSMDM.Controllers
{
    public class CertSignResponse
    {
        public CertSignResponse(string issuerBase64, string issuerSerial, string certBase64, string certSerial)
        {
            IssuerBase64 = issuerBase64;
            IssuerSerial = issuerSerial;
            CertBase64 = certBase64;
            CertSerial = certSerial;
        }
        public string IssuerBase64 { get; set; }
        public string IssuerSerial { get; set; }
        public string CertBase64 { get; set; }
        public string CertSerial { get; set; }
    }
}
