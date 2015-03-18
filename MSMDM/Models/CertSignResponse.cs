namespace MSMDM.Models
{
    public class CertSignResponse
    {
        public CertSignResponse(string issuerBase64, string issuerThumbprint, string certBase64, string certThumbprint)
        {
            IssuerBase64 = issuerBase64;
            IssuerThumbprint = issuerThumbprint;
            CertBase64 = certBase64;
            CertThumbprint = certThumbprint;
        }
        public string IssuerBase64 { get; set; }
        public string IssuerThumbprint { get; set; }
        public string CertBase64 { get; set; }
        public string CertThumbprint { get; set; }
    }
}
