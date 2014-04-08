using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Crypto.Prng;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Pkcs;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Utilities;
using Org.BouncyCastle.X509;
using System;
using System.Collections;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Text.RegularExpressions;
using System.Web;
using System.Web.Mvc;

namespace MSMDM.Controllers
{
    [RoutePrefix("EnrollmentServer")]
    public class EnrollmentController : Controller
    {
        [HttpGet] // used by windows 8.1
        [Route("contract")]
        public ActionResult GetContract()
        {
            string response = @"{""DeviceRegistrationService"":{""RegistrationEndpoint"":""https:\/\/sts.contoso.com\/EnrollmentServer\/DeviceEnrollmentWebService.svc"",""RegistrationResourceId"":""urn:ms-drs:sts.contoso.com"",""ServiceVersion"":""1.0""},""AuthenticationService"":{""OAuth2"":{""AuthCodeEndpoint"":""https:\/\/sts.contoso.com\/adfs\/oauth2\/authorize"",""TokenEndpoint"":""https:\/\/sts.con toso.com\/adfs\/oauth2\/token""}},""IdentityProviderService"":{""PassiveAuthEndpoint"":""https:\/\/ sts.contoso.com\/adfs\/ls""}}";

            return Content(response, "application/json");
        }

        [HttpGet]
        [Route("Discovery.svc")]
        public ActionResult GetDiscovery()
        {
            return Content("", "text/html");
        }

        [HttpPost]
        [Route("Discovery.svc")]
        public ActionResult PostDiscovery()
        {
            Stream req = Request.InputStream;
            req.Seek(0, System.IO.SeekOrigin.Begin);
            string request = new StreamReader(req).ReadToEnd();

            string response = "";

            Regex messageIdRegex = new Regex("<a:MessageID>(?<messageId>[a-z0-9:-]+)</a:MessageID>", RegexOptions.Multiline);
            Match match = messageIdRegex.Match(request);
            if (match.Success)
            {
                string template = @"
<s:Envelope xmlns:s=""http://www.w3.org/2003/05/soap-envelope"" xmlns:a=""http://www.w3.org/2005/08/addressing"">
    <s:Header>
        <a:Action s:mustUnderstand=""1"">http://schemas.microsoft.com/windows/management/2012/01/enrollment/IDiscoveryService/DiscoverResponse</a:Action>
        <ActivityId>{0}</ActivityId>
        <a:RelatesTo>{1}</a:RelatesTo> 
    </s:Header>
    <s:Body xmlns:xsi=""http://www.w3.org/2001/XMLSchema-instance""
        xmlns:xsd=""http://www.w3.org/2001/XMLSchema"">
        <DiscoverResponse
            xmlns=""http://schemas.microsoft.com/windows/management/2012/01/enrollment"">
            <DiscoverResult>
            <AuthPolicy>OnPremise</AuthPolicy>
            <EnrollmentServiceUrl>{2}</EnrollmentServiceUrl>
            </DiscoverResult>
        </DiscoverResponse>
    </s:Body>
</s:Envelope>";

                string enrollmentUrl = "https://enterpriseenrollment.dynamit.com.au/EnrollmentServer/Enrollment.svc";

                response = string.Format(template, System.Guid.NewGuid().ToString("D"), match.Groups["messageId"], enrollmentUrl);
            }

            return Content(response, "application/soap+xml", System.Text.Encoding.UTF8);
        }

        [HttpPost]
        [Route("Policy.svc")]
        public ActionResult PostService()
        {
            Stream req = Request.InputStream;
            req.Seek(0, System.IO.SeekOrigin.Begin);
            string request = new StreamReader(req).ReadToEnd();

            string response = "";

            Regex messageIdPattern = new Regex(@"<a:MessageID>(?<messageId>[a-zA-Z0-9:-]+)</a:MessageID>", RegexOptions.Multiline);
            Regex usernameTokenPattern = new Regex(@"<wsse:UsernameToken u:Id=""(?<usernameToken>[a-zA-Z0-9-]+)"">", RegexOptions.Multiline);

            string messageId = messageIdPattern.Match(request).Groups["messageId"].Value;
            string usernameToken = usernameTokenPattern.Match(request).Groups["usernameToken"].Value;

            string template = @"
<s:Envelope
  xmlns:a=""http://www.w3.org/2005/08/addressing""
  xmlns:s=""http://www.w3.org/2003/05/soap-envelope"">
  <s:Header>
     <a:Action s:mustUnderstand=""1"">http://schemas.microsoft.com/windows/pki/2009/01/enrollmentpolicy/IPolicy/GetPoliciesResponse</a:Action>
     <ActivityId CorrelationId=""" + System.Guid.NewGuid().ToString("D") + @""" xmlns=""http://schemas.microsoft.com/2004/09/ServiceModel/Diagnostics"">" + System.Guid.NewGuid().ToString("D") + @"</ActivityId>
     <a:RelatesTo>{0}</a:RelatesTo>
   </s:Header>
   <s:Body
    xmlns:xsi=""http://www.w3.org/2001/XMLSchema-instance""
    xmlns:xsd=""http://www.w3.org/2001/XMLSchema"">
    <GetPoliciesResponse xmlns=""http://schemas.microsoft.com/windows/pki/2009/01/enrollmentpolicy"">
      <response>
        <policyID>" + System.Guid.NewGuid().ToString() + @"</policyID>
        <policyFriendlyName xsi:nil=""true"" xmlns:xsi=""http://www.w3.org/2001/XMLSchema-instance""/>
        <nextUpdateHours xsi:nil=""true"" xmlns:xsi=""http://www.w3.org/2001/XMLSchema-instance""/>
        <policiesNotChanged xsi:nil=""true"" xmlns:xsi=""http://www.w3.org/2001/XMLSchema-instance""/>
        <policies>
          <policy>
            <policyOIDReference>9</policyOIDReference>
            <cAs>
              <cAReference>0</cAReference>
            </cAs>
            <attributes>
                <policySchema>3</policySchema>
                <privateKeyAttributes>
                <minimalKeyLength>2048</minimalKeyLength>
                <keySpec xsi:nil=""true"" />
                <keyUsageProperty xsi:nil=""true"" />
                <permissions xsi:nil=""true"" />
                <algorithmOIDReference xsi:nil=""true"" />
                <cryptoProviders xsi:nil=""true"" />
                </privateKeyAttributes>
                <supersededPolicies xsi:nil=""true"" />
                <privateKeyFlags xsi:nil=""true"" />
                <subjectNameFlags xsi:nil=""true"" />
                <enrollmentFlags xsi:nil=""true"" />
                <generalFlags xsi:nil=""true"" />
                <hashAlgorithmOIDReference>0</hashAlgorithmOIDReference>
                <rARequirements xsi:nil=""true"" />
                <keyArchivalAttributes xsi:nil=""true"" />
                <extensions xsi:nil=""true"" />
            </attributes>
          </policy>                    
        </policies>
      </response>
      <cAs xsi:nil=""true"" />
      <oIDs>
        <oID>
          <value>1.3.14.3.2.29</value>
          <group>1</group>
          <oIDReferenceID>0</oIDReferenceID>
          <defaultName>szOID_OIWSEC_sha1RSASign</defaultName>
        </oID>
      </oIDs>
    </GetPoliciesResponse>
  </s:Body>
</s:Envelope>
";
            response = string.Format(template, messageId);

            return Content(response, "application/soap+xml", System.Text.Encoding.UTF8);
        }

        [HttpPost]
        [Route("Enrollment.svc")]
        public ActionResult PostEnrollment()
        {
            Stream req = Request.InputStream;
            req.Seek(0, System.IO.SeekOrigin.Begin);
            string request = new StreamReader(req).ReadToEnd();

            string response = "";

            Regex messageIdPattern = new Regex(@"<a:MessageID>(?<messageId>[a-zA-Z0-9:-]+)</a:MessageID>", RegexOptions.Multiline);
            Regex usernameTokenPattern = new Regex(@"<wsse:UsernameToken u:Id=""(?<usernameToken>[a-zA-Z0-9-]+)"">", RegexOptions.Multiline);
            Regex deviceTypePattern = new Regex(@"<ac:ContextItem Name=""DeviceType"">\s+<ac:Value>(?<deviceType>.*)</ac:Value>\s+</ac:ContextItem>", RegexOptions.Multiline);
            Regex applicationVersionPattern = new Regex(@"<ac:ContextItem Name=""ApplicationVersion"">\s+<ac:Value>(?<applicationVersion>.*)</ac:Value>\s+</ac:ContextItem>", RegexOptions.Multiline);
            Regex binarySecurityTokenPattern = new Regex(@"<wsse:BinarySecurityToken\b[^>]*>(?<securityToken>.*?)</wsse:BinarySecurityToken>", RegexOptions.Multiline);
            

            string messageId = messageIdPattern.Match(request).Groups["messageId"].Value;
            string usernameToken = usernameTokenPattern.Match(request).Groups["usernameToken"].Value;
            string deviceType = deviceTypePattern.Match(request).Groups["deviceType"].Value;
            string applicationVersion = applicationVersionPattern.Match(request).Groups["applicationVersion"].Value;
            string securityToken = binarySecurityTokenPattern.Match(request).Groups["securityToken"].Value;

            string template = @"
<s:Envelope xmlns:s=""http://schemas.xmlsoap.org/soap/envelope/""
    xmlns:a=""http://www.w3.org/2005/08/addressing""
    xmlns:u=""http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd"">
    <s:Header>
        <Action s:mustUnderstand=""1"" >http://schemas.microsoft.com/windows/pki/2009/01/enrollment/RSTRC/wstep</Action>
        <a:RelatesTo>{0}</a:RelatesTo>
        <o:Security s:mustUnderstand=""1"" xmlns:o=""http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd"">
            <u:Timestamp u:Id=""_0"">
            <u:Created>2014-04-01T00:32:59.420Z</u:Created>
            <u:Expires>2020-04-01T00:37:59.420Z</u:Expires>
            </u:Timestamp>
        </o:Security>
    </s:Header>
    <s:Body>
        <RequestSecurityTokenResponseCollection xmlns=""http://docs.oasis-open.org/ws-sx/ws-trust/200512"">
            <RequestSecurityTokenResponse>
            <TokenType>http://schemas.microsoft.com/5.0.0.0/ConfigurationManager/Enrollment/DeviceEnrollmentToken</TokenType>
            <RequestedSecurityToken>
                <BinarySecurityToken
                    ValueType=""http://schemas.microsoft.com/5.0.0.0/ConfigurationManager/Enrollment/DeviceEnrollmentProvisionDoc""
                    EncodingType=""http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd#base64binary""
                    xmlns=""http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd"">
                    {1}
                </BinarySecurityToken>
            </RequestedSecurityToken>
            <RequestID xmlns=""http://schemas.microsoft.com/windows/pki/2009/01/enrollment"">0</RequestID>
            </RequestSecurityTokenResponse>
        </RequestSecurityTokenResponseCollection>
    </s:Body>
</s:Envelope>";

            response = string.Format(template, messageId, GetToken(securityToken));

            return Content(response, "application/soap+xml", System.Text.Encoding.UTF8);
        }

        const int strength = 2048;
        const string signatureAlgorithm = "SHA256WithRSA";

        private static System.Security.Cryptography.X509Certificates.X509Certificate2 LoadCertificate(string issuerFileName, string password)
        {
            var issuerCertificate = new System.Security.Cryptography.X509Certificates.X509Certificate2(issuerFileName, password, System.Security.Cryptography.X509Certificates.X509KeyStorageFlags.Exportable);
            return issuerCertificate;
        }

        private CertSignResponse GenerateSignedCertificate(Org.BouncyCastle.Asn1.Pkcs.CertificationRequestInfo csrInfo)
        {
            RsaPublicKeyStructure publicKeyStructure = RsaPublicKeyStructure.GetInstance(csrInfo.SubjectPublicKeyInfo.GetPublicKey());
            RsaKeyParameters subjectPublicKey = new RsaKeyParameters(false, publicKeyStructure.Modulus, publicKeyStructure.PublicExponent);

            var issuerCertificate = LoadCertificate(@"c:\ca\CAKey.pfx", null);
            var issuerName = issuerCertificate.Subject;
            var issuerSerialNumber = new BigInteger(issuerCertificate.GetSerialNumber());
            var issuerKeyPair = DotNetUtilities.GetKeyPair(issuerCertificate.PrivateKey);

            var randomGenerator = new CryptoApiRandomGenerator();
            var random = new SecureRandom(randomGenerator);

            var serialNumber = BigIntegers.CreateRandomInRange(
                       BigInteger.One,
                       BigInteger.ValueOf(Int64.MaxValue),
                       random);

            var certificateGenerator = new X509V3CertificateGenerator();

            var issuerDN = new X509Name(issuerName);
            certificateGenerator.SetIssuerDN(issuerDN);

            certificateGenerator.SetSerialNumber(serialNumber);
            certificateGenerator.SetSignatureAlgorithm(signatureAlgorithm);

            //certificateGenerator.SetSubjectDN(csrInfo.Subject);
            certificateGenerator.SetSubjectDN(new X509Name("CN=MSMDM Device"));
            certificateGenerator.SetPublicKey(subjectPublicKey);

            ///// For Server Certificates Only
            //var subjectAlternativeNames = new Asn1Encodable[]
            //                                    {
            //                                        new GeneralName(GeneralName.DnsName, "enterpriseenrollment"),
            //                                        new GeneralName(GeneralName.DnsName, "enterpriseenrollment.dynamit.com.au")
            //                                    };
            //var subjectAlternativeNamesExtension = new DerSequence(subjectAlternativeNames);
            //certificateGenerator.AddExtension(X509Extensions.SubjectAlternativeName.Id, false, subjectAlternativeNamesExtension);

            certificateGenerator.AddExtension(X509Extensions.KeyUsage.Id, false, new KeyUsage(0xa0));

            certificateGenerator.AddExtension(X509Extensions.ExtendedKeyUsage.Id, false, new ExtendedKeyUsage(new ArrayList() 
                                                                                                                    { 
                                                                                                                        KeyPurposeID.IdKPClientAuth,
                                                                                                                        new DerObjectIdentifier("1.3.6.1.4.1.311.65.2.1")
                                                                                                                    }));

            var notBefore = DateTime.UtcNow.Date;
            var notAfter = notBefore.AddYears(1);

            certificateGenerator.SetNotBefore(notBefore);
            certificateGenerator.SetNotAfter(notAfter);

            // Add CA Reference to Chain
            var authorityKeyIdentifierExtension =
              new AuthorityKeyIdentifier(
                  SubjectPublicKeyInfoFactory.CreateSubjectPublicKeyInfo(issuerKeyPair.Public),
                  new GeneralNames(new GeneralName(issuerDN)),
                  issuerSerialNumber);
            certificateGenerator.AddExtension(X509Extensions.AuthorityKeyIdentifier.Id, false, authorityKeyIdentifierExtension);

            var subjectKeyIdentifierExtension =
                         new SubjectKeyIdentifier(
                             SubjectPublicKeyInfoFactory.CreateSubjectPublicKeyInfo(subjectPublicKey));
            certificateGenerator.AddExtension(X509Extensions.SubjectKeyIdentifier.Id, false, subjectKeyIdentifierExtension);

            var certificate = certificateGenerator.Generate(issuerKeyPair.Private, random);

            certificate.Verify(issuerKeyPair.Public);
            System.Security.Cryptography.X509Certificates.X509Certificate msCert = DotNetUtilities.ToX509Certificate(certificate);

            string issuerBase64 = Convert.ToBase64String(issuerCertificate.Export(System.Security.Cryptography.X509Certificates.X509ContentType.Cert));
            string issuerSerial = issuerCertificate.GetSerialNumberString();
            
            string certBase64 = Convert.ToBase64String(msCert.Export(System.Security.Cryptography.X509Certificates.X509ContentType.Cert));
            string certSerial = msCert.GetSerialNumberString();

            System.IO.File.WriteAllText(@"c:\ca\enroll-" + msCert.GetSerialNumberString() + ".cer", ExportToPEM(msCert));
            
            return new CertSignResponse(issuerBase64, issuerSerial, certBase64, certSerial);
        }

        public static string ExportToPEM(System.Security.Cryptography.X509Certificates.X509Certificate cert)
        {
            StringBuilder builder = new StringBuilder();

            builder.AppendLine("-----BEGIN CERTIFICATE-----");
            builder.AppendLine(Convert.ToBase64String(cert.Export(System.Security.Cryptography.X509Certificates.X509ContentType.Cert), Base64FormattingOptions.InsertLineBreaks));
            builder.AppendLine("-----END CERTIFICATE-----");

            return builder.ToString();
        }

        private string GetToken(string binarySecurityToken)
        {
            byte[] encoded = Convert.FromBase64String(binarySecurityToken);
            var csr = new Pkcs10CertificationRequest(encoded);

            var requestInfo = csr.GetCertificationRequestInfo();

            CertSignResponse response = GenerateSignedCertificate(requestInfo);

            string template = @"<wap-provisioningdoc version=""1.1"">
    <characteristic type=""CertificateStore"">
        <characteristic type=""Root"">
            <characteristic type=""System"">
                <characteristic type=""{0}"">
                    <parm name=""EncodedCertificate"" value=""{1}"" />
                </characteristic>
            </characteristic>
        </characteristic>
        <characteristic type=""My"" >
            <characteristic type=""User"">
                <characteristic type=""{2}"">
                    <parm name=""EncodedCertificate"" value=""{3}"" /> 
                </characteristic>
                <characteristic type=""PrivateKeyContainer""/>
                <!-- This tag must be present for XML syntax correctness. -->
            </characteristic>
        </characteristic>
    </characteristic>
    <characteristic type=""APPLICATION"">
        <parm name=""APPID"" value=""w7""/>
        <parm name=""PROVIDER-ID"" value=""TestMDMServer""/>
        <parm name=""NAME"" value=""Microsoft""/>
        <parm name=""ADDR"" value=""https://enterpriseenrollment.dynamit.com.au:443/""/>
        <parm name=""CONNRETRYFREQ"" value=""6"" />
        <parm name=""INITIALBACKOFFTIME"" value=""30000"" />
        <parm name=""MAXBACKOFFTIME"" value=""120000"" />
        <parm name=""BACKCOMPATRETRYDISABLED"" />
        <parm name=""DEFAULTENCODING"" value=""application/vnd.syncml.dm+wbxml"" />
        <parm name=""SSLCLIENTCERTSEARCHCRITERIA"" value=""Subject=CN%3dMSMDM%20Device&amp;Stores=My%5CUser""/>
        <characteristic type=""APPAUTH"">
        <parm name=""AAUTHLEVEL"" value=""CLIENT""/>
        <parm name=""AAUTHTYPE"" value=""BASIC""/>
        <parm name=""AAUTHNAME"" value=""testclient""/>
        <parm name=""AAUTHSECRET"" value=""password2""/>
        </characteristic>
        <characteristic type=""APPAUTH"">
            <parm name=""AAUTHLEVEL"" value=""APPSRV""/>
            <parm name=""AAUTHTYPE"" value=""BASIC""/>
            <parm name=""AAUTHNAME"" value=""testclient""/>
            <parm name=""AAUTHSECRET"" value=""password2""/>
        </characteristic>
    </characteristic>
    <characteristic type=""Registry"">
        <characteristic type=""HKLM\Software\Microsoft\Enrollment"">
            <parm name=""RenewalPeriod"" value=""42"" datatype=""integer"" />
        </characteristic>
        <characteristic type=""HKLM\Software\Microsoft\Enrollment\OmaDmRetry"">
            <parm name=""NumRetries"" value=""8"" datatype=""integer"" />
            <parm name=""RetryInterval"" value=""15"" datatype=""integer"" />
            <parm name=""AuxNumRetries"" value=""5"" datatype=""integer"" />
            <parm name=""AuxRetryInterval"" value=""3"" datatype=""integer"" />
            <parm name=""Aux2NumRetries"" value=""0"" datatype=""integer"" />
            <parm name=""Aux2RetryInterval"" value=""480"" datatype=""integer"" />
        </characteristic>
    </characteristic>
    <characteristic type=""DMClient"">
        <characteristic type=""Provider"">
            <characteristic type=""TestMDMServer"">
            <parm name=""EntDeviceName"" value=""Administrator_WindowsPhone"" datatype=""string"" />
            </characteristic>
        </characteristic>
    </characteristic>
</wap-provisioningdoc>";

            string fullToken = string.Format(template, response.IssuerSerial, response.IssuerBase64, response.CertSerial, response.CertBase64);

            return EncodeToBase64(fullToken);
        }

        static public string EncodeToBase64(string toEncode)
        {
            byte[] toEncodeAsBytes = System.Text.ASCIIEncoding.ASCII.GetBytes(toEncode);
            string returnValue = System.Convert.ToBase64String(toEncodeAsBytes);
            return returnValue;
        }

        [Route("CACert.cer")]
        public ActionResult CACert()
        {
            string cert = System.IO.File.ReadAllText(@"c:\ca\CACert.cer");
            return Content(cert, 
            "application/x-x509-ca-cert");
        }
    }
}