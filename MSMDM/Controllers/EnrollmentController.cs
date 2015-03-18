using System;
using System.Collections;
using System.IdentityModel.Protocols.WSTrust;
using System.IO;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.RegularExpressions;
using System.Web.Mvc;
using MSMDM.Core;
using MSMDM.Models;
using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.Pkcs;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Crypto.Digests;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Crypto.Prng;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Pkcs;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Utilities;
using Org.BouncyCastle.X509;
using X509Certificate = System.Security.Cryptography.X509Certificates.X509Certificate;

namespace MSMDM.Controllers
{
    [RoutePrefix("EnrollmentServer")]
    public class EnrollmentController : Controller
    {
        private const int strength = 2048;
        private const string signatureAlgorithm = "SHA1WithRSA";

        [HttpGet] // used by windows 8.1
        [Route("contract")]
        public ActionResult GetContract()
        {
            var response = @"
{""DeviceRegistrationService"": {
        ""RegistrationEndpoint"":""https:\/\/sts.contoso.com\/EnrollmentServer\/DeviceEnrollmentWebService.svc"",
        ""RegistrationResourceId"":""urn:ms-drs:sts.contoso.com"",
        ""ServiceVersion"":""1.0""
    },
    ""AuthenticationService"": {
        ""OAuth2"": { 
            ""AuthCodeEndpoint"":""https:\/\/sts.contoso.com\/adfs\/oauth2\/authorize"",
            ""TokenEndpoint"":""https:\/\/sts.con toso.com\/adfs\/oauth2\/token""
        }
    },
    ""IdentityProviderService"": {
        ""PassiveAuthEndpoint"":""https:\/\/sts.contoso.com\/adfs\/ls""
    }
}";

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
            var requestString = GetRequestString();

            var response = "";

            var messageIdRegex = new Regex("<a:MessageID>(?<messageId>[a-z0-9:-]+)</a:MessageID>",
                RegexOptions.Multiline);
            var match = messageIdRegex.Match(requestString);
            if (match.Success)
            {
                var template = @"
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

                var enrollmentUrl = "https://enterpriseenrollment.dynamit.com.au/EnrollmentServer/Enrollment.svc";

                response = string.Format(template, Guid.NewGuid().ToString("D"), match.Groups["messageId"],
                    enrollmentUrl);
            }

            return Content(response, "application/soap+xml", Encoding.UTF8);
        }

        [HttpPost]
        [Route("Policy.svc")]
        public ActionResult PostService()
        {
            var requestString = GetRequestString();
            var response = "";

            var messageIdPattern = new Regex(@"<a:MessageID>(?<messageId>[a-zA-Z0-9:-]+)</a:MessageID>",
                RegexOptions.Multiline);
            var usernameTokenPattern = new Regex(@"<wsse:UsernameToken u:Id=""(?<usernameToken>[a-zA-Z0-9-]+)"">",
                RegexOptions.Multiline);

            var messageId = messageIdPattern.Match(requestString).Groups["messageId"].Value;
            var usernameToken = usernameTokenPattern.Match(requestString).Groups["usernameToken"].Value;

            var template = @"
<s:Envelope
  xmlns:a=""http://www.w3.org/2005/08/addressing""
  xmlns:s=""http://www.w3.org/2003/05/soap-envelope"">
  <s:Header>
     <a:Action s:mustUnderstand=""1"">http://schemas.microsoft.com/windows/pki/2009/01/enrollmentpolicy/IPolicy/GetPoliciesResponse</a:Action>
     <ActivityId CorrelationId=""" + Guid.NewGuid().ToString("D") +
                           @""" xmlns=""http://schemas.microsoft.com/2004/09/ServiceModel/Diagnostics"">" +
                           Guid.NewGuid().ToString("D") + @"</ActivityId>
     <a:RelatesTo>{0}</a:RelatesTo>
   </s:Header>
   <s:Body
    xmlns:xsi=""http://www.w3.org/2001/XMLSchema-instance""
    xmlns:xsd=""http://www.w3.org/2001/XMLSchema"">
    <GetPoliciesResponse xmlns=""http://schemas.microsoft.com/windows/pki/2009/01/enrollmentpolicy"">
      <response>
        <policyID>" + Guid.NewGuid() + @"</policyID>
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

            return Content(response, "application/soap+xml", Encoding.UTF8);
        }

        [HttpPost]
        [Route("Enrollment.svc")]
        public ActionResult PostEnrollment()
        {
            var requestString = GetRequestString();
            var response = "";

            var messageIdPattern = new Regex(@"<a:MessageID>(?<messageId>[a-zA-Z0-9:-]+)</a:MessageID>",
                RegexOptions.Multiline);
            var usernameTokenPattern = new Regex(@"<wsse:UsernameToken u:Id=""(?<usernameToken>[a-zA-Z0-9-]+)"">",
                RegexOptions.Multiline);
            var deviceTypePattern =
                new Regex(
                    @"<ac:ContextItem Name=""DeviceType"">\s+<ac:Value>(?<deviceType>.*)</ac:Value>\s+</ac:ContextItem>",
                    RegexOptions.Multiline);
            var applicationVersionPattern =
                new Regex(
                    @"<ac:ContextItem Name=""ApplicationVersion"">\s+<ac:Value>(?<applicationVersion>.*)</ac:Value>\s+</ac:ContextItem>",
                    RegexOptions.Multiline);
            var binarySecurityTokenPattern =
                new Regex(@"<wsse:BinarySecurityToken\b[^>]*>(?<securityToken>.*?)</wsse:BinarySecurityToken>",
                    RegexOptions.Multiline);


            var messageId = messageIdPattern.Match(requestString).Groups["messageId"].Value;
            var usernameToken = usernameTokenPattern.Match(requestString).Groups["usernameToken"].Value;
            var deviceType = deviceTypePattern.Match(requestString).Groups["deviceType"].Value;
            var applicationVersion = applicationVersionPattern.Match(requestString).Groups["applicationVersion"].Value;
            var securityToken = binarySecurityTokenPattern.Match(requestString).Groups["securityToken"].Value;

            var template = @"<s:Envelope xmlns:s=""http://schemas.xmlsoap.org/soap/envelope/""
    xmlns:a=""http://www.w3.org/2005/08/addressing""
    xmlns:u=""http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd"">
    <s:Header>
        <Action s:mustUnderstand=""1"" >http://schemas.microsoft.com/windows/pki/2009/01/enrollment/RSTRC/wstep</Action>
        <a:RelatesTo>{0}</a:RelatesTo>
        <o:Security s:mustUnderstand=""1"" xmlns:o=""http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd"">
            <u:Timestamp u:Id=""_0"">
            <u:Created>{2}</u:Created>
            <u:Expires>{3}</u:Expires>
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
                    xmlns=""http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd"">{1}</BinarySecurityToken>
            </RequestedSecurityToken>
            <RequestID xmlns=""http://schemas.microsoft.com/windows/pki/2009/01/enrollment"">0</RequestID>
            </RequestSecurityTokenResponse>
        </RequestSecurityTokenResponseCollection>
    </s:Body>
</s:Envelope>";

            DateTimeOffset createdTime = DateTimeOffset.UtcNow;
            DateTimeOffset expiresTime = createdTime.AddYears(6).AddMinutes(5);

            response = string.Format(template, messageId, GetToken(securityToken), createdTime.ToString("O"), expiresTime.ToString("O"));

            return Content(response, "application/soap+xml", Encoding.UTF8);
        }

        private string GetRequestString()
        {
            var req = Request.InputStream;
            req.Seek(0, SeekOrigin.Begin);
            var request = new StreamReader(req).ReadToEnd();
            return request;
        }

        private CertSignResponse GenerateSignedCertificate(CertificationRequestInfo csrInfo)
        {
            var publicKeyStructure = RsaPublicKeyStructure.GetInstance(csrInfo.SubjectPublicKeyInfo.GetPublicKey());
            var subjectPublicKey = new RsaKeyParameters(false, publicKeyStructure.Modulus,
                publicKeyStructure.PublicExponent);
            var subjectName = csrInfo.Subject;

            var issuerCertificate = CryptoHelpers.LoadCertificate(Server.MapPath(@"~/App_Data/CA.pfx"), null);
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

            certificateGenerator.SetSubjectDN(subjectName);
            certificateGenerator.SetPublicKey(subjectPublicKey);

            certificateGenerator.AddExtension(X509Extensions.KeyUsage.Id, false, new KeyUsage(0xa0));

            certificateGenerator.AddExtension(X509Extensions.ExtendedKeyUsage.Id, false,
                new ExtendedKeyUsage(new ArrayList
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
            certificateGenerator.AddExtension(X509Extensions.AuthorityKeyIdentifier.Id, false,
                authorityKeyIdentifierExtension);

            var subjectKeyIdentifierExtension =
                new SubjectKeyIdentifier(
                    SubjectPublicKeyInfoFactory.CreateSubjectPublicKeyInfo(subjectPublicKey));
            certificateGenerator.AddExtension(X509Extensions.SubjectKeyIdentifier.Id, false,
                subjectKeyIdentifierExtension);

            var certificate = certificateGenerator.Generate(issuerKeyPair.Private, random);

            certificate.Verify(issuerKeyPair.Public);
            var msCert = DotNetUtilities.ToX509Certificate(certificate);

            var issuerDer = issuerCertificate.Export(X509ContentType.Cert);
            var issuerBase64 = Convert.ToBase64String(issuerDer);
            var issuerThumbprint = Sha1Hash(issuerDer);

            var certDer = msCert.Export(X509ContentType.Cert);
            var certBase64 = Convert.ToBase64String(certDer);
            var certThumbprint = Sha1Hash(certDer);

            // System.IO.File.WriteAllText(Server.MapPath(@"~/App_Data/enroll-" + msCert.GetSerialNumberString() + ".cer"), CryptoHelpers.ExportToPEM(msCert));

            return new CertSignResponse(issuerBase64, issuerThumbprint, certBase64, certThumbprint);
        }

        private static string Sha1Hash(byte[] inputBytes)
        {
            Sha1Digest sha1 = new Sha1Digest();
            sha1.BlockUpdate(inputBytes, 0, inputBytes.Length);
            byte[] sha1Result = new byte[sha1.GetDigestSize()];
            sha1.DoFinal(sha1Result, 0);

            return BitConverter.ToString(sha1Result).Replace("-", string.Empty);
        }

        private string GetToken(string binarySecurityToken)
        {
            var encoded = Convert.FromBase64String(binarySecurityToken);
            var csr = new Pkcs10CertificationRequest(encoded);

            var requestInfo = csr.GetCertificationRequestInfo();
            var response = GenerateSignedCertificate(requestInfo);

            var token = System.IO.File.ReadAllText(Server.MapPath(@"~/App_Data/token_template.xml"));
            token = token.Replace("#{RootFingerprint}", response.IssuerThumbprint);
            token = token.Replace("#{RootCertificate}", response.IssuerBase64);
            token = token.Replace("#{UserFingerprint}", response.CertThumbprint);
            token = token.Replace("#{UserCertificate}", response.CertBase64);
            token = token.Replace("#{ApplicationAddress}", "http://10.0.1.57/");

            return CryptoHelpers.EncodeToBase64(token);
        }

        [Route("CACert.cer")]
        public ActionResult CACert()
        {
            var cert = System.IO.File.ReadAllText(Server.MapPath(@"~/App_Data/CA.cer"));
            return Content(cert,
                "application/x-x509-ca-cert");
        }
    }
}