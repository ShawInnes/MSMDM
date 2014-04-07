using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text.RegularExpressions;
using System.Web;
using System.Web.Mvc;

namespace MSMDM.Controllers
{
    [RoutePrefix("EnrollmentServer")]
    public class EnrollmentController : Controller
    {
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
                string template = @"<s:Envelope xmlns:s=""http://www.w3.org/2003/05/soap-envelope"" xmlns:a=""http://www.w3.org/2005/08/addressing"">
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

            string messageId = messageIdPattern.Match(request).Groups["messageId"].Value;
            string usernameToken = usernameTokenPattern.Match(request).Groups["usernameToken"].Value;
            string deviceType = deviceTypePattern.Match(request).Groups["deviceType"].Value;
            string applicationVersion = applicationVersionPattern.Match(request).Groups["applicationVersion"].Value;


            string template = @"
<s:Envelope xmlns:s=""http://schemas.xmlsoap.org/soap/envelope/""
   xmlns:a=""http://www.w3.org/2005/08/addressing""
   xmlns:u=""http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd"">
   <s:Header>
      <Action s:mustUnderstand=""1"" >
         http://schemas.microsoft.com/windows/pki/2009/01/enrollment/RSTRC/wstep
      </Action>
      <a:RelatesTo>{0}</a:RelatesTo>
      <o:Security s:mustUnderstand=""1"" xmlns:o=""http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd"">
         <u:Timestamp u:Id=""_0"">
            <u:Created>2014-04-01T00:32:59.420Z</u:Created>
            <u:Expires>2020-04-01T00:37:59.420Z</u:Expires>
         </u:Timestamp>
      </o:Security>
   </s:Header>
   <s:Body>
      <RequestSecurityTokenResponseCollection
         xmlns=""http://docs.oasis-open.org/ws-sx/ws-trust/200512"">
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
            <RequestID xmlns=""http://schemas.microsoft.com/windows/pki/2009/01/enrollment"">0
            </RequestID>
         </RequestSecurityTokenResponse>
      </RequestSecurityTokenResponseCollection>
   </s:Body>
</s:Envelope>
    ";

            response = string.Format(template, messageId, GetToken());

            return Content(response, "application/soap+xml", System.Text.Encoding.UTF8);
        }

        private string GetToken()
        {
            string token = @"
<wap-provisioningdoc version=""1.1"">
   <characteristic type=""CertificateStore"">
      <characteristic type=""Root"">
         <characteristic type=""System"">
            <characteristic type=""031336C933CC7E228B88880D78824FB2909A0A2F"">
               <parm name=""EncodedCertificate"" value=""B64 encoded cert insert here"" />
            </characteristic>
         </characteristic>
      </characteristic>
      <characteristic type=""My"" >
      <!-- ""My"" and “User” are case-sensitive -->
         <characteristic type=""User"">
            <characteristic type=""F9A4F20FC50D990FDD0E3DB9AFCBF401818D5462"">
               <parm name=""EncodedCertificate"" value=""B64EncodedCertInsertedHere"" /> 
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
      <parm name=""ADDR"" value=""https://DM.contoso.com:443/omadm/WindowsPhone.ashx""/>
      <parm name=""CONNRETRYFREQ"" value=""6"" />
      <parm name=""INITIALBACKOFFTIME"" value=""30000"" />
      <parm name=""MAXBACKOFFTIME"" value=""120000"" />
      <parm name=""BACKCOMPATRETRYDISABLED"" />
      <parm name=""DEFAULTENCODING"" value=""application/vnd.syncml.dm+wbxml"" />
      <parm name=""SSLCLIENTCERTSEARCHCRITERIA"" value=""Subject=DC%3dcom%2cDC%3dmicrosoft%2cCN%3dUsers%2cCN%3dAdministrator&amp;Stores=My%5CUser""/>
      <characteristic type=""APPAUTH"">
        <parm name=""AAUTHLEVEL"" value=""CLIENT""/>
        <parm name=""AAUTHTYPE"" value=""DIGEST""/>
        <parm name=""AAUTHSECRET"" value=""password1""/>
        <parm name=""AAUTHDATA"" value=""B64encodedBinaryNonceInsertedHere""/>
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
         <!-- Retry waiting interval less than 60 minutes isn’t suggested due to impact to data comsumption and battery life. -->
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
   <!—Specify application Enrollment Token (AET) in EnrollmenToken node, provide URL for downloading company app hub apps, specify client certificate search criteria for downloading company app from SSL server that requires client cert based authentication . -->
   <characteristic type=""EnterpriseAppManagement""> 
      <characteristic type=""EnterpriseIDInsertedHere"">
          <parm datatype=""string"" name=""EnrollmentToken"" value=""AETInsertedHere""/> <parm datatype=""string"" name=""StoreProductId"" value=""AppProductIDInsertedHere""/> 
          <parm datatype=""string"" name=""StoreURI"" value=""HTTPS://DM.contoso.com:443/EnrollmentServer/clientcabs/EnterpriseApp1.xap""/>
          <parm datatype=""string"" name=""StoreName"" value=""Contoso App Store""/>
          <parm datatype=""string"" name=""CertificateSearchCriteria"" value=""ClientCertSearchCriteriaInsertedHere""/>
          <parm datatype=""string"" name=""CRLCheck"" value=""0""/>
      </characteristic>
   </characteristic>
</wap-provisioningdoc>";

            return EncodeToBase64(token);
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
            return Content(@"-----BEGIN CERTIFICATE-----
MIIDBTCCAe2gAwIBAgIQKzhdbbSbU79PWrlTQ7jTlzANBgkqhkiG9w0BAQUFADAV
MRMwEQYDVQQDEwppbkJldGEgTURNMB4XDTE0MDQwNzEwMzEyOFoXDTE5MDQwNzEw
NDEyOFowFTETMBEGA1UEAxMKaW5CZXRhIE1ETTCCASIwDQYJKoZIhvcNAQEBBQAD
ggEPADCCAQoCggEBAKJSsvnFBHOH49mJYAJ3NbJwle/sRNvV+9fyC0Lw3pU/XydO
z0/NBGyyop4JGomqr7VP0RFx6rCgemPI9FhQ7JCBCFA7U9OLj3kFbZ/vZ268qJ7B
F6RnDe1d9chfrXravc+yOO7z2eH7s0f5Cg8ZepfLcM5DOR3Yu/f+Q3iDGDlWST91
683t3mS7Iy8paGVX+2xK3XHfoyyZTIeI0G1kC/904Bvni1Lj56d64rlLb5LxXrx3
t2wsjg12LFJ5Kffg6gGbmfY93UPVtkoue5trqxV+MoAXvi6PNNdeeuOC4iyvqUmL
b93nHDgQtzvbyaC5sdGehRPlo8u+KwBQ7Y5i07sCAwEAAaNRME8wCwYDVR0PBAQD
AgGGMA8GA1UdEwEB/wQFMAMBAf8wHQYDVR0OBBYEFGtQrYkJcz/LMa8J2jMFgwf5
oi8GMBAGCSsGAQQBgjcVAQQDAgEAMA0GCSqGSIb3DQEBBQUAA4IBAQA+itTytErG
GGwcf4/Pxa8lXrKNtN2Y2lg8BpEo1QyiN7ofH0TIoR/ko6Jd9ig0OMY+g3EDnAUz
GJ1NY+LE5+RM+4FglUwhsAY/2AKwENa8OW+sa8NKjRHSjzyls7zhx4fR54nWH99g
Tkhizfo2Y17aE4yZjeWT5vvGfjy1RChm967e2yvm463c+iu3+cHS7AaoWhpoJ09D
8FzTXcP65PXLxUGxF6UvYNB+ofo6J5v97SLc7JZsvlPJOOy7H3NRFy4uM6h1R3+S
P9ErbS2QMacPQboaop20xhDXFgKzTcHPV/ae8XMdyB2ceZ9JXT0KRB/BfccmaYH1
sBSc9I2M1RJr
-----END CERTIFICATE-----", 
            "application/x-x509-ca-cert");
        }
    }
}