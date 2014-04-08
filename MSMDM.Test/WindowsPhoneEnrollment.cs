using System;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using System.Xml;
using System.Text.RegularExpressions;
using System.Net;
using Org.BouncyCastle.Pkcs;
using System.Text;

namespace MSMDM.Test
{
    [TestClass]
    public class WindowsPhoneEnrollment
    {
        [TestMethod]
        public void DiscoveryTest()
        {
            string xml = @"<s:Envelope xmlns:a=""http://www.w3.org/2005/08/addressing"" xmlns:s=""http://www.w3.org/2003/05/soap-envelope"">
                        <s:Header>
                        <a:Action s:mustUnderstand=""1"">http://schemas.microsoft.com/windows/management/2012/01/enrollment/IDiscoveryService/Discover</a:Action>
                        <a:MessageID>urn:uuid:748132ec-a575-4329-b01b-6171a9cf8478</a:MessageID>
                        <a:ReplyTo>
                            <a:Address>http://www.w3.org/2005/08/addressing/anonymous</a:Address>
                        </a:ReplyTo>
                        <a:To s:mustUnderstand=""1"">https://EnterpriseEnrollment.dynamit.com.au:443/EnrollmentServer/Discovery.svc</a:To>
                        </s:Header>
                        <s:Body>
                        <Discover xmlns=""http://schemas.microsoft.com/windows/management/2012/01/enrollment"">
                            <request xmlns:i=""http://www.w3.org/2001/XMLSchema-instance"">
                                <EmailAddress>m@dynamit.com.au</EmailAddress>
                                <RequestVersion>1.0</RequestVersion>
                            </request>
                        </Discover>
                        </s:Body>
                        </s:Envelope>";

            string response = null;

            Regex pattern = new Regex("<a:MessageID>(?<messageId>[a-z0-9:-]+)</a:MessageID>", RegexOptions.Multiline);
            Match match = pattern.Match(xml);
            if (match.Success)
            {
                string messageId = match.Groups["messageId"].Value;
                Assert.IsNotNull(messageId);

                string template = @"<s:Envelope xmlns:s=""http://www.w3.org/2003/05/soap-envelope"" xmlns:a=""http://www.w3.org/2005/08/addressing"">
                                    <s:Header>
                                        <a:Action s:mustUnderstand=""1"">http://schemas.microsoft.com/windows/management/2012/01/enrollment/IDiscoveryService/DiscoverResponse</a:Action>
                                        <ActivityId>{0}</ActivityId>
                                        <a:RelatesTo>{1}</a:RelatesTo> 
                                    </s:Header>
                                    <s:Body xmlns:xsi=""http://www.w3.org/2001/XMLSchema-instance"" xmlns:xsd=""http://www.w3.org/2001/XMLSchema"">
                                        <DiscoverResponse xmlns=""http://schemas.microsoft.com/windows/management/2012/01/enrollment"">
                                            <DiscoverResult>
                                                <AuthPolicy>OnPremise</AuthPolicy>
                                                <EnrollmentPolicyServiceUrl>{2}</EnrollmentPolicyServiceUrl>
                                                <EnrollmentServiceUrl>{3}</EnrollmentServiceUrl>
                                            </DiscoverResult>
                                        </DiscoverResponse>
                                    </s:Body>
                                    </s:Envelope>";

                string enrollmentUrl = "https://enterpriseenrollment.dynamit.com.au/EnrollmentServer/Service.svc";
                response = string.Format(template, System.Guid.NewGuid().ToString("D"), messageId, enrollmentUrl, enrollmentUrl);
            }

            Assert.IsNotNull(response);
        }

        [TestMethod]
        public void PolicyTest()
        {
            string xml = @"
<s:Envelope xmlns:s=""http://www.w3.org/2003/05/soap-envelope"" xmlns:a=""http://www.w3.org/2005/08/addressing"" xmlns:u=""http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd"" xmlns:wsse=""http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd"" xmlns:wst=""http://docs.oasis-open.org/ws-sx/ws-trust/200512"" xmlns:ac=""http://schemas.xmlsoap.org/ws/2006/12/authorization"">
	<s:Header>
		<a:Action s:mustUnderstand=""1"">http://schemas.microsoft.com/windows/pki/2009/01/enrollmentpolicy/IPolicy/GetPolicies</a:Action>
		<a:MessageID>urn:uuid:72048B64-0F19-448F-8C2E-B4C661860AA0</a:MessageID>
		<a:ReplyTo>
			<a:Address>http://www.w3.org/2005/08/addressing/anonymous</a:Address>
		</a:ReplyTo>
		<a:To s:mustUnderstand=""1"">https://enterpriseenrollment.dynamit.com.au/EnrollmentServer/Service.svc</a:To>
		<wsse:Security s:mustUnderstand=""1"">
			<wsse:UsernameToken u:Id=""uuid-cc1ccc1f-2fba-4bcf-b063-ffc0cac77917-4"">
				<wsse:Username>m@dynamit.com.au</wsse:Username>
				<wsse:Password wsse:Type=""http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-username-token-profile-1.0#PasswordText"">fhcuk</wsse:Password>
			</wsse:UsernameToken>
		</wsse:Security>
	</s:Header>
	<s:Body xmlns:xsi=""http://www.w3.org/2001/XMLSchema-instance"" xmlns:xsd=""http://www.w3.org/2001/XMLSchema"">
		<GetPolicies xmlns=""http://schemas.microsoft.com/windows/pki/2009/01/enrollmentpolicy"">
			<client>
				<lastUpdate xsi:nil=""true""/>
				<preferredLanguage xsi:nil=""true""/>
			</client>
			<requestFilter xsi:nil=""true""/>
		</GetPolicies>
	</s:Body>
</s:Envelope>";

            Regex messageIdPattern = new Regex(@"<a:MessageID>(?<messageId>[a-zA-Z0-9:-]+)</a:MessageID>", RegexOptions.Multiline);
            Regex usernameTokenPattern = new Regex(@"<wsse:UsernameToken u:Id=""(?<usernameToken>[a-zA-Z0-9-]+)"">", RegexOptions.Multiline);

            string messageId = messageIdPattern.Match(xml).Groups["messageId"].Value;
            string usernameToken = usernameTokenPattern.Match(xml).Groups["usernameToken"].Value;

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

            string response = string.Format(template, messageId);
        }

        [TestMethod]
        public void EnrollmentTest()
        {
            string xml = @"
<s:Envelope xmlns:s=""http://www.w3.org/2003/05/soap-envelope"" xmlns:a=""http://www.w3.org/2005/08/addressing"" xmlns:u=""http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd"" xmlns:wsse=""http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd"" xmlns:wst=""http://docs.oasis-open.org/ws-sx/ws-trust/200512"" xmlns:ac=""http://schemas.xmlsoap.org/ws/2006/12/authorization"">
	<s:Header>
		<a:Action s:mustUnderstand=""1"">http://schemas.microsoft.com/windows/pki/2009/01/enrollment/RST/wstep</a:Action>
		<a:MessageID>urn:uuid:0d5a1441-5891-453b-becf-a2e5f6ea3749</a:MessageID>
		<a:ReplyTo>
			<a:Address>http://www.w3.org/2005/08/addressing/anonymous</a:Address>
		</a:ReplyTo>
		<a:To s:mustUnderstand=""1"">https://enterpriseenrollment.dynamit.com.au/EnrollmentServer/Enrollment.svc</a:To>
		<wsse:Security s:mustUnderstand=""1"">
			<wsse:UsernameToken u:Id=""uuid-cc1ccc1f-2fba-4bcf-b063-ffc0cac77917-4"">
				<wsse:Username>m@dynamit.com.au</wsse:Username>
				<wsse:Password wsse:Type=""http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-username-token-profile-1.0#PasswordText"">fhcuk</wsse:Password>
			</wsse:UsernameToken>
		</wsse:Security>
	</s:Header>
	<s:Body>
		<wst:RequestSecurityToken>
			<wst:TokenType>http://schemas.microsoft.com/5.0.0.0/ConfigurationManager/Enrollment/DeviceEnrollmentToken</wst:TokenType>
			<wst:RequestType>http://docs.oasis-open.org/ws-sx/ws-trust/200512/Issue</wst:RequestType>
			<wsse:BinarySecurityToken ValueType=""http://schemas.microsoft.com/windows/pki/2009/01/enrollment#PKCS10"" 
                EncodingType=""http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd#base64binary"">MIICcTCCAV0CAQAwMDEuMCwGA1UEAxMlQjFDNDNDRDAtMTYyNC01RkJCLThFNTQtMzRDRjE3REZEM0ExADCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAKmxUQiA2yc1hiGoWS9h/6FoNpiCf8mm6FU3h+fKOKR2cFfc9wDV+FxW/VUPm9Tw1boqGFLg6vY71k1RJo3lqi3NOkJltCqnuXStNXgR/4+4hFQtULdUoWX5grTZY1Pg+zN7a/3X1MVMTD+R1f0+zHdlK1w6pWRVp5JP86v9OOSGtE9Eyy/RmhlaYCb8qK2U98WtGCTr55cv24fhVs56S7oTvWAn9VMyBucjXiAxLclyX1kD+m+KQpsvz7BUT7oI/015Xb/t84DthbFavNiBvZ0Z/vHbsCa37gSeSstVztzd7czxEjq4IQKj390zOqsaq4mGL/mWXhzKUNj/M9rU4d0CAwEAAaAAMAkGBSsOAwIdBQADggEBACFeOB6OBiC3mpyzU8R6cFNxG6QDEgbHWIo/6yfdwjueg/A68vjh/qw1kfDxi7P1NHS2wmZt1QgjdVCHEWU/tH0q8Cwm2JCI388ELqlY+j0jV9mhRgwv0oNUBQa+DoVsp+j10AbFKbx3+UVOpi6UQGlV3o/ekH5IfXKF+MY/1S+xDczcB6b5UlqhmHj+a52R+tSYmYg71pVg5LsJ4pKFFu+g6Qy5gXi3yVvIQRBqn03rQM26An24RMAxo5JpSfacI4ewDP5+Eai7xVZyWBXigh/PN+K53fxfVksCaiukGYvqGbad3nUUZwwxWVg7sLCTut56q0f1Z6xwJakBn0CMvVc=</wsse:BinarySecurityToken>
			<ac:AdditionalContext xmlns=""http://schemas.xmlsoap.org/ws/2006/12/authorization"">
				<ac:ContextItem Name=""DeviceType"">
					<ac:Value>WindowsPhone</ac:Value>
				</ac:ContextItem>
				<ac:ContextItem Name=""ApplicationVersion"">
					<ac:Value>8.0.10517.150</ac:Value>
				</ac:ContextItem>
			</ac:AdditionalContext>
		</wst:RequestSecurityToken>
	</s:Body>
</s:Envelope>
";

            Regex messageIdPattern = new Regex(@"<a:MessageID>(?<messageId>[a-zA-Z0-9:-]+)</a:MessageID>", RegexOptions.Multiline);
            Regex usernameTokenPattern = new Regex(@"<wsse:UsernameToken u:Id=""(?<usernameToken>[a-zA-Z0-9-]+)"">", RegexOptions.Multiline);
            Regex deviceTypePattern = new Regex(@"<ac:ContextItem Name=""DeviceType"">\s+<ac:Value>(?<deviceType>.*)</ac:Value>\s+</ac:ContextItem>", RegexOptions.Multiline);
            Regex applicationVersionPattern = new Regex(@"<ac:ContextItem Name=""ApplicationVersion"">\s+<ac:Value>(?<applicationVersion>.*)</ac:Value>\s+</ac:ContextItem>", RegexOptions.Multiline);
            Regex binaryCSR = new Regex(@"<wsse:BinarySecurityToken\b[^>]*>(?<securityToken>.*?)</wsse:BinarySecurityToken>", RegexOptions.Multiline);

            string messageId = messageIdPattern.Match(xml).Groups["messageId"].Value;
            string usernameToken = usernameTokenPattern.Match(xml).Groups["usernameToken"].Value;
            string deviceType = deviceTypePattern.Match(xml).Groups["deviceType"].Value;
            string applicationVersion = applicationVersionPattern.Match(xml).Groups["applicationVersion"].Value;
            string securityToken = binaryCSR.Match(xml).Groups["securityToken"].Value;

            Assert.IsNotNull(messageId);
            Assert.IsNotNull(usernameToken);
            Assert.IsNotNull(deviceType);
            Assert.IsNotNull(applicationVersion);
            Assert.IsNotNull(securityToken);

            string template = @"
<s:Envelope xmlns:s=""http://schemas.xmlsoap.org/soap/envelope/""
   xmlns:a=""http://www.w3.org/2005/08/addressing""
   xmlns:u=""http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd"">
   <s:Header>
      <Action s:mustUnderstand=""1"" >
         http://schemas.microsoft.com/windows/pki/2009/01/enrollment/RSTRC/wstep
      </Action>
      <a:RelatesTo>{0}</a:RelatesTo>
      <o:Security s:mustUnderstand=""1"" xmlns:o=""http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd"">Windows Phone 8 Enterprise Device Management Protocol v1.6
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
                  B64EncodedSampleBinarySecurityToken
               </BinarySecurityToken>
            </RequestedSecurityToken>
            <RequestID xmlns=""http://schemas.microsoft.com/windows/pki/2009/01/enrollment"">0
            </RequestID>
         </RequestSecurityTokenResponse>
      </RequestSecurityTokenResponseCollection>
   </s:Body>
</s:Envelope>
    ";
        }

        [TestMethod]
        public void BinarySecurityToken()
        {
            string input = @"<wsse:BinarySecurityToken ValueType=""http://schemas.microsoft.com/windows/pki/2009/01/enrollment#PKCS10"" 
                EncodingType=""http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd#base64binary"">MIICcTCCAV0CAQAwMDEuMCwGA1UEAxMlQjFDNDNDRDAtMTYyNC01RkJCLThFNTQtMzRDRjE3REZEM0ExADCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAKmxUQiA2yc1hiGoWS9h/6FoNpiCf8mm6FU3h+fKOKR2cFfc9wDV+FxW/VUPm9Tw1boqGFLg6vY71k1RJo3lqi3NOkJltCqnuXStNXgR/4+4hFQtULdUoWX5grTZY1Pg+zN7a/3X1MVMTD+R1f0+zHdlK1w6pWRVp5JP86v9OOSGtE9Eyy/RmhlaYCb8qK2U98WtGCTr55cv24fhVs56S7oTvWAn9VMyBucjXiAxLclyX1kD+m+KQpsvz7BUT7oI/015Xb/t84DthbFavNiBvZ0Z/vHbsCa37gSeSstVztzd7czxEjq4IQKj390zOqsaq4mGL/mWXhzKUNj/M9rU4d0CAwEAAaAAMAkGBSsOAwIdBQADggEBACFeOB6OBiC3mpyzU8R6cFNxG6QDEgbHWIo/6yfdwjueg/A68vjh/qw1kfDxi7P1NHS2wmZt1QgjdVCHEWU/tH0q8Cwm2JCI388ELqlY+j0jV9mhRgwv0oNUBQa+DoVsp+j10AbFKbx3+UVOpi6UQGlV3o/ekH5IfXKF+MY/1S+xDczcB6b5UlqhmHj+a52R+tSYmYg71pVg5LsJ4pKFFu+g6Qy5gXi3yVvIQRBqn03rQM26An24RMAxo5JpSfacI4ewDP5+Eai7xVZyWBXigh/PN+K53fxfVksCaiukGYvqGbad3nUUZwwxWVg7sLCTut56q0f1Z6xwJakBn0CMvVc=</wsse:BinarySecurityToken>";
            string token = @"MIICcTCCAV0CAQAwMDEuMCwGA1UEAxMlQjFDNDNDRDAtMTYyNC01RkJCLThFNTQtMzRDRjE3REZEM0ExADCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAKmxUQiA2yc1hiGoWS9h/6FoNpiCf8mm6FU3h+fKOKR2cFfc9wDV+FxW/VUPm9Tw1boqGFLg6vY71k1RJo3lqi3NOkJltCqnuXStNXgR/4+4hFQtULdUoWX5grTZY1Pg+zN7a/3X1MVMTD+R1f0+zHdlK1w6pWRVp5JP86v9OOSGtE9Eyy/RmhlaYCb8qK2U98WtGCTr55cv24fhVs56S7oTvWAn9VMyBucjXiAxLclyX1kD+m+KQpsvz7BUT7oI/015Xb/t84DthbFavNiBvZ0Z/vHbsCa37gSeSstVztzd7czxEjq4IQKj390zOqsaq4mGL/mWXhzKUNj/M9rU4d0CAwEAAaAAMAkGBSsOAwIdBQADggEBACFeOB6OBiC3mpyzU8R6cFNxG6QDEgbHWIo/6yfdwjueg/A68vjh/qw1kfDxi7P1NHS2wmZt1QgjdVCHEWU/tH0q8Cwm2JCI388ELqlY+j0jV9mhRgwv0oNUBQa+DoVsp+j10AbFKbx3+UVOpi6UQGlV3o/ekH5IfXKF+MY/1S+xDczcB6b5UlqhmHj+a52R+tSYmYg71pVg5LsJ4pKFFu+g6Qy5gXi3yVvIQRBqn03rQM26An24RMAxo5JpSfacI4ewDP5+Eai7xVZyWBXigh/PN+K53fxfVksCaiukGYvqGbad3nUUZwwxWVg7sLCTut56q0f1Z6xwJakBn0CMvVc=";

            Regex binarySecurityTokenPattern = new Regex(@"<wsse:BinarySecurityToken\b[^>]*>(?<securityToken>.*?)</wsse:BinarySecurityToken>", RegexOptions.Multiline);
            Match match = binarySecurityTokenPattern.Match(input);

            Assert.IsTrue(match.Success);
            Assert.AreEqual(token, match.Groups["securityToken"].Value);
        }

        [TestMethod]
        public void ExtractCertificateRequest()
        {
            string token = @"MIICcTCCAV0CAQAwMDEuMCwGA1UEAxMlQjFDNDNDRDAtMTYyNC01RkJCLThFNTQtMzRDRjE3REZEM0ExADCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAKmxUQiA2yc1hiGoWS9h/6FoNpiCf8mm6FU3h+fKOKR2cFfc9wDV+FxW/VUPm9Tw1boqGFLg6vY71k1RJo3lqi3NOkJltCqnuXStNXgR/4+4hFQtULdUoWX5grTZY1Pg+zN7a/3X1MVMTD+R1f0+zHdlK1w6pWRVp5JP86v9OOSGtE9Eyy/RmhlaYCb8qK2U98WtGCTr55cv24fhVs56S7oTvWAn9VMyBucjXiAxLclyX1kD+m+KQpsvz7BUT7oI/015Xb/t84DthbFavNiBvZ0Z/vHbsCa37gSeSstVztzd7czxEjq4IQKj390zOqsaq4mGL/mWXhzKUNj/M9rU4d0CAwEAAaAAMAkGBSsOAwIdBQADggEBACFeOB6OBiC3mpyzU8R6cFNxG6QDEgbHWIo/6yfdwjueg/A68vjh/qw1kfDxi7P1NHS2wmZt1QgjdVCHEWU/tH0q8Cwm2JCI388ELqlY+j0jV9mhRgwv0oNUBQa+DoVsp+j10AbFKbx3+UVOpi6UQGlV3o/ekH5IfXKF+MY/1S+xDczcB6b5UlqhmHj+a52R+tSYmYg71pVg5LsJ4pKFFu+g6Qy5gXi3yVvIQRBqn03rQM26An24RMAxo5JpSfacI4ewDP5+Eai7xVZyWBXigh/PN+K53fxfVksCaiukGYvqGbad3nUUZwwxWVg7sLCTut56q0f1Z6xwJakBn0CMvVc=";
            byte[] encoded = Convert.FromBase64String(token);
            var csr = new Pkcs10CertificationRequest(encoded);            
        }

        [TestMethod]
        public void ExtractRootCertificate()
        {
            string data = @"MIIEyjCCA7KgAwIBAgIQS8hmxuUrrYhLVVReCh3RfTANBgkqhkiG9w0BAQUFADBTMRMwEQYKCZImiZPyLGQBGRYDbmV0MRQwEgYKCZImiZPyLGQBGRYEc290aTEUMBIGCgmSJomT8ixkARkWBGNvcnAxEDAOBgNVBAMTB1NPVEkgQ0EwHhcNMTIwMTE2MTk1MTM0WhcNMTcwMTE2MjAwMDQ5WjBTMRMwEQYKCZImiZPyLGQBGRYDbmV0MRQwEgYKCZImiZPyLGQBGRYEc290aTEUMBIGCgmSJomT8ixkARkWBGNvcnAxEDAOBgNVBAMTB1NPVEkgQ0EwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQCd8TGCjDScOVqQ4ngEB3aikx+MVzHYIoZ9B6tzqn7PyNHHpxpE+2haQ6twoFlS66NcZE2lzJKrBE77QrwIJqc6FMVeUCSH+YF++8CCRXH8lHh+RBL3dd+KAZdB7nSnFGIXqzAgtQTfNQyCizqJw1lF/Y6mMmF5s8tCpOHKZU6hmGI8JHPWsFmJ8wCStzNwSanyX6D/c3PoSmmbYbATcinY3TzcsS7xfygGx54sBgA+moTKePIxb14E18z74DMT+l9yuM+AKJ/55nHMNRAZTAc3+8kv7asXf3Jf68XF2jV7bGReYUyopCwQf8nMfWv0ipHcJWDjuA4UHER6T4qy8jmzAgMBAAGjggGYMIIBlDATBgkrBgEEAYI3FAIEBh4EAEMAQTALBgNVHQ8EBAMCAYYwDwYDVR0TAQH/BAUwAwEB/zAdBgNVHQ4EFgQUNE64WDoy1W513V1PyTQuw4wIzdIwggEFBgNVHR8Egf0wgfowgfeggfSggfGGgbZsZGFwOi8vL0NOPVNPVEklMjBDQSxDTj1hbmFjb25kYSxDTj1DRFAsQ049UHVibGljJTIwS2V5JTIwU2VydmljZXMsQ049U2VydmljZXMsQ049Q29uZmlndXJhdGlvbixEQz1jb3JwLERDPXNvdGksREM9bmV0P2NlcnRpZmljYXRlUmV2b2NhdGlvbkxpc3Q/YmFzZT9vYmplY3RDbGFzcz1jUkxEaXN0cmlidXRpb25Qb2ludIY2aHR0cDovL2FuYWNvbmRhLmNvcnAuc290aS5uZXQvQ2VydEVucm9sbC9TT1RJJTIwQ0EuY3JsMBIGCSsGAQQBgjcVAQQFAgMBAAEwIwYJKwYBBAGCNxUCBBYEFJC0aZTkzToMB2cu9tGHd2BrAQ5kMA0GCSqGSIb3DQEBBQUAA4IBAQAr0ip9daVKbK94y2e85zsTmv2D1uJwampdiGIQYgGKzoIkMMkd79Qfzkuw+0b+7hqugFz4v8N+tzTEODUZuMCifhA4RV4dsZzCvj+9CkojPXBFjSWotLvl7MZtRt2vJRIzWFnl3Qk0EahagxDNEMJFV/RHApsBKBDzphmH3lui9L73OhgugXat6hODd2Dgz5DUd8fFX5SvsZkLPX8lK3yh4wSOYzqiKXgL5c4rqHeD6ZexGjELRXuGOUiZ2RM6lDhhusWm66PeGM3GJnR8ASEIbexEUX63BGWiziL6WzWpRdNghuf8wrhgyRQWMLj8YOoRk1Ig2XbtmXTjGmdPPghB";
            byte[] bytes = Convert.FromBase64String(data);
            System.Security.Cryptography.X509Certificates.X509Certificate cert = new System.Security.Cryptography.X509Certificates.X509Certificate(bytes);

            string hash = cert.GetCertHashString();
            
            string encoded = Convert.ToBase64String(cert.Export(System.Security.Cryptography.X509Certificates.X509ContentType.Cert));

            Assert.AreEqual(data, encoded);
            Assert.AreEqual("32B66F15F216972FFC30C8667436B41E36E85948", hash);
        }

        [TestMethod]
        public void ExtractClientCertificate()
        {
            string data = @"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";
            byte[] bytes = Convert.FromBase64String(data);
            System.Security.Cryptography.X509Certificates.X509Certificate cert = new System.Security.Cryptography.X509Certificates.X509Certificate(bytes);

            string hash = cert.GetCertHashString();

            string encoded = Convert.ToBase64String(cert.Export(System.Security.Cryptography.X509Certificates.X509ContentType.Cert));

            Assert.AreEqual(data, encoded);
            Assert.AreEqual("B3BDDAAC607007241B07AA4DF59781624CC6E0DD", hash);

            System.IO.File.WriteAllText(@"c:\ca\sample_clientcert.cer", ExportToPEM(cert));
        }

        public static string ExportToPEM(System.Security.Cryptography.X509Certificates.X509Certificate cert)
        {
            StringBuilder builder = new StringBuilder();

            builder.AppendLine("-----BEGIN CERTIFICATE-----");
            builder.AppendLine(Convert.ToBase64String(cert.Export(System.Security.Cryptography.X509Certificates.X509ContentType.Cert), Base64FormattingOptions.InsertLineBreaks));
            builder.AppendLine("-----END CERTIFICATE-----");

            return builder.ToString();
        }

    }
}
