using System;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using System.Xml;
using System.Text.RegularExpressions;
using System.Net;

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

            string messageId = messageIdPattern.Match(xml).Groups["messageId"].Value;
            string usernameToken = usernameTokenPattern.Match(xml).Groups["usernameToken"].Value;
            string deviceType = deviceTypePattern.Match(xml).Groups["deviceType"].Value;
            string applicationVersion = applicationVersionPattern.Match(xml).Groups["applicationVersion"].Value;

            Assert.IsNotNull(messageId);
            Assert.IsNotNull(usernameToken);
            Assert.IsNotNull(deviceType);
            Assert.IsNotNull(applicationVersion);

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
    }
}
