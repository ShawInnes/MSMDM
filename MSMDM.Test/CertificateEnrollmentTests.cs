using System;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using System.Xml;
using System.Text.RegularExpressions;
using System.Net;

namespace MSMDM.Test
{

    [TestClass]
    public class CertificateEnrollmentTests
    {
        private TestContext _TestContextInstance;

        /// <summary>
        ///Gets or sets the test context which provides
        ///information about and functionality for the current test run.
        ///</summary>
        public TestContext TestContext
        {
            get
            {
                return _TestContextInstance;
            }
            set
            {
                _TestContextInstance = value;
            }
        }
        [TestMethod]
        public void Test()
        {
            //Perform the cert req
            //HttpWebRequest certfnsh = (HttpWebRequest)WebRequest.Create(strUriFnsh);
            //certfnsh.Method = "POST";
            //certfnsh.Headers.Add("Authorization", "Basic " + strEncCredentials);
            //certfnsh.ContentType = "application/x-www-form-urlencoded";

            //string strRequest = "Mode=newreq&CertRequest=" + HttpUtility.UrlEncode(txtCertReq.Text, Encoding.ASCII) + "&CertAttrib=CertificateTemplate%3A" + strCertificateTemplate + "%0D%0AUserAgent%3AMozilla%2F5.0+%28compatible%3B+MSIE+10.0%3B+Windows+NT+6.2%3B+WOW64%3B+Trident%2F6.0%3B+Touch%29%0D%0A&FriendlyType=CSR&ThumbPrint=&TargetStoreFlags=0&SaveCert=yes";

            //byte[] csrBytes = UTF8Encoding.UTF8.GetBytes(strRequest);

            //try
            //{
            //    Stream sw = certfnsh.GetRequestStream();
            //    sw.Write(csrBytes, 0, csrBytes.Length);
            //    sw.Close();

            //    WebResponse certfnshResponse = certfnsh.GetResponse();
            //    StreamReader sr = new StreamReader(certfnshResponse.GetResponseStream());

            //    string responsebody = sr.ReadToEnd().Trim();

            //    reqId = parseReqId(responsebody);

            //}
            //catch
            //{
            //}

            ////Fetch the cert
            //string strUriNew = "https://" + strCAAddress + "/certsrv/certnew.cer?ReqID=" + reqId + "&Enc=b64";
            //HttpWebRequest certnew = (HttpWebRequest)WebRequest.Create(strUriNew);
            //certnew.Method = "GET";
            //certnew.Headers.Add("Authorization", "Basic " + strEncCredentials);

            //try
            //{
            //    WebResponse certResponse = certnew.GetResponse();

            //    StreamReader sr = new StreamReader(certResponse.GetResponseStream());
            //    string responsebody = sr.ReadToEnd().Trim();

            //    txtCert.Text = responsebody;
            //}
            //catch
            //{
            //}
        }
    }
}
