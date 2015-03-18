using System;
using System.Collections;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Pkcs;
using Org.BouncyCastle.Pkix;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Utilities.Collections;
using Org.BouncyCastle.X509;
using Org.BouncyCastle.X509.Extension;
using Org.BouncyCastle.X509.Store;
using Org.BouncyCastle.Crypto.Prng;
using Org.BouncyCastle.Utilities;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Asn1;
using System.Text;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Utilities.IO.Pem;
using MSCert = System.Security.Cryptography.X509Certificates;
using System.Diagnostics;
using MSMDM.Core;
using NUnit.Framework;
using Org.BouncyCastle.Asn1.Pkcs;
using Shouldly;

namespace MSMDM.Test
{
    [TestFixture]
    public class BouncyCastleCACerts
    {
        private string CASubjectName = "CN=BouncyCastle CA";
        private string CACertFile = @"CA.cer";
        private string CAKeyFile = @"CA.pfx";

        private string CSRSubjectName = "CN=BouncyCastle CSR";
        private string CSRCertFile = @"CSR_Cert.cer";
        private string CSRKeyFile = @"CSR_Key.cer";

        const int strength = 2048;
        const string signatureAlgorithm = "SHA256WithRSA";

        [TestFixtureSetUp]
        public void Init()
        {

        }

        //
        // http://stackoverflow.com/questions/12679533/how-do-i-use-bouncycastle-to-generate-a-root-certificate-and-then-a-site-certifi
        //
        [Test]
        public void CreateCACert()
        {
            var randomGenerator = new CryptoApiRandomGenerator();
            var random = new SecureRandom(randomGenerator);

            var serialNumber = BigInteger.One;

            var certificateGenerator = new X509V3CertificateGenerator();

            certificateGenerator.SetSerialNumber(serialNumber);
            certificateGenerator.SetSignatureAlgorithm(signatureAlgorithm);

            var subjectDN = new X509Name(CASubjectName);
            var issuerDN = subjectDN;

            certificateGenerator.SetIssuerDN(issuerDN);
            certificateGenerator.SetSubjectDN(subjectDN);

            var notBefore = DateTime.UtcNow.Date;
            var notAfter = notBefore.AddYears(10);

            certificateGenerator.SetNotBefore(notBefore);
            certificateGenerator.SetNotAfter(notAfter);

            var keyGenerationParameters = new KeyGenerationParameters(random, strength);

            var keyPairGenerator = new RsaKeyPairGenerator();
            keyPairGenerator.Init(keyGenerationParameters);
            var subjectKeyPair = keyPairGenerator.GenerateKeyPair();

            certificateGenerator.SetPublicKey(subjectKeyPair.Public);

            // Self-signed, so it's all the same.
            var issuerKeyPair = subjectKeyPair;
            var issuerSerialNumber = serialNumber;

            var authorityKeyIdentifier =
                new AuthorityKeyIdentifier(
                    SubjectPublicKeyInfoFactory.CreateSubjectPublicKeyInfo(issuerKeyPair.Public),
                    new GeneralNames(new GeneralName(issuerDN)),
                    issuerSerialNumber);

            certificateGenerator.AddExtension(
                X509Extensions.AuthorityKeyIdentifier.Id, false, authorityKeyIdentifier);

            var subjectKeyIdentifier = new SubjectKeyIdentifier(SubjectPublicKeyInfoFactory.CreateSubjectPublicKeyInfo(subjectKeyPair.Public));
            certificateGenerator.AddExtension(X509Extensions.SubjectKeyIdentifier.Id, false, subjectKeyIdentifier);

            // This denotes a CA certificate
            certificateGenerator.AddExtension(X509Extensions.BasicConstraints.Id, true, new BasicConstraints(true));

            var certificate = certificateGenerator.Generate(subjectKeyPair.Private, random);
            var x509Cert = CryptoHelpers.ConvertCertificate(certificate, subjectKeyPair, random);
            CryptoHelpers.SaveCertificate(x509Cert, CAKeyFile);

            File.WriteAllText(CACertFile, CryptoHelpers.ExportToPEM(x509Cert));

            File.Exists(CACertFile).ShouldBe(true);
            File.Exists(CAKeyFile).ShouldBe(true);
        }

        [Test]
        [TestCase("CSR_Private.cer", "CSR_Request.cer")]
        public void CreateCertificateRequest(string csrPrivateFile, string csrRequestFile)
        {
            var randomGenerator = new CryptoApiRandomGenerator();
            var random = new SecureRandom(randomGenerator);
            var keyGenerationParameters = new KeyGenerationParameters(random, strength);

            var keyPairGenerator = new RsaKeyPairGenerator();
            keyPairGenerator.Init(keyGenerationParameters);

            AsymmetricCipherKeyPair subjectKeyPair = keyPairGenerator.GenerateKeyPair();
            var subjectDN = new X509Name(CSRSubjectName);

            Pkcs10CertificationRequest csr = new Pkcs10CertificationRequest(
                                                                  signatureAlgorithm,
                                                                  subjectDN,
                                                                  subjectKeyPair.Public,
                                                                  new DerSet(),
                                                                  subjectKeyPair.Private);

            File.WriteAllText(csrPrivateFile, CryptoHelpers.ExportToPEM(subjectKeyPair.Private));
            File.WriteAllText(csrRequestFile, CryptoHelpers.ExportToPEM(csr));
        }

        [Test]
        [TestCase("IIS_Request.cer", "IIS_Signed.cer")]
        [TestCase("CSR_Request.cer", "CSR_Signed.cer")]
        [TestCase("Test_Request.cer", "Test_Signed.cer")]
        public void SignRequestTest(string certRequestFile, string certSignedFile)
        {
            TextReader reader = File.OpenText(certRequestFile);
            PemReader pemReader = new PemReader(reader);

            var csr = new Pkcs10CertificationRequest(pemReader.ReadPemObject().Content);
            var csrInfo = csr.GetCertificationRequestInfo();
            
            RsaPublicKeyStructure publicKeyStructure = RsaPublicKeyStructure.GetInstance(csrInfo.SubjectPublicKeyInfo.GetPublicKey());
            RsaKeyParameters subjectPublicKey = new RsaKeyParameters(false, publicKeyStructure.Modulus, publicKeyStructure.PublicExponent);

            bool certIsOK = csr.Verify(subjectPublicKey);

            var issuerCertificate = CryptoHelpers.LoadCertificate(CAKeyFile, null);
            var issuerName = issuerCertificate.Subject;
            var issuerSerialNumber = new BigInteger(issuerCertificate.GetSerialNumber());
            var issuerKeyPair = DotNetUtilities.GetKeyPair(issuerCertificate.PrivateKey);

            var randomGenerator = new CryptoApiRandomGenerator();
            var random = new SecureRandom(randomGenerator);

            var serialNumber = new BigInteger("1");
            //            var serialNumber = BigIntegers.CreateRandomInRange(
            //                       BigInteger.One,
            //                       BigInteger.ValueOf(Int64.MaxValue),
            //                       random);

            var certificateGenerator = new X509V3CertificateGenerator();

            var issuerDN = new X509Name(issuerName);
            certificateGenerator.SetIssuerDN(issuerDN);

            certificateGenerator.SetSerialNumber(serialNumber);
            certificateGenerator.SetSignatureAlgorithm(signatureAlgorithm);

            certificateGenerator.SetSubjectDN(csrInfo.Subject);
            certificateGenerator.SetPublicKey(subjectPublicKey);

            // For Server Certificates Only
            var subjectAlternativeNames = new Asn1Encodable[]
                                                {
                                                    new GeneralName(GeneralName.DnsName, "msmdm.localhost"),
                                                    new GeneralName(GeneralName.DnsName, "*.localhost")
                                                };
            var subjectAlternativeNamesExtension = new DerSequence(subjectAlternativeNames);
            certificateGenerator.AddExtension(X509Extensions.SubjectAlternativeName.Id, false, subjectAlternativeNamesExtension);

            certificateGenerator.AddExtension(X509Extensions.KeyUsage.Id, false, new KeyUsage(KeyUsage.DigitalSignature));

            // For Server Certificates Only
            var usages = new[] { KeyPurposeID.IdKPServerAuth };
            certificateGenerator.AddExtension(X509Extensions.ExtendedKeyUsage.Id, false, new ExtendedKeyUsage(usages));

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

            certificateGenerator.AddExtension(X509Extensions.BasicConstraints.Id, true, new BasicConstraints(false));

            var certificate = certificateGenerator.Generate(issuerKeyPair.Private, random);

            certificate.Verify(issuerKeyPair.Public);
            File.WriteAllText(certSignedFile, CryptoHelpers.ExportToPEM(DotNetUtilities.ToX509Certificate(certificate)));
        }

        [Test]
        public void GetAllTheCerts()
        {
            MSCert.X509Store store = new MSCert.X509Store(MSCert.StoreName.My, MSCert.StoreLocation.CurrentUser);
            store.Open(MSCert.OpenFlags.ReadOnly);
            var certs = store.Certificates.Cast<MSCert.X509Certificate2>().ToList();

            Assert.IsNotNull(certs);
        }

        [Test]
        [TestCase("Client_Key.cer", "Client_Signed.cer")]
        public void IssueClientCert(string certKeyFile, string certSignedFile)
        {
            string subjectName = "CN=ClientCertificate";

            var issuerCertificate = CryptoHelpers.LoadCertificate(CAKeyFile, "");
            var issuerName = issuerCertificate.Subject;
            var issuerSerialNumber = new BigInteger(issuerCertificate.GetSerialNumber());
            var issuerKeyPair = DotNetUtilities.GetKeyPair(issuerCertificate.PrivateKey);

            var randomGenerator = new CryptoApiRandomGenerator();
            var random = new SecureRandom(randomGenerator);

            var keyGenerationParameters = new KeyGenerationParameters(random, strength);

            var keyPairGenerator = new RsaKeyPairGenerator();
            keyPairGenerator.Init(keyGenerationParameters);
            var subjectKeyPair = keyPairGenerator.GenerateKeyPair();

            var serialNumber = BigIntegers.CreateRandomInRange(
                       BigInteger.One,
                       BigInteger.ValueOf(Int64.MaxValue),
                       random);

            var certificateGenerator = new X509V3CertificateGenerator();

            certificateGenerator.SetSerialNumber(serialNumber);
            certificateGenerator.SetSignatureAlgorithm(signatureAlgorithm);

            var issuerDN = new X509Name(issuerName);
            certificateGenerator.SetIssuerDN(issuerDN);

            // Note: The subject can be omitted if you specify a subject alternative name (SAN).
            var subjectDN = new X509Name(subjectName);
            certificateGenerator.SetSubjectDN(subjectDN);

            // Our certificate needs valid from/to values.
            var notBefore = DateTime.UtcNow.Date;
            var notAfter = notBefore.AddYears(2);

            certificateGenerator.SetNotBefore(notBefore);
            certificateGenerator.SetNotAfter(notAfter);

            // The subject's public key goes in the certificate.
            certificateGenerator.SetPublicKey(subjectKeyPair.Public);

            // Add CA Reference to Chain
            var authorityKeyIdentifierExtension =
                  new AuthorityKeyIdentifier(SubjectPublicKeyInfoFactory.CreateSubjectPublicKeyInfo(issuerKeyPair.Public),
                      new GeneralNames(new GeneralName(issuerDN)),
                      issuerSerialNumber);
            certificateGenerator.AddExtension(X509Extensions.AuthorityKeyIdentifier.Id, false, authorityKeyIdentifierExtension);

            var subjectKeyIdentifierExtension =
                         new SubjectKeyIdentifier(
                             SubjectPublicKeyInfoFactory.CreateSubjectPublicKeyInfo(subjectKeyPair.Public));
            certificateGenerator.AddExtension(X509Extensions.SubjectKeyIdentifier.Id, false, subjectKeyIdentifierExtension);

            certificateGenerator.AddExtension(X509Extensions.BasicConstraints.Id, true, new BasicConstraints(false));

            var certificate = certificateGenerator.Generate(issuerKeyPair.Private, random);

            File.WriteAllText(certSignedFile, CryptoHelpers.ExportToPEM(DotNetUtilities.ToX509Certificate(certificate)));
            File.WriteAllText(certKeyFile, CryptoHelpers.ExportToPEM(subjectKeyPair.Private));
        }
    }
}
