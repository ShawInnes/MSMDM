using System;
using System.Collections;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using Microsoft.VisualStudio.TestTools.UnitTesting;
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

namespace MSMDM.Test
{
    [TestClass]
    public class BouncyCastleCACerts
    {
        const int strength = 2048;
        const string signatureAlgorithm = "SHA256WithRSA";

        //
        // http://stackoverflow.com/questions/12679533/how-do-i-use-bouncycastle-to-generate-a-root-certificate-and-then-a-site-certifi
        //
        [TestMethod]
        public void CreateCACert()
        {
            const string subjectName = "CN=MDM CA";

            var randomGenerator = new CryptoApiRandomGenerator();
            var random = new SecureRandom(randomGenerator);

            var serialNumber = BigIntegers.CreateRandomInRange(
                                BigInteger.One, 
                                BigInteger.ValueOf(Int64.MaxValue), 
                                random);

            var certificateGenerator = new X509V3CertificateGenerator();

            certificateGenerator.SetSerialNumber(serialNumber);
            certificateGenerator.SetSignatureAlgorithm(signatureAlgorithm);

            var subjectDN = new X509Name(subjectName);
            var issuerDN = subjectDN;

            certificateGenerator.SetIssuerDN(issuerDN);
            certificateGenerator.SetSubjectDN(subjectDN);

            //var subjectAlternativeNames = new Asn1Encodable[]
            //                                    {
            //                                        new GeneralName(GeneralName.DnsName, "server"),
            //                                        new GeneralName(GeneralName.DnsName, "server.mydomain.com")
            //                                    };

            //var subjectAlternativeNamesExtension = new DerSequence(subjectAlternativeNames);
            //certificateGenerator.AddExtension(X509Extensions.SubjectAlternativeName.Id, false, subjectAlternativeNamesExtension);

            var notBefore = DateTime.UtcNow.Date;
            var notAfter = notBefore.AddYears(10);

            certificateGenerator.SetNotBefore(notBefore);
            certificateGenerator.SetNotAfter(notAfter);
            //var usages = new[] { KeyPurposeID.IdKPServerAuth };
            //certificateGenerator.AddExtension(
            //    X509Extensions.ExtendedKeyUsage.Id,
            //    false,
            //    new ExtendedKeyUsage(usages));


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

            certificateGenerator.AddExtension(X509Extensions.BasicConstraints.Id, true, new BasicConstraints(true));

            var certificate = certificateGenerator.Generate(issuerKeyPair.Private, random);

            var x509Cert = ConvertCertificate(certificate, subjectKeyPair, random);

            System.IO.File.WriteAllText(@"c:\CA\CACert.cer", ExportToPEM(x509Cert));
            WriteCertificate(x509Cert, @"c:\CA\CAKey.pfx");
        }

        [TestMethod]
        public void SignRequestTest()
        {
            string filename = @"c:\ca\enterpriseenrollment.dynamit.com.au.req";
            //byte[] der = System.IO.File.ReadAllBytes(filename);

            TextReader reader = File.OpenText(filename);
            PemReader pemReader = new PemReader(reader);

            var csr = new Pkcs10CertificationRequest(pemReader.ReadPemObject().Content);
            var csrInfo = csr.GetCertificationRequestInfo();

            RsaPublicKeyStructure publicKeyStructure = RsaPublicKeyStructure.GetInstance(csrInfo.SubjectPublicKeyInfo.GetPublicKey());
            RsaKeyParameters subjectPublicKey = new RsaKeyParameters(false, publicKeyStructure.Modulus, publicKeyStructure.PublicExponent);
            
            bool certIsOK = csr.Verify(subjectPublicKey);

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

            certificateGenerator.SetSubjectDN(csrInfo.Subject);
            certificateGenerator.SetPublicKey(subjectPublicKey);

            ///// For Server Certificates Only
            //var subjectAlternativeNames = new Asn1Encodable[]
            //                                    {
            //                                        new GeneralName(GeneralName.DnsName, "enterpriseenrollment"),
            //                                        new GeneralName(GeneralName.DnsName, "enterpriseenrollment.dynamit.com.au")
            //                                    };
            //var subjectAlternativeNamesExtension = new DerSequence(subjectAlternativeNames);
            //certificateGenerator.AddExtension(X509Extensions.SubjectAlternativeName.Id, false, subjectAlternativeNamesExtension);

            ///// For Server Certificates Only
            //var usages = new[] { KeyPurposeID.IdKPServerAuth };
            //certificateGenerator.AddExtension(X509Extensions.ExtendedKeyUsage.Id, false, new ExtendedKeyUsage(usages));

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
            string outputFilename = string.Format(@"c:\CA\Signed-{0}.cer", certificate.SerialNumber.ToString());
            System.IO.File.WriteAllText(outputFilename, ExportToPEM(DotNetUtilities.ToX509Certificate(certificate)));
        }

        [TestMethod]
        public void GetAllTheCerts()
        {
            MSCert.X509Store store = new MSCert.X509Store(MSCert.StoreName.My, MSCert.StoreLocation.CurrentUser);
            store.Open(MSCert.OpenFlags.ReadOnly);
            MSCert.X509Certificate2 cert = store.Certificates.Cast<MSCert.X509Certificate2>().SingleOrDefault(p => p.SerialNumber == "73920EFD4D9F1D3F7AAF");

            Assert.IsNotNull(cert);
        }

        [TestMethod]
        public void IssueClientCert()
        {
            string subjectName = "CN=Test Certificate Creation";

            //var issuerCertificate = LoadCertificate(@"c:\ca\CAKey.pfx", null);
            var issuerCertificate = LoadCertificate(@"c:\ca\mypfx.pfx", "");
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
            
            string outputFilename = string.Format(@"c:\CA\Issued-{0}.cer", certificate.SerialNumber.ToString());
            System.IO.File.WriteAllText(outputFilename, ExportToPEM(DotNetUtilities.ToX509Certificate(certificate)));
        }

        string[] certs = new string[] { };

        [TestMethod]
        public void ReadIssued()
        {
            string filename = @"c:\ca\Issued-1715698592009644032.cer";

            X509CertificateParser parser = new X509CertificateParser();
            PkixCertPathBuilder builder = new PkixCertPathBuilder();

            // Separate root from itermediate
            var intermediateCerts = new List<Org.BouncyCastle.X509.X509Certificate>();
            HashSet rootCerts = new HashSet();

            foreach (string certString in certs)
            {
                StringReader StringReader = new StringReader(certString);
                PemReader pem = new PemReader(StringReader);
                var cert = parser.ReadCertificate(pem.ReadPemObject().Content);

                // Separate root and subordinate certificates
                if (cert.IssuerDN.Equivalent(cert.SubjectDN))
                {
                    rootCerts.Add(new TrustAnchor(cert, null));
                }
                else
                {
                    intermediateCerts.Add(cert);
                    Debug.WriteLine("Leaf ->");
                }

                Debug.WriteLine("\tCertificate: " + cert.SubjectDN);
                Debug.WriteLine("\tIssuer: " + cert.SubjectDN);
            }

            TextReader reader = File.OpenText(filename);
            PemReader pemReader = new PemReader(reader);
            var primary = parser.ReadCertificate(pemReader.ReadPemObject().Content);

            // Create chain for this certificate
            X509CertStoreSelector holder = new X509CertStoreSelector();
            holder.Certificate = primary;

            // WITHOUT THIS LINE BUILDER CANNOT BEGIN BUILDING THE CHAIN
            intermediateCerts.Add(holder.Certificate);

            PkixBuilderParameters builderParams = new PkixBuilderParameters(rootCerts, holder);
            builderParams.IsRevocationEnabled = false;

            X509CollectionStoreParameters intermediateStoreParameters = new X509CollectionStoreParameters(intermediateCerts);

            builderParams.AddStore(X509StoreFactory.Create("Certificate/Collection", intermediateStoreParameters));

            PkixCertPathBuilderResult result = builder.Build(builderParams);

            //return result.CertPath.Certificates.Cast<Org.BouncyCastle.X509.X509Certificate>();

        }

        private static MSCert.X509Certificate2 LoadCertificate(string issuerFileName, string password)
        {
            // We need to pass 'Exportable', otherwise we can't get the private key.
            var issuerCertificate = new MSCert.X509Certificate2(issuerFileName, password, MSCert.X509KeyStorageFlags.Exportable);
            return issuerCertificate;
        }

        /// <summary>
        /// Export a certificate to a PEM format string
        /// </summary>
        /// <param name="cert">The certificate to export</param>
        /// <returns>A PEM encoded string</returns>
        public static string ExportToPEM(MSCert.X509Certificate cert)
        {
            StringBuilder builder = new StringBuilder();

            builder.AppendLine("-----BEGIN CERTIFICATE-----");
            builder.AppendLine(Convert.ToBase64String(cert.Export(MSCert.X509ContentType.Cert), Base64FormattingOptions.InsertLineBreaks));
            builder.AppendLine("-----END CERTIFICATE-----");

            return builder.ToString();
        }

        private static void WriteCertificate(MSCert.X509Certificate2 certificate, string outputFileName)
        {
            // This password is the one attached to the PFX file. Use 'null' for no password.
            string password = null;
            var bytes = certificate.Export(MSCert.X509ContentType.Pfx, password);
            File.WriteAllBytes(outputFileName, bytes);
        }

        private static MSCert.X509Certificate2 ConvertCertificate(X509Certificate certificate,
                                                          AsymmetricCipherKeyPair subjectKeyPair,
                                                          SecureRandom random)
        {
            // Now to convert the Bouncy Castle certificate to a .NET certificate.
            // See http://web.archive.org/web/20100504192226/http://www.fkollmann.de/v2/post/Creating-certificates-using-BouncyCastle.aspx
            // ...but, basically, we create a PKCS12 store (a .PFX file) in memory, and add the public and private key to that.
            var store = new Pkcs12Store();

            // What Bouncy Castle calls "alias" is the same as what Windows terms the "friendly name".
            string friendlyName = certificate.SubjectDN.ToString();

            // Add the certificate.
            var certificateEntry = new X509CertificateEntry(certificate);
            store.SetCertificateEntry(friendlyName, certificateEntry);

            // Add the private key.
            store.SetKeyEntry(friendlyName, new AsymmetricKeyEntry(subjectKeyPair.Private), new[] { certificateEntry });

            // Convert it to an X509Certificate2 object by saving/loading it from a MemoryStream.
            // It needs a password. Since we'll remove this later, it doesn't particularly matter what we use.
            const string password = "password";
            var stream = new MemoryStream();
            store.Save(stream, password.ToCharArray(), random);

            var convertedCertificate =
                new MSCert.X509Certificate2(stream.ToArray(),
                                     password,
                                     MSCert.X509KeyStorageFlags.PersistKeySet 
                                        | MSCert.X509KeyStorageFlags.Exportable);

            return convertedCertificate;
        }
    }
}
