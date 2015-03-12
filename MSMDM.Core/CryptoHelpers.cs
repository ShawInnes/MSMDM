using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Pkcs;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.X509;
using MSCert = System.Security.Cryptography.X509Certificates;

namespace MSMDM.Core
{
    public static class CryptoHelpers
    {
        public static string ExportToPEM(object csr)
        {
            string result;
            using (MemoryStream mem = new MemoryStream())
            {
                StreamWriter writer = new StreamWriter(mem);
                Org.BouncyCastle.OpenSsl.PemWriter pem = new Org.BouncyCastle.OpenSsl.PemWriter(writer);
                pem.WriteObject(csr);
                pem.Writer.Flush();

                StreamReader reader = new StreamReader(mem);
                mem.Position = 0;
                result = reader.ReadToEnd();
            }

            return result;
        }

        public static MSCert.X509Certificate2 LoadCertificate(string issuerFileName, string password)
        {
            // We need to pass 'Exportable', otherwise we can't get the private key.
            var issuerCertificate = new MSCert.X509Certificate2(issuerFileName, password, MSCert.X509KeyStorageFlags.Exportable);
            return issuerCertificate;
        }

        public static void SaveCertificate(MSCert.X509Certificate2 certificate, string outputFileName)
        {
            // This password is the one attached to the PFX file. Use 'null' for no password.
            string password = null;
            var bytes = certificate.Export(MSCert.X509ContentType.Pfx, password);
            File.WriteAllBytes(outputFileName, bytes);
        }

        public static MSCert.X509Certificate2 ConvertCertificate(X509Certificate certificate,
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

        public static string EncodeToBase64(string toEncode)
        {
            var toEncodeAsBytes = Encoding.ASCII.GetBytes(toEncode);
            var returnValue = Convert.ToBase64String(toEncodeAsBytes);
            return returnValue;
        }
    }
}
