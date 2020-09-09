using Azure.Identity;
using Azure.Security.KeyVault.Certificates;
using System;
using System.Collections.Generic;
using System.Text;
using System.Threading.Tasks;

namespace LetsEncryptAzureCdn.Helpers
{
    public class KeyVaultCertificateHelper
    {
        private string keyVaultUri;
        private CertificateClient certificateClient;

        public KeyVaultCertificateHelper(string keyVaultName)
        {
            keyVaultUri = $"https://{keyVaultName}.vault.azure.net";
            certificateClient = new CertificateClient(new Uri(keyVaultUri), new VisualStudioCredential());
        }

        public async Task ImportCertificate(string certificateName, byte[] certificate, string password)
        {
            await certificateClient.ImportCertificateAsync(new ImportCertificateOptions(certificateName, certificate)
            {
                Password = password
            });
        }
    }
}
