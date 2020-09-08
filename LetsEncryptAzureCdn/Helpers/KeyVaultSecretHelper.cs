using Azure;
using Azure.Identity;
using Azure.Security.KeyVault.Secrets;
using System;
using System.Collections.Generic;
using System.Text;
using System.Threading.Tasks;

namespace LetsEncryptAzureCdn.Helpers
{
    public class KeyVaultSecretHelper
    {
        private string keyVaultUri;
        private SecretClient secretClient;

        public KeyVaultSecretHelper(string keyVaultName)
        {
            keyVaultUri = $"https://{keyVaultName}.vault.azure.net";
            secretClient = new SecretClient(new Uri(keyVaultUri), new VisualStudioCredential());
        }

        public async Task<string> GetSecretAsync(string secretName)
        {
            try
            {
                return (await secretClient.GetSecretAsync(secretName)).Value.Value;
            }
            catch (RequestFailedException e)
            {
                if (e.Status == 404)
                {
                    return null;
                }
                else
                {
                    throw;
                }
            }
        }

        public async Task SetSecretAsync(string secretName, string secretValue)
        {
            await secretClient.SetSecretAsync(secretName, secretValue);
        }
    }
}
