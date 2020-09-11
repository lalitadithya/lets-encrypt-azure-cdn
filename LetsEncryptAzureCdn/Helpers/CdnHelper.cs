using Microsoft.Azure.Management.Cdn;
using Microsoft.Azure.Management.Cdn.Models;
using Microsoft.Azure.Services.AppAuthentication;
using Microsoft.Rest;
using System;
using System.Collections.Generic;
using System.Text;
using System.Threading.Tasks;

namespace LetsEncryptAzureCdn.Helpers
{
    public class CdnHelper
    {
        private readonly CdnManagementClient cdnManagementClient;
        private readonly string subscriptionId;

        public CdnHelper(string subscriptionId)
        {
            var azureServiceTokenProvider = new AzureServiceTokenProvider();
            var token = azureServiceTokenProvider.GetAccessTokenAsync("https://management.azure.com/").GetAwaiter().GetResult();
            cdnManagementClient = new CdnManagementClient(new TokenCredentials(token))
            {
                SubscriptionId = subscriptionId
            };
            this.subscriptionId = subscriptionId;
        }

        public async Task EnableHttpsForCustomDomain(string resourceGroupName, string cdnProfileName, string cdnEndpointName,
            string cdnCustomDomainName, string certificateName, string certificateVerison, string keyVaultName)
        {
            await cdnManagementClient.CustomDomains.EnableCustomHttpsAsync(resourceGroupName, cdnProfileName, cdnEndpointName,
                cdnCustomDomainName, new UserManagedHttpsParameters
                {
                    CertificateSourceParameters = new KeyVaultCertificateSourceParameters
                    {
                        SecretName = certificateName,
                        SecretVersion = certificateVerison,
                        ResourceGroupName = resourceGroupName,
                        SubscriptionId = subscriptionId,
                        VaultName = keyVaultName
                    },
                    MinimumTlsVersion = MinimumTlsVersion.TLS12,
                    ProtocolType = "ServerNameIndication"
                });
        }
    }
}
