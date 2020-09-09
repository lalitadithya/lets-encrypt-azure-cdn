using Azure;
using Microsoft.Azure.Management.Dns;
using Microsoft.Azure.Management.Dns.Models;
using Microsoft.Azure.Services.AppAuthentication;
using Microsoft.Rest;
using Microsoft.Rest.Azure;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace LetsEncryptAzureCdn.Helpers
{
    public class DnsHelper
    {
        private readonly DnsManagementClient dnsManagementClient;

        public DnsHelper(string subscriptionId)
        {
            var azureServiceTokenProvider = new AzureServiceTokenProvider();
            var token = azureServiceTokenProvider.GetAccessTokenAsync("https://management.azure.com/").GetAwaiter().GetResult();
            dnsManagementClient = new DnsManagementClient(new TokenCredentials(token))
            {
                SubscriptionId = subscriptionId
            };
        }

        public async Task<IList<string>> FetchTxtRecordsAsync(string resourceGroupName, string dnsZoneName, string recordName)
        {
            try
            {
                var result = await dnsManagementClient.RecordSets.GetAsync(resourceGroupName, dnsZoneName, recordName, RecordType.TXT);
                if (result.TxtRecords.Count > 0)
                {
                    return result.TxtRecords[0].Value;
                }
                else
                {
                    return null;
                }
            }
            catch (CloudException e)
            {
                if (e.Body.Code == "NotFound")
                {
                    return null;
                }
                else
                {
                    throw;
                }
            }
        }

        public async Task CreateTxtRecord(string resourceGroupName, string dnsZoneName, string recordName, string recordValue)
        {
            await dnsManagementClient.RecordSets.CreateOrUpdateAsync(resourceGroupName, dnsZoneName, recordName, RecordType.TXT, new RecordSet
            {
                TxtRecords = new List<TxtRecord>()
                    {
                        new TxtRecord()
                        {
                            Value = new List<string> { recordValue }
                        }
                    },
                TTL = 3600
            });
        }
    }
}
