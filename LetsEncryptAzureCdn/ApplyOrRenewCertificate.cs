using System;
using System.Collections.Generic;
using System.Threading.Tasks;
using LetsEncryptAzureCdn.Helpers;
using LetsEncryptAzureCdn.Models;
using Microsoft.Azure.WebJobs;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging;

namespace LetsEncryptAzureCdn
{
    public static class ApplyOrRenewCertificate
    {
        [FunctionName("ApplyOrRenewCertificate")]
        public static async Task Run([TimerTrigger("0 */5 * * * *")] TimerInfo myTimer, ILogger log, ExecutionContext executionContext)
        {
            log.LogInformation($"C# Timer trigger function executed at: {DateTime.Now}");

            string subscriptionId = Environment.GetEnvironmentVariable("SubscriptionId");
            var config = new ConfigurationBuilder()
                                .SetBasePath(executionContext.FunctionAppDirectory)
                                .AddJsonFile("local.settings.json", optional: true, reloadOnChange: true)
                                .AddEnvironmentVariables()
                                .Build();

            var certificateDetails = new List<CertificateRenewalInputModel>();
            config.GetSection("CertificateDetails").Bind(certificateDetails);

            foreach (var certifcate in certificateDetails)
            {
                log.LogInformation($"Processing certificate - {certifcate.DomainName}");
                var acmeHelper = new AcmeHelper(log);

                var secretHelper = new KeyVaultSecretHelper(certifcate.KeyVaultName);
                var acmeAccountPem = await secretHelper.GetSecretAsync("AcmeAccountKeyPem");
                if (string.IsNullOrWhiteSpace(acmeAccountPem))
                {
                    log.LogInformation("Acme Account not found.");
                    string pem = await acmeHelper.InitWithNewAccountAsync(Environment.GetEnvironmentVariable("AcmeAccountEmail"));
                    log.LogInformation("Acme account created");
                    await secretHelper.SetSecretAsync("AcmeAccountKeyPem", pem);
                    log.LogInformation("Secret uploaded to key vault");
                }
                else
                {
                    acmeHelper.InitWithExistingAccount(acmeAccountPem);
                }

                var certificateHelper = new KeyVaultCertificateHelper(certifcate.KeyVaultName);

                string domainName = certifcate.DomainName;
                if (domainName.StartsWith("*"))
                {
                    domainName = domainName.Substring(1);
                }
                log.LogInformation($"Calculated domain name is {domainName}");

                string keyVaultCertificateName = domainName.Replace(".", "");
                log.LogInformation($"Getting expiry for {keyVaultCertificateName} in Key Vault certifictes");
                var certificateExpiry = await certificateHelper.GetCertificateExpiryAsync(keyVaultCertificateName);
                if (certificateExpiry.HasValue && certificateExpiry.Value.Subtract(DateTime.UtcNow).TotalDays > 7)
                {
                    log.LogInformation("No certificates to renew.");
                    continue;
                }

                log.LogInformation("Creating order for certificates");
                await acmeHelper.CreateOrderAsync(certifcate.DomainName);
                log.LogInformation("Authorization created");

                var dnsHelper = new DnsHelper(subscriptionId);

                log.LogInformation("Fetching DNS authorization");
                var dnsText = await acmeHelper.GetDnsAuthorizationTextAsync();
                var dnsName = ("_acme-challenge." + domainName).Replace("." + certifcate.DnsZoneName, "").Trim();
                log.LogInformation($"Got DNS challenge {dnsText} for {dnsName}");

                var txtRecords = await dnsHelper.FetchTxtRecordsAsync(certifcate.DnsZoneResourceGroup, certifcate.DnsZoneName, dnsName);

                if (txtRecords == null || !txtRecords.Contains(dnsText))
                {
                    await dnsHelper.CreateTxtRecord(certifcate.DnsZoneResourceGroup, certifcate.DnsZoneName, dnsName, dnsText);
                    log.LogInformation("Created DNS TXT records");
                }

                log.LogInformation("Waiting 60 seconds for DNS propagation");
                await Task.Delay(60 * 1000);

                log.LogInformation("Validating DNS challenge");
                await acmeHelper.ValidateDnsAuthorizationAsync();
                log.LogInformation("Challenge validated");

                string password = Guid.NewGuid().ToString();
                var pfx = await acmeHelper.GetPfxCertificateAsync(password, certifcate.CertificateCountryName, certifcate.CertificateState, certifcate.CertificateLocality,
                    certifcate.CertificateOrganization, certifcate.CertificateOrganizationUnit, certifcate.DomainName, domainName);
                log.LogInformation("Certificate built");

                (string certificateName, string certificateVerison) = await certificateHelper.ImportCertificate(keyVaultCertificateName, pfx, password);

                log.LogInformation("Certificate imported");

                var cdnHelper = new CdnHelper(subscriptionId);

                await cdnHelper.EnableHttpsForCustomDomain(certifcate.CdnResourceGroup, certifcate.CdnProfileName,
                    certifcate.CdnEndpointName, certifcate.CdnCustomDomainName, certificateName, certificateVerison, certifcate.KeyVaultName);

                log.LogInformation("HTTPS enabling started");
            }
        }
    }
}
