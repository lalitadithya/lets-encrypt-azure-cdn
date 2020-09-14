using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using Certes;
using Certes.Acme;
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
                AcmeContext acmeContext;

                var secretHelper = new KeyVaultSecretHelper(certifcate.KeyVaultName);
                var acmeAccountPem = await secretHelper.GetSecretAsync("AcmeAccountKeyPem");
                if (string.IsNullOrWhiteSpace(acmeAccountPem))
                {
                    log.LogInformation("Acme Account not found.");
                    acmeContext = new AcmeContext(WellKnownServers.LetsEncryptV2);
                    await acmeContext.NewAccount(Environment.GetEnvironmentVariable("AcmeAccountEmail"), true);
                    var pem = acmeContext.AccountKey.ToPem();
                    log.LogInformation("Acme account created");
                    await secretHelper.SetSecretAsync("AcmeAccountKeyPem", pem);
                    log.LogInformation("Secret uploaded to key vault");
                }
                else
                {
                    acmeContext = new AcmeContext(WellKnownServers.LetsEncryptV2, KeyFactory.FromPem(acmeAccountPem));
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
                var order = await acmeContext.NewOrder(new string[] { certifcate.DomainName });
                var authorization = (await order.Authorizations()).First();
                log.LogInformation("Authorization created");

                string subscriptionId = Environment.GetEnvironmentVariable("SubscriptionId");

                var dnsHelper = new DnsHelper(subscriptionId);

                log.LogInformation("Fetching DNS authorization");
                var dnsChallenge = await authorization.Dns();
                var dnsText = acmeContext.AccountKey.DnsTxt(dnsChallenge.Token);
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
                var challengeResult = await dnsChallenge.Validate();
                while (challengeResult.Status.HasValue && challengeResult.Status.Value == Certes.Acme.Resource.ChallengeStatus.Pending)
                {
                    log.LogInformation("Validation is pending. Will retry in 1 second");
                    await Task.Delay(1 * 1000);
                    challengeResult = await dnsChallenge.Resource();
                }

                if (!challengeResult.Status.HasValue || challengeResult.Status.Value != Certes.Acme.Resource.ChallengeStatus.Valid)
                {
                    log.LogError("Unable to validate challenge - {0} - {1}", challengeResult.Error.Detail, string.Join('~', challengeResult.Error.Subproblems.Select(x => x.Detail)));
                    return;
                }

                log.LogInformation("Challenge validated");

                var privateKey = KeyFactory.NewKey(KeyAlgorithm.RS256);
                var cert = await order.Generate(new CsrInfo
                {
                    CountryName = certifcate.CertificateCountryName,
                    State = certifcate.CertificateState,
                    Locality = certifcate.CertificateLocality,
                    Organization = certifcate.CertificateOrganization,
                    OrganizationUnit = certifcate.CertificateOrganizationUnit,
                    CommonName = certifcate.DomainName,
                }, privateKey);
                var certPem = cert.ToPem();

                var pfxBuilder = cert.ToPfx(privateKey);
                string password = "abcd1234";
                var pfx = pfxBuilder.Build(domainName, password);

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
