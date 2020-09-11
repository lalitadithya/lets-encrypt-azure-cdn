using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using Certes;
using Certes.Acme;
using LetsEncryptAzureCdn.Helpers;
using Microsoft.Azure.Management.Cdn;
using Microsoft.Azure.Management.Cdn.Models;
using Microsoft.Azure.Services.AppAuthentication;
using Microsoft.Azure.WebJobs;
using Microsoft.Extensions.Logging;
using Microsoft.Rest;

namespace LetsEncryptAzureCdn
{
    public static class ApplyOrRenewCertificate
    {
        [FunctionName("ApplyOrRenewCertificate")]
        public static async Task Run([TimerTrigger("0 */5 * * * *")] TimerInfo myTimer, ILogger log)
        {
            log.LogInformation($"C# Timer trigger function executed at: {DateTime.Now}");

            AcmeContext acmeContext;

            var secretHelper = new KeyVaultSecretHelper(Environment.GetEnvironmentVariable("KeyVaultName"));
            var acmeAccountPem = await secretHelper.GetSecretAsync("AcmeAccountKeyPem");
            if (string.IsNullOrWhiteSpace(acmeAccountPem))
            {
                acmeContext = new AcmeContext(WellKnownServers.LetsEncryptV2);
                await acmeContext.NewAccount(Environment.GetEnvironmentVariable("AcmeAccountEmail"), true);
                var pem = acmeContext.AccountKey.ToPem();
                await secretHelper.SetSecretAsync("AcmeAccountKeyPem", pem);
            }
            else
            {
                acmeContext = new AcmeContext(WellKnownServers.LetsEncryptV2, KeyFactory.FromPem(acmeAccountPem));
            }

            string keyVaultName = Environment.GetEnvironmentVariable("KeyVaultName");
            var certificateHelper = new KeyVaultCertificateHelper(keyVaultName);

            var domainNames = Environment.GetEnvironmentVariable("DomainName").Split(',');
            List<string> domainNameCertificateToRenew = new List<string>();
            for (int j = 0; j < domainNames.Length; j++)
            {
                string domainName = domainNames[j];
                if (domainName.StartsWith("*"))
                {
                    domainName = domainName.Substring(1);
                }

                string keyVaultCertificateName = domainName.Replace(".", "");
                var certificateExpiry = await certificateHelper.GetCertificateExpiryAsync(keyVaultCertificateName);
                if ((certificateExpiry.HasValue && certificateExpiry.Value.Subtract(DateTime.UtcNow).TotalDays <= 7) || !certificateExpiry.HasValue)
                {
                    domainNameCertificateToRenew.Add(domainNames[j]);
                }
            }

            if (!domainNameCertificateToRenew.Any())
            {
                log.LogInformation("No certificates to renew.");
                return;
            }

            domainNames = domainNameCertificateToRenew.ToArray();

            var order = await acmeContext.NewOrder(domainNames);
            var authorizations = await order.Authorizations();

            string subscriptionId = Environment.GetEnvironmentVariable("SubscriptionId");
            string resourceGroupName = Environment.GetEnvironmentVariable("DnsZoneResourceGroup");
            string dnsZoneName = Environment.GetEnvironmentVariable("DnsZoneName");

            var dnsHelper = new DnsHelper(subscriptionId);
            var cdnHelper = new CdnHelper(subscriptionId);

            int i = 0;
            foreach (var authorization in authorizations)
            {
                var domainName = domainNames[i];
                if (domainName.StartsWith("*"))
                {
                    domainName = domainName.Substring(1);
                }

                string keyVaultCertificateName = domainName.Replace(".", "");


                var dnsChallenge = await authorization.Dns();
                var dnsText = acmeContext.AccountKey.DnsTxt(dnsChallenge.Token);
                var dnsName = ("_acme-challenge." + domainName).Replace("." + dnsZoneName, "").Trim();

                var txtRecords = await dnsHelper.FetchTxtRecordsAsync(resourceGroupName, dnsZoneName, dnsName);

                if (txtRecords == null || !txtRecords.Contains(dnsText))
                {
                    await dnsHelper.CreateTxtRecord(resourceGroupName, dnsZoneName, dnsName, dnsText);
                }

                await Task.Delay(60 * 1000);

                var challengeResult = await dnsChallenge.Validate();
                while (challengeResult.Status.HasValue && challengeResult.Status.Value == Certes.Acme.Resource.ChallengeStatus.Pending)
                {
                    await Task.Delay(1 * 1000);
                    challengeResult = await dnsChallenge.Resource();
                }

                if (!challengeResult.Status.HasValue || challengeResult.Status.Value != Certes.Acme.Resource.ChallengeStatus.Valid)
                {
                    log.LogError("Unable to validate challenge - {0} - {1}", challengeResult.Error.Detail, string.Join('~', challengeResult.Error.Subproblems.Select(x => x.Detail)));
                    return;
                }

                var privateKey = KeyFactory.NewKey(KeyAlgorithm.RS256);
                var cert = await order.Generate(new CsrInfo
                {
                    CountryName = Environment.GetEnvironmentVariable("CountryName"),
                    State = Environment.GetEnvironmentVariable("State"),
                    Locality = Environment.GetEnvironmentVariable("Locality"),
                    Organization = Environment.GetEnvironmentVariable("Organization"),
                    OrganizationUnit = Environment.GetEnvironmentVariable("OrganizationUnit"),
                    CommonName = domainName,
                }, privateKey);
                var certPem = cert.ToPem();

                var pfxBuilder = cert.ToPfx(privateKey);
                string password = "abcd1234";
                var pfx = pfxBuilder.Build(domainName, password);

                (string certificateName, string certificateVerison) = await certificateHelper.ImportCertificate(keyVaultCertificateName, pfx, password);

                await cdnHelper.EnableHttpsForCustomDomain(Environment.GetEnvironmentVariable("CdnResourceGroup"), Environment.GetEnvironmentVariable("CdnProfileName"),
                    Environment.GetEnvironmentVariable("CdnEndpointName"), Environment.GetEnvironmentVariable("CdnCustomDomainName"),
                    certificateName, certificateVerison, keyVaultName);
            }
        }
    }
}
