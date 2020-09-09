using System;
using System.Threading.Tasks;
using Certes;
using Certes.Acme;
using LetsEncryptAzureCdn.Helpers;
using Microsoft.Azure.WebJobs;
using Microsoft.Extensions.Logging;

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
                acmeContext = new AcmeContext(WellKnownServers.LetsEncryptStagingV2);
                await acmeContext.NewAccount(Environment.GetEnvironmentVariable("AcmeAccountEmail"), true);
                var pem = acmeContext.AccountKey.ToPem();
                await secretHelper.SetSecretAsync("AcmeAccountKeyPem", pem);
            }
            else
            {
                acmeContext = new AcmeContext(WellKnownServers.LetsEncryptStagingV2, KeyFactory.FromPem(acmeAccountPem));
            }

            var domainNames = Environment.GetEnvironmentVariable("DomainName").Split(',');
            var order = await acmeContext.NewOrder(domainNames);
            var authorizations = await order.Authorizations();

            int i = 0;
            foreach (var authorization in authorizations)
            {
                var domainName = domainNames[i];
                if (domainName.StartsWith("*"))
                {
                    domainName = domainName.Substring(1);
                }

                var dnsChallenge = await authorization.Dns();
                var dnsText = acmeContext.AccountKey.DnsTxt(dnsChallenge.KeyAuthz);
                var dnsName = "_acme-challenge" + domainName;

            }
        }
    }
}
