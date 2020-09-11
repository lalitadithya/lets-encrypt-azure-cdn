namespace LetsEncryptAzureCdn.Models
{
    public class CertificateRenewalInputModel
    {
        public string DnsZoneResourceGroup { get; set; }
        public string DnsZoneName { get; set; }

        public string DomainName { get; set; }
        public string CertificateCountryName { get; set; }
        public string CertificateState { get; set; }
        public string CertificateLocality { get; set; }
        public string CertificateOrganization { get; set; }
        public string CertificateOrganizationUnit { get; set; }

        public string CdnProfileName { get; set; }
        public string CdnEndpointName { get; set; }
        public string CdnCustomDomainName { get; set; }
        public string CdnResourceGroup { get; set; }

        public string KeyVaultName { get; set; }
        public string KeyVaultResourceGroup { get; set; }
    }
}
