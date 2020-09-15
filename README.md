# Lets Encrypt for Azure CDN 

Azure CDN provides free SSL certificates for all non-root/non-apex domains, but it does not provide free SSL certificates for root/apex domains like 'lalitadithya.com'. To get free SSL for root domains, we can make use of Let’s Encrypt, but we need to keep manually renewing the certificate every 3 months as there is no bot available that will take care of automatic renewal. This project aims to automate the provisioning and renewal of Let’s Encrypt SSL certificates for any domain on Azure CDN. 

This project makes use of an Azure functions app that will add the necessary DNS records in Azure DNS for the ACME DNS challenge validation, and it will talk to the CDN to update/enable the SSL certificate. The certificate along with the ACME account information will be stored in an Azure key vault for safe keeping. The function will be triggered every day close to midnight. 

## Features

1.	Renewal of SSL certificates for more than one website 
2.	Makes use of Azure Managed Identity – There is no need to hardcode any secrets in code
3.	Cheap to run – Will only cost less than 1 USD per month 
4.	All secrets and certificates are stored and read from a key vault making it extra secure

## Setup

1.	Create a new Azure function app for .NET Core using Windows
2.	Enable System Assigned Managed Identity for the function app created in step 1
3.	Provider contributor access to your Azure DNS Zone for the Managed Identity created in step 2
4.	Provider contributor access to your Azure CDN Profile for the Managed Identity created in step 2
5.	Provide secret and certificate get, update, and list permissions in your Azure Key Vault for the Managed Identity created in step 2
6.	Add the following configuration to your function app –
```
[
  {
    "name": "AcmeAccountEmail",
    "value": "***",
    "slotSetting": false
  },
  {
    "name": "CertificateDetails:[0]:CdnCustomDomainName",
    "value": "example-com",  // if the custom domain you have configured is example.com, then this value will be example-com
    "slotSetting": false
  },
  {
    "name": "CertificateDetails:[0]:CdnEndpointName",
    "value": "exampleblog",
    "slotSetting": false
  },
  {
    "name": "CertificateDetails:[0]:CdnProfileName",
    "value": "cdn-exampleblog",
    "slotSetting": false
  },
  {
    "name": "CertificateDetails:[0]:CdnResourceGroup",
    "value": "rg-example_blog",
    "slotSetting": false
  },
  {
    "name": "CertificateDetails:[0]:CertificateCountryName",
    "value": "IN",
    "slotSetting": false
  },
  {
    "name": "CertificateDetails:[0]:CertificateLocality",
    "value": "Bangalore",
    "slotSetting": false
  },
  {
    "name": "CertificateDetails:[0]:CertificateOrganization",
    "value": "example",
    "slotSetting": false
  },
  {
    "name": "CertificateDetails:[0]:CertificateOrganizationUnit",
    "value": "blog",
    "slotSetting": false
  },
  {
    "name": "CertificateDetails:[0]:CertificateState",
    "value": "Karnataka",
    "slotSetting": false
  },
  {
    "name": "CertificateDetails:[0]:DnsZoneName",
    "value": "example.com",
    "slotSetting": false
  },
  {
    "name": "CertificateDetails:[0]:DnsZoneResourceGroup",
    "value": "rg-dns",
    "slotSetting": false
  },
  {
    "name": "CertificateDetails:[0]:DomainName",
    "value": "example.com",
    "slotSetting": false
  },
  {
    "name": "CertificateDetails:[0]:KeyVaultName",
    "value": "kvexampleblog",
    "slotSetting": false
  },
  {
    "name": "CertificateDetails:[0]:KeyVaultResourceGroup",
    "value": "rg-example_blog",
    "slotSetting": false
  },
  {
    "name": "SubscriptionId",
    "value": "***",
    "slotSetting": false
  }
]
```
7.	Fork this repository 
8.	Download the publish profile for your functions app and add it as a secret with name AZURE_FUNCTIONAPP_PUBLISH_PROFILE
9.	Update the “AZURE_FUNCTIONAPP_NAME” to match your function name in “.github/workflows/build-deploy.yml”
10.	Wait for the GitHub action to complete the deployment
11.	Either wait till 23:17 hours UTC or manually trigger the function by POSTing to https://<<URL for function app created in step 1>>/admin/functions/ApplyOrRenewCertificate
12.	Wait for the certification propagation to complete 
13.	Verify that your website is now being served with a new certificate

