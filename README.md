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
6.	Fork this repository 
7.	Download the publish profile for your functions app and add it as a secret with name AZURE_FUNCTIONAPP_PUBLISH_PROFILE
8.	Update the “AZURE_FUNCTIONAPP_NAME” to match your function name in “.github/workflows/build-deploy.yml”
9.	Wait for the GitHub action to complete the deployment
10.	Either wait till 23:17 hours UTC or manually trigger the function by POSTing to https://<<URL for function app created in step 1>>/admin/functions/ApplyOrRenewCertificate
11.	Wait for the certification propagation to complete 
12.	Verify that your website is now being served with a new certificate
