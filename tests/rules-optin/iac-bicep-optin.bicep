// Fixtures for rules/optin/iac-bicep-optin.yaml.
// ruleid: labsec.bicep.secret-parameter-not-secure
param adminPassword string

// ok: labsec.bicep.secret-parameter-not-secure
@secure()
param dbPassword string

// ok: labsec.bicep.secret-parameter-not-secure
param skuName string = 'Standard_LRS'
