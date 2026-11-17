// Fixtures for rules/opengrep/iac-bicep-secrets.yaml. Nothing here is deployed.
param location string = resourceGroup().location

// ruleid: labsec.bicep.output-exposes-secret
output storageKey string = storage.listKeys().keys[0].value

// ruleid: labsec.bicep.output-exposes-secret
output adminSecret string = adminPassword

// ok: labsec.bicep.output-exposes-secret
output storageId string = storage.id

// ok: labsec.bicep.output-exposes-secret
output secretName string = vault.name

// ruleid: labsec.bicep.secure-parameter-default
@secure()
param adminPassword string = 'Placeholder-not-a-real-value'

// ok: labsec.bicep.secure-parameter-default
@secure()
param dbPassword string = newGuid()

// ok: labsec.bicep.secure-parameter-default
@secure()
param apiToken string = ''

// ok: labsec.bicep.secure-parameter-default
param skuName string = 'Standard_LRS'

resource vm 'Microsoft.Compute/virtualMachines@2024-03-01' = {
  name: 'vm1'
  location: location
  properties: {
    osProfile: {
      // ruleid: labsec.bicep.admin-username-literal
      adminUsername: 'azureadmin'
    }
  }
}

resource vm2 'Microsoft.Compute/virtualMachines@2024-03-01' = {
  name: 'vm2'
  location: location
  properties: {
    osProfile: {
      // ok: labsec.bicep.admin-username-literal
      adminUsername: adminUsername
    }
  }
}

resource vm3 'Microsoft.Compute/virtualMachines@2024-03-01' = {
  name: 'vm3'
  location: location
  properties: {
    osProfile: {
      // ok: labsec.bicep.admin-username-literal
      adminUsername: '${prefix}-admin'
    }
  }
}
