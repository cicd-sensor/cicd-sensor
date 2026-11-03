// cicd-sensor-manager on Azure Container Apps, storing logs in Azure Blob Storage.
//
// Creates: Log Analytics workspace, storage account + container, user-assigned
// managed identity (Storage Blob Data Contributor on the account), Container Apps
// environment, and the manager Container App.
//
// Deploy:
//   az deployment group create -g <rg> -f main.bicep \
//     -p managerImage=<registry>/cicd-sensor-manager:<tag> managerToken=sk_cs_...

targetScope = 'resourceGroup'

@description('Base name used to derive resource names.')
@minLength(3)
@maxLength(16)
param baseName string = 'cicdsensor'

param location string = resourceGroup().location

@description('cicd-sensor-manager container image (built from Dockerfile.manager).')
param managerImage string

@description('Registry server of a private image (e.g. myacr.azurecr.io). Leave empty for a public image.')
param registryServer string = ''

@description('Resource ID of the Azure Container Registry used for AcrPull. Leave empty when not using ACR with managed identity.')
param acrResourceId string = ''

@description('Manager bearer token (sk_cs_..., from `cicd-sensorctl token generate`).')
@secure()
param managerToken string

@description('Optional second token for rotation overlap.')
@secure()
param managerToken2 string = ''

@description('Blob container that receives the logs.')
param logContainerName string = 'cicd-sensor-logs'

@description('Blob name prefix inside the container.')
param logPrefix string = 'cicd-sensor/'

@description('Treat terminate rules as detect rules (collection-only rollout).')
param monitorMode bool = false

@minValue(1)
param minReplicas int = 1

@minValue(1)
param maxReplicas int = 3

@description('Days to retain log blobs. 0 disables lifecycle deletion.')
@minValue(0)
param logRetentionDays int = 0

var suffix = uniqueString(resourceGroup().id)
var storageAccountName = toLower('${take(replace(baseName, '-', ''), 11)}${take(suffix, 12)}')
var useRegistry = !empty(registryServer)
var blobEndpoint = 'https://${storageAccountName}.blob.${environment().suffixes.storage}'

var managerConfig = join([
  'bind:'
  '  address: "0.0.0.0"'
  '  port: 8080'
  'monitor_mode: ${monitorMode}'
  'sinks:'
  '  azure-blob:'
  '    type: azure_blob'
  '    uri: ${blobEndpoint}/${logContainerName}/${logPrefix}'
  'logs:'
  '  summary:'
  '    sink: azure-blob'
  '  detection:'
  '    sink: azure-blob'
  '  runtime_event:'
  '    sink: azure-blob'
  ''
], '\n')

var storageBlobDataContributor = 'ba92f5b4-2d11-453d-a403-e96b0029c9fe'
var acrPull = '7f951dda-4ed3-4680-a7ca-43fe172d538d'

resource identity 'Microsoft.ManagedIdentity/userAssignedIdentities@2023-01-31' = {
  name: '${baseName}-manager-id'
  location: location
}

resource logAnalytics 'Microsoft.OperationalInsights/workspaces@2023-09-01' = {
  name: '${baseName}-logs-${take(suffix, 6)}'
  location: location
  properties: {
    sku: {
      name: 'PerGB2018'
    }
    retentionInDays: 30
  }
}

resource storage 'Microsoft.Storage/storageAccounts@2023-05-01' = {
  name: storageAccountName
  location: location
  kind: 'StorageV2'
  sku: {
    name: 'Standard_LRS'
  }
  properties: {
    minimumTlsVersion: 'TLS1_2'
    supportsHttpsTrafficOnly: true
    allowBlobPublicAccess: false
    allowSharedKeyAccess: false
    defaultToOAuthAuthentication: true
    accessTier: 'Hot'
  }
}

resource blobService 'Microsoft.Storage/storageAccounts/blobServices@2023-05-01' = {
  parent: storage
  name: 'default'
  properties: {
    deleteRetentionPolicy: {
      enabled: true
      days: 7
    }
  }
}

resource logContainer 'Microsoft.Storage/storageAccounts/blobServices/containers@2023-05-01' = {
  parent: blobService
  name: logContainerName
  properties: {
    publicAccess: 'None'
  }
}

resource lifecycle 'Microsoft.Storage/storageAccounts/managementPolicies@2023-05-01' = if (logRetentionDays > 0) {
  parent: storage
  name: 'default'
  properties: {
    policy: {
      rules: [
        {
          name: 'expire-logs'
          enabled: true
          type: 'Lifecycle'
          definition: {
            filters: {
              blobTypes: [
                'blockBlob'
              ]
              prefixMatch: [
                '${logContainerName}/${logPrefix}'
              ]
            }
            actions: {
              baseBlob: {
                delete: {
                  daysAfterModificationGreaterThan: logRetentionDays
                }
              }
            }
          }
        }
      ]
    }
  }
}

resource blobWriter 'Microsoft.Authorization/roleAssignments@2022-04-01' = {
  scope: storage
  name: guid(storage.id, identity.id, storageBlobDataContributor)
  properties: {
    principalId: identity.properties.principalId
    principalType: 'ServicePrincipal'
    roleDefinitionId: subscriptionResourceId('Microsoft.Authorization/roleDefinitions', storageBlobDataContributor)
  }
}

resource acr 'Microsoft.ContainerRegistry/registries@2023-07-01' existing = if (!empty(acrResourceId)) {
  name: last(split(acrResourceId, '/'))
}

resource acrPullAssignment 'Microsoft.Authorization/roleAssignments@2022-04-01' = if (!empty(acrResourceId)) {
  scope: acr
  name: guid(acrResourceId, identity.id, acrPull)
  properties: {
    principalId: identity.properties.principalId
    principalType: 'ServicePrincipal'
    roleDefinitionId: subscriptionResourceId('Microsoft.Authorization/roleDefinitions', acrPull)
  }
}

resource acaEnv 'Microsoft.App/managedEnvironments@2024-03-01' = {
  name: '${baseName}-env'
  location: location
  properties: {
    appLogsConfiguration: {
      destination: 'log-analytics'
      logAnalyticsConfiguration: {
        customerId: logAnalytics.properties.customerId
        sharedKey: logAnalytics.listKeys().primarySharedKey
      }
    }
  }
}

var tokenSecrets = concat(
  [
    {
      name: 'manager-token'
      value: managerToken
    }
  ],
  empty(managerToken2) ? [] : [
    {
      name: 'manager-token-2'
      value: managerToken2
    }
  ]
)

var tokenEnv = concat(
  [
    {
      name: 'CICD_SENSOR_MANAGER_TOKEN'
      secretRef: 'manager-token'
    }
  ],
  empty(managerToken2) ? [] : [
    {
      name: 'CICD_SENSOR_MANAGER_TOKEN_2'
      secretRef: 'manager-token-2'
    }
  ]
)

resource managerApp 'Microsoft.App/containerApps@2024-03-01' = {
  name: '${baseName}-manager'
  location: location
  identity: {
    type: 'UserAssigned'
    userAssignedIdentities: {
      '${identity.id}': {}
    }
  }
  dependsOn: [
    blobWriter
    acrPullAssignment
  ]
  properties: {
    managedEnvironmentId: acaEnv.id
    configuration: {
      activeRevisionsMode: 'Single'
      ingress: {
        external: true
        targetPort: 8080
        transport: 'auto'
        allowInsecure: false
      }
      registries: useRegistry ? [
        {
          server: registryServer
          identity: identity.id
        }
      ] : []
      secrets: concat(tokenSecrets, [
        {
          name: 'manager-config'
          value: managerConfig
        }
      ])
    }
    template: {
      containers: [
        {
          name: 'manager'
          image: managerImage
          resources: {
            cpu: json('0.5')
            memory: '1Gi'
          }
          env: concat(tokenEnv, [
            {
              name: 'AZURE_CLIENT_ID'
              value: identity.properties.clientId
            }
            {
              name: 'CICD_SENSOR_MANAGER_CONFIG_FILE'
              value: '/etc/cicd-sensor/manager.yaml'
            }
          ])
          volumeMounts: [
            {
              volumeName: 'config'
              mountPath: '/etc/cicd-sensor'
            }
          ]
        }
      ]
      volumes: [
        {
          name: 'config'
          storageType: 'Secret'
          secrets: [
            {
              secretRef: 'manager-config'
              path: 'manager.yaml'
            }
          ]
        }
      ]
      scale: {
        minReplicas: minReplicas
        maxReplicas: maxReplicas
        rules: [
          {
            name: 'http'
            http: {
              metadata: {
                concurrentRequests: '50'
              }
            }
          }
        ]
      }
    }
  }
}

output managerUrl string = 'https://${managerApp.properties.configuration.ingress.fqdn}'
output storageAccountName string = storage.name
output logContainerUri string = '${blobEndpoint}/${logContainerName}/${logPrefix}'
output managerIdentityClientId string = identity.properties.clientId
