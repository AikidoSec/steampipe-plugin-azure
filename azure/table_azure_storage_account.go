package azure

import (
	"context"
	"fmt"
	"reflect"
	"strings"

	"github.com/Azure/azure-sdk-for-go/profiles/latest/storage/mgmt/storage"
	"github.com/Azure/azure-sdk-for-go/profiles/preview/preview/monitor/mgmt/insights"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/arm"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/storage/armstorage"
	"github.com/Azure/go-autorest/autorest"
	"github.com/tombuildsstuff/giovanni/storage/2019-12-12/blob/accounts"
	"github.com/turbot/steampipe-plugin-sdk/v5/grpc/proto"
	"github.com/turbot/steampipe-plugin-sdk/v5/plugin"
	"github.com/turbot/steampipe-plugin-sdk/v5/plugin/transform"
)

//// TABLE DEFINITION

func tableAzureStorageAccount(_ context.Context) *plugin.Table {
	return &plugin.Table{
		Name:        "azure_storage_account",
		Description: "Azure Storage Account",
		Get: &plugin.GetConfig{
			KeyColumns: plugin.AllColumns([]string{"name", "resource_group"}),
			Hydrate:    getStorageAccount,
			Tags: map[string]string{
				"service": "Microsoft.Storage",
				"action":  "storageAccounts/read",
			},
			IgnoreConfig: &plugin.IgnoreConfig{
				ShouldIgnoreErrorFunc: isNotFoundError([]string{"ResourceNotFound", "ResourceGroupNotFound"}),
			},
		},
		List: &plugin.ListConfig{
			Hydrate: listStorageAccounts,
			Tags: map[string]string{
				"service": "Microsoft.Storage",
				"action":  "storageAccounts/read",
			},
			IgnoreConfig: &plugin.IgnoreConfig{
				ShouldIgnoreErrorFunc: isNotFoundError([]string{"ResourceNotFound", "ResourceGroupNotFound"}),
			},
		},
		Columns: azureColumns([]*plugin.Column{
			{
				Name:        "name",
				Type:        proto.ColumnType_STRING,
				Description: "The friendly name that identifies the storage account.",
			},
			{
				Name:        "id",
				Description: "Contains ID to identify a storage account uniquely.",
				Type:        proto.ColumnType_STRING,
				Transform:   transform.FromField("ID"),
			},
			{
				Name:        "type",
				Description: "Type of the resource.",
				Type:        proto.ColumnType_STRING,
				Transform:   transform.FromField("Account.Type"),
			},
			{
				Name:        "access_tier",
				Description: "The access tier used for billing.",
				Type:        proto.ColumnType_STRING,
				Transform:   transform.FromField("Account.Properties.AccessTier").Transform(transformToString),
			},
			{
				Name:        "kind",
				Description: "The kind of the resource.",
				Type:        proto.ColumnType_STRING,
				Transform:   transform.FromField("Account.Kind").Transform(transformToString),
			},
			{
				Name:        "sku_name",
				Description: "Contains sku name of the storage account.",
				Type:        proto.ColumnType_STRING,
				Transform:   transform.FromField("Account.SKU.Name").Transform(transformToString),
			},
			{
				Name:        "sku_tier",
				Description: "Contains sku tier of the storage account.",
				Type:        proto.ColumnType_STRING,
				Transform:   transform.FromField("Account.SKU.Tier").Transform(transformToString),
			},
			{
				Name:        "creation_time",
				Description: "Creation date and time of the storage account.",
				Type:        proto.ColumnType_TIMESTAMP,
				Transform:   transform.FromField("Account.Properties.CreationTime").Transform(transform.NullIfZeroValue),
			},
			{
				Name:        "allow_blob_public_access",
				Description: "Specifies whether allow or disallow public access to all blobs or containers in the storage account.",
				Type:        proto.ColumnType_BOOL,
				Transform:   transform.FromField("Account.Properties.AllowBlobPublicAccess"),
			},
			{
				Name:        "allow_shared_key_access",
				Description: "Indicates whether the storage account permits requests to be authorized with the account access key via Shared Key. If false, then all requests, including shared access signatures, must be authorized with Azure Active Directory (Azure AD).",
				Type:        proto.ColumnType_BOOL,
				Transform:   transform.FromField("Account.Properties.AllowSharedKeyAccess"),
			},
			{
				Name:        "blob_change_feed_enabled",
				Description: "Specifies whether change feed event logging is enabled for the Blob service.",
				Type:        proto.ColumnType_BOOL,
				Hydrate:     getAzureStorageAccountBlobProperties,
				Transform:   transform.FromField("BlobServiceProperties.ChangeFeed.Enabled"),
			},
			{
				Name:        "blob_container_soft_delete_enabled",
				Description: "Specifies whether DeleteRetentionPolicy is enabled.",
				Type:        proto.ColumnType_BOOL,
				Hydrate:     getAzureStorageAccountBlobProperties,
				Transform:   transform.FromField("BlobServiceProperties.ContainerDeleteRetentionPolicy.Enabled"),
			},
			{
				Name:        "blob_container_soft_delete_retention_days",
				Description: "Indicates the number of days that the deleted item should be retained.",
				Type:        proto.ColumnType_INT,
				Hydrate:     getAzureStorageAccountBlobProperties,
				Transform:   transform.FromField("BlobServiceProperties.ContainerDeleteRetentionPolicy.Days"),
			},
			{
				Name:        "blob_restore_policy_days",
				Description: "Specifies how long the blob can be restored.",
				Type:        proto.ColumnType_INT,
				Hydrate:     getAzureStorageAccountBlobProperties,
				Transform:   transform.FromField("BlobServiceProperties.RestorePolicy.Days"),
			},
			{
				Name:        "blob_restore_policy_enabled",
				Description: "Specifies whether blob restore is enabled.",
				Type:        proto.ColumnType_BOOL,
				Hydrate:     getAzureStorageAccountBlobProperties,
				Transform:   transform.FromField("BlobServiceProperties.RestorePolicy.Enabled"),
			},
			{
				Name:        "blob_soft_delete_enabled",
				Description: "Specifies whether DeleteRetentionPolicy is enabled.",
				Type:        proto.ColumnType_BOOL,
				Hydrate:     getAzureStorageAccountBlobProperties,
				Transform:   transform.FromField("BlobServiceProperties.DeleteRetentionPolicy.Enabled"),
			},
			{
				Name:        "blob_soft_delete_retention_days",
				Description: "Indicates the number of days that the deleted item should be retained.",
				Type:        proto.ColumnType_INT,
				Hydrate:     getAzureStorageAccountBlobProperties,
				Transform:   transform.FromField("BlobServiceProperties.DeleteRetentionPolicy.Days"),
			},
			{
				Name:        "blob_versioning_enabled",
				Description: "Specifies whether versioning is enabled.",
				Type:        proto.ColumnType_BOOL,
				Hydrate:     getAzureStorageAccountBlobProperties,
				Transform:   transform.FromField("BlobServiceProperties.IsVersioningEnabled"),
			},
			{
				Name:        "enable_https_traffic_only",
				Description: "Allows https traffic only to storage service if sets to true.",
				Type:        proto.ColumnType_BOOL,
				Transform:   transform.FromField("Account.Properties.EnableHTTPSTrafficOnly"),
			},
			{
				Name:        "encryption_key_source",
				Description: "Contains the encryption keySource (provider).",
				Type:        proto.ColumnType_STRING,
				Transform:   transform.FromField("Account.Properties.Encryption.KeySource").Transform(transformToString),
			},
			{
				Name:        "encryption_key_vault_properties_key_current_version_id",
				Description: "The object identifier of the current versioned Key Vault Key in use.",
				Type:        proto.ColumnType_STRING,
				Transform:   transform.FromField("Account.Properties.Encryption.KeyVaultProperties.CurrentVersionedKeyIdentifier"),
			},
			{
				Name:        "encryption_key_vault_properties_key_name",
				Description: "The name of KeyVault key.",
				Type:        proto.ColumnType_STRING,
				Transform:   transform.FromField("Account.Properties.Encryption.KeyVaultProperties.KeyName"),
			},
			{
				Name:        "encryption_key_vault_properties_key_vault_uri",
				Description: "The Uri of KeyVault.",
				Type:        proto.ColumnType_STRING,
				Transform:   transform.FromField("Account.Properties.Encryption.KeyVaultProperties.KeyVaultURI"),
			},
			{
				Name:        "encryption_key_vault_properties_key_version",
				Description: "The version of KeyVault key.",
				Type:        proto.ColumnType_STRING,
				Transform:   transform.FromField("Account.Properties.Encryption.KeyVaultProperties.KeyVersion"),
			},
			{
				Name:        "encryption_key_vault_properties_last_rotation_time",
				Description: "Timestamp of last rotation of the Key Vault Key.",
				Type:        proto.ColumnType_TIMESTAMP,
				Transform:   transform.FromField("Account.Properties.Encryption.KeyVaultProperties.LastKeyRotationTimestamp").Transform(transform.NullIfZeroValue),
			},
			{
				Name:        "failover_in_progress",
				Description: "Specifies whether the failover is in progress.",
				Type:        proto.ColumnType_BOOL,
				Transform:   transform.FromField("Account.Properties.FailoverInProgress"),
			},
			{
				Name:        "file_soft_delete_enabled",
				Description: "Specifies whether DeleteRetentionPolicy is enabled.",
				Type:        proto.ColumnType_BOOL,
				Hydrate:     getAzureStorageAccountFileProperties,
				Transform:   transform.FromField("FileServiceProperties.ShareDeleteRetentionPolicy.Enabled"),
			},
			{
				Name:        "file_soft_delete_retention_days",
				Description: "Indicates the number of days that the deleted item should be retained.",
				Type:        proto.ColumnType_INT,
				Hydrate:     getAzureStorageAccountFileProperties,
				Transform:   transform.FromField("FileServiceProperties.ShareDeleteRetentionPolicy.Days"),
			},
			{
				Name:        "is_hns_enabled",
				Description: "Specifies whether account HierarchicalNamespace is enabled.",
				Type:        proto.ColumnType_BOOL,
				Transform:   transform.FromField("Account.Properties.IsHnsEnabled"),
			},
			{
				Name:        "queue_logging_delete",
				Description: "Specifies whether all delete requests should be logged.",
				Type:        proto.ColumnType_BOOL,
				Hydrate:     getAzureStorageAccountQueueProperties,
				Transform:   transform.FromField("Logging.Delete"),
			},
			{
				Name:        "queue_logging_read",
				Description: "Specifies whether all read requests should be logged.",
				Type:        proto.ColumnType_BOOL,
				Hydrate:     getAzureStorageAccountQueueProperties,
				Transform:   transform.FromField("Logging.Read"),
			},
			{
				Name:        "queue_logging_retention_days",
				Description: "Indicates the number of days that metrics or logging data should be retained.",
				Type:        proto.ColumnType_INT,
				Hydrate:     getAzureStorageAccountQueueProperties,
				Transform:   transform.FromField("Logging.RetentionPolicy.Days"),
			},
			{
				Name:        "queue_logging_retention_enabled",
				Description: "Specifies whether a retention policy is enabled for the storage service.",
				Type:        proto.ColumnType_BOOL,
				Hydrate:     getAzureStorageAccountQueueProperties,
				Transform:   transform.FromField("Logging.RetentionPolicy.Enabled"),
			},
			{
				Name:        "queue_logging_version",
				Description: "The version of Storage Analytics to configure.",
				Type:        proto.ColumnType_STRING,
				Hydrate:     getAzureStorageAccountQueueProperties,
				Transform:   transform.FromField("Logging.Version"),
			},
			{
				Name:        "queue_logging_write",
				Description: "Specifies whether all write requests should be logged.",
				Type:        proto.ColumnType_BOOL,
				Hydrate:     getAzureStorageAccountQueueProperties,
				Transform:   transform.FromField("Logging.Write"),
			},
			{
				Name:        "table_logging_read",
				Description: "Indicates whether all read requests should be logged.",
				Type:        proto.ColumnType_BOOL,
				Hydrate:     getAzureStorageAccountTableProperties,
				Transform:   transform.FromField("Logging.Read"),
			},
			{
				Name:        "table_logging_write",
				Description: "Indicates whether all write requests should be logged.",
				Type:        proto.ColumnType_BOOL,
				Hydrate:     getAzureStorageAccountTableProperties,
				Transform:   transform.FromField("Logging.Write"),
			},
			{
				Name:        "table_logging_delete",
				Description: "Indicates whether all delete requests should be logged.",
				Type:        proto.ColumnType_BOOL,
				Hydrate:     getAzureStorageAccountTableProperties,
				Transform:   transform.FromField("Logging.Delete"),
			},
			{
				Name:        "table_logging_version",
				Description: "The version of Analytics to configure.",
				Type:        proto.ColumnType_STRING,
				Hydrate:     getAzureStorageAccountTableProperties,
				Transform:   transform.FromField("Logging.Version"),
			},
			{
				Name:        "minimum_tls_version",
				Description: "Contains the minimum TLS version to be permitted on requests to storage.",
				Type:        proto.ColumnType_STRING,
				Transform:   transform.FromField("Account.Properties.MinimumTLSVersion").Transform(transformToString),
			},
			{
				Name:        "network_rule_bypass",
				Description: "Specifies whether traffic is bypassed for Logging/Metrics/AzureServices.",
				Type:        proto.ColumnType_STRING,
				Transform:   transform.FromField("Account.Properties.NetworkRuleSet.Bypass").Transform(transformToString),
			},
			{
				Name:        "network_rule_default_action",
				Description: "Specifies the default action of allow or deny when no other rules match.",
				Type:        proto.ColumnType_STRING,
				Transform:   transform.FromField("Account.Properties.NetworkRuleSet.DefaultAction").Transform(transformToString),
			},
			{
				Name:        "primary_blob_endpoint",
				Description: "Contains the blob endpoint.",
				Type:        proto.ColumnType_STRING,
				Transform:   transform.FromField("Account.Properties.PrimaryEndpoints.Blob"),
			},
			{
				Name:        "primary_dfs_endpoint",
				Description: "Contains the dfs endpoint.",
				Type:        proto.ColumnType_STRING,
				Transform:   transform.FromField("Account.Properties.PrimaryEndpoints.Dfs"),
			},
			{
				Name:        "primary_file_endpoint",
				Description: "Contains the file endpoint.",
				Type:        proto.ColumnType_STRING,
				Transform:   transform.FromField("Account.Properties.PrimaryEndpoints.File"),
			},
			{
				Name:        "primary_location",
				Description: "Contains the location of the primary data center for the storage account.",
				Type:        proto.ColumnType_STRING,
				Transform:   transform.FromField("Account.Properties.PrimaryLocation"),
			},
			{
				Name:        "primary_queue_endpoint",
				Description: "Contains the queue endpoint.",
				Type:        proto.ColumnType_STRING,
				Transform:   transform.FromField("Account.Properties.PrimaryEndpoints.Queue"),
			},
			{
				Name:        "primary_table_endpoint",
				Description: "Contains the table endpoint.",
				Type:        proto.ColumnType_STRING,
				Transform:   transform.FromField("Account.Properties.PrimaryEndpoints.Table"),
			},
			{
				Name:        "primary_web_endpoint",
				Description: "Contains the web endpoint.",
				Type:        proto.ColumnType_STRING,
				Transform:   transform.FromField("Account.Properties.PrimaryEndpoints.Web"),
			},
			{
				Name:        "public_network_access",
				Description: "Allow or disallow public network access to Storage Account. Value is optional but if passed in, must be Enabled or Disabled.",
				Type:        proto.ColumnType_STRING,
				Transform:   transform.FromField("Account.Properties.PublicNetworkAccess"),
			},
			{
				Name:        "status_of_primary",
				Description: "The status indicating whether the primary location of the storage account is available or unavailable. Possible values include: 'available', 'unavailable'.",
				Type:        proto.ColumnType_STRING,
				Transform:   transform.FromField("Account.Properties.StatusOfPrimary"),
			},
			{
				Name:        "provisioning_state",
				Description: "The provisioning state of the storage account resource.",
				Type:        proto.ColumnType_STRING,
				Transform:   transform.FromField("Account.Properties.ProvisioningState").Transform(transformToString),
			},
			{
				Name:        "require_infrastructure_encryption",
				Description: "Specifies whether or not the service applies a secondary layer of encryption with platform managed keys for data at rest.",
				Type:        proto.ColumnType_BOOL,
				Transform:   transform.FromField("Account.Properties.Encryption.RequireInfrastructureEncryption"),
			},
			{
				Name:        "secondary_location",
				Description: "Contains the location of the geo-replicated secondary for the storage account.",
				Type:        proto.ColumnType_STRING,
				Transform:   transform.FromField("Account.Properties.SecondaryLocation"),
			},
			{
				Name:        "status_of_secondary",
				Description: "The status indicating whether the secondary location of the storage account is available or unavailable. Only available if the SKU name is Standard_GRS or Standard_RAGRS. Possible values include: 'available', 'unavailable'.",
				Type:        proto.ColumnType_STRING,
				Transform:   transform.FromField("Account.Properties.StatusOfSecondary"),
			},
			{
				Name:        "blob_service_logging",
				Description: "Specifies the blob service properties for logging access.",
				Type:        proto.ColumnType_JSON,
				Hydrate:     getAzureStorageAccountBlobServiceLogging,
				Transform:   transform.FromValue(),
			},
			{
				Name:        "table_logging_retention_policy",
				Description: "The retention policy.",
				Type:        proto.ColumnType_JSON,
				Hydrate:     getAzureStorageAccountTableProperties,
				Transform:   transform.FromField("Logging.RetentionPolicy"),
			},
			{
				Name:        "diagnostic_settings",
				Description: "A list of active diagnostic settings for the storage account.",
				Type:        proto.ColumnType_JSON,
				Hydrate:     listStorageAccountDiagnosticSettings,
				Transform:   transform.FromValue(),
			},
			{
				Name:        "encryption_scope",
				Description: "Encryption scope details for the storage account.",
				Type:        proto.ColumnType_JSON,
				Hydrate:     listAzureStorageAccountEncryptionScope,
				Transform:   transform.FromValue(),
			},
			{
				Name:        "encryption_services",
				Description: "A list of services which support encryption.",
				Type:        proto.ColumnType_JSON,
				Transform:   transform.FromField("Account.Properties.Encryption.Services"),
			},
			{
				Name:        "lifecycle_management_policy",
				Description: "The managementpolicy associated with the specified storage account.",
				Type:        proto.ColumnType_JSON,
				Hydrate:     getAzureStorageAccountLifecycleManagementPolicy,
				Transform:   transform.FromValue(),
			},
			{
				Name:        "network_ip_rules",
				Description: "A list of IP ACL rules.",
				Type:        proto.ColumnType_JSON,
				Transform:   transform.FromField("Account.Properties.NetworkRuleSet.IPRules"),
			},
			{
				Name:        "private_endpoint_connections",
				Description: "A list of private endpoint connection associated with the specified storage account.",
				Type:        proto.ColumnType_JSON,
				Transform:   transform.FromField("Account.Properties.PrivateEndpointConnections"),
			},
			{
				Name:        "table_properties",
				Description: "Azure Analytics Logging settings of tables.",
				Type:        proto.ColumnType_JSON,
				Hydrate:     getAzureStorageAccountTableProperties,
				Transform:   transform.FromValue(),
			},
			{
				Name:        "access_keys",
				Description: "The list of access keys or Kerberos keys (if active directory enabled) for the specified storage account.",
				Type:        proto.ColumnType_JSON,
				Hydrate:     listAzureStorageAccountAccessKeys,
				Transform:   transform.FromValue(),
			},
			{
				Name:        "virtual_network_rules",
				Description: "A list of virtual network rules.",
				Type:        proto.ColumnType_JSON,
				Transform:   transform.FromField("Account.Properties.NetworkRuleSet.VirtualNetworkRules"),
			},
			{
				Name:        "allow_cross_tenant_replication",
				Description: "Specifies whether cross-tenant replication is allowed for the storage account.",
				Type:        proto.ColumnType_BOOL,
				Transform:   transform.FromField("Account.Properties.AllowCrossTenantReplication"),
			},
			{
				Name:        "default_to_oauth_authentication",
				Description: "Specifies whether Azure Active Directory is the default authentication method.",
				Type:        proto.ColumnType_BOOL,
				Transform:   transform.FromField("Account.Properties.DefaultToOAuthAuthentication"),
			},
			{
				Name:        "sas_expiration_period",
				Description: "Specifies the time period for SAS token expiration.",
				Type:        proto.ColumnType_STRING,
				Transform:   transform.FromField("Account.Properties.SasPolicy.SasExpirationPeriod"),
			},
			{
				Name:        "sas_expiration_action",
				Description: "The action to be taken when a SAS token expires. Possible values include: 'Log'.",
				Type:        proto.ColumnType_STRING,
				Transform:   transform.FromField("Account.Properties.SasPolicy.ExpirationAction"),
			},
			{
				Name:        "is_local_user_enabled",
				Description: "Specifies whether local RBAC users are enabled for the storage account.",
				Type:        proto.ColumnType_BOOL,
				Transform:   transform.FromField("Account.Properties.IsLocalUserEnabled"),
			},
			{
				Name:        "routing_preference_routing_choice",
				Description: "Specifies the network routing choice for the storage account (MicrosoftRouting or InternetRouting).",
				Type:        proto.ColumnType_STRING,
				Transform:   transform.FromField("Account.Properties.RoutingPreference.RoutingChoice"),
			},
			{
				Name:        "routing_preference_publish_microsoft_endpoints",
				Description: "Specifies whether Microsoft routing endpoints are published.",
				Type:        proto.ColumnType_BOOL,
				Transform:   transform.FromField("Account.Properties.RoutingPreference.PublishMicrosoftEndpoints"),
			},
			{
				Name:        "routing_preference_publish_internet_endpoints",
				Description: "Specifies whether Internet routing endpoints are published.",
				Type:        proto.ColumnType_BOOL,
				Transform:   transform.FromField("Account.Properties.RoutingPreference.PublishInternetEndpoints"),
			},

			// Steampipe standard columns
			{
				Name:        "title",
				Description: ColumnDescriptionTitle,
				Type:        proto.ColumnType_STRING,
				Transform:   transform.FromField("Name"),
			},
			{
				Name:        "tags",
				Description: ColumnDescriptionTags,
				Type:        proto.ColumnType_JSON,
				Transform:   transform.FromField("Account.Tags"),
			},
			{
				Name:        "akas",
				Description: ColumnDescriptionAkas,
				Type:        proto.ColumnType_JSON,
				Transform:   transform.FromField("Account.ID").Transform(idToAkas),
			},

			// Azure standard columns
			{
				Name:        "region",
				Description: ColumnDescriptionRegion,
				Type:        proto.ColumnType_STRING,
				Transform:   transform.FromField("Account.Location").Transform(toLower),
			},
			{
				Name:        "resource_group",
				Description: ColumnDescriptionResourceGroup,
				Type:        proto.ColumnType_STRING,
				Transform:   transform.FromField("ResourceGroup"),
			},
		}),
	}
}

type AccountInfo = struct {
	Account        armstorage.Account
	Name           string
	ID             string
	SubscriptionID string
	ResourceGroup  string
}

//// LIST FUNCTION

func listStorageAccounts(ctx context.Context, d *plugin.QueryData, _ *plugin.HydrateData) (interface{}, error) {
	logger := plugin.Logger(ctx)
	logger.Trace("listStorageAccounts")

	// Create session
	session, err := GetNewSessionUpdated(ctx, d)
	if err != nil {
		plugin.Logger(ctx).Error("azure_role_assignment.listIamRoleAssignments", "session_error", err)
		return nil, err
	}

	// Create client
	client, err := armstorage.NewAccountsClient(session.SubscriptionID, session.Cred, session.ClientOptions)
	if err != nil {
		logger.Error("error while creating accounts client", "client_error", err)
		return nil, err
	}

	pager := client.NewListPager(nil)

	for pager.More() {
		// apply rate limiting
		d.WaitForListRateLimit(ctx)

		resp, err := pager.NextPage(ctx)
		if err != nil {
			logger.Error("error listing next page", "api_error", err)
			return nil, err
		}

		for _, v := range resp.Value {
			resourceID, err := arm.ParseResourceID(*v.ID)
			if err != nil {
				return nil, fmt.Errorf("error parsing resource ID: %w", err)
			}

			d.StreamListItem(ctx, &AccountInfo{
				Account:        *v,
				Name:           *v.Name,
				ID:             *v.ID,
				SubscriptionID: session.SubscriptionID,
				ResourceGroup:  resourceID.ResourceGroupName,
			})

			// Check if the context has been canceled or if the limit has been hit (if specified)
			if d.RowsRemaining(ctx) == 0 {
				return nil, nil
			}
		}
	}

	return nil, nil
}

//// HYDRATE FUNCTIONS

func getStorageAccount(ctx context.Context, d *plugin.QueryData, _ *plugin.HydrateData) (interface{}, error) {
	name := d.EqualsQuals["name"].GetStringValue()
	resourceGroup := d.EqualsQuals["resource_group"].GetStringValue()

	logger := plugin.Logger(ctx)
	logger.Trace("getStorageAccount")

	// Create session
	session, err := GetNewSessionUpdated(ctx, d)
	if err != nil {
		plugin.Logger(ctx).Error("azure_role_assignment.listIamRoleAssignments", "session_error", err)
		return nil, err
	}

	// Create client
	client, err := armstorage.NewAccountsClient(session.SubscriptionID, session.Cred, session.ClientOptions)
	if err != nil {
		logger.Error("error while creating accounts client", "client_error", err)
		return nil, err
	}

	statusExpand := armstorage.StorageAccountExpand("blobRestoreStatus")
	resp, err := client.GetProperties(ctx, resourceGroup, name, &armstorage.AccountsClientGetPropertiesOptions{
		Expand: &statusExpand,
	})
	if err != nil {
		logger.Error("error getting storage account properties", "api_error", err)
		return nil, err
	}

	return &AccountInfo{
		Account:        resp.Account,
		Name:           *resp.Name,
		ID:             *resp.ID,
		SubscriptionID: session.SubscriptionID,
	}, nil
}

func getAzureStorageAccountLifecycleManagementPolicy(ctx context.Context, d *plugin.QueryData, h *plugin.HydrateData) (interface{}, error) {
	accountData := h.Item.(*AccountInfo)

	logger := plugin.Logger(ctx)
	logger.Trace("getAzureStorageAccountLifecycleManagementPolicy")

	// Create session
	session, err := GetNewSessionUpdated(ctx, d)
	if err != nil {
		plugin.Logger(ctx).Error("azure_role_assignment.listIamRoleAssignments", "session_error", err)
		return nil, err
	}

	// Create client
	client, err := armstorage.NewManagementPoliciesClient(session.SubscriptionID, session.Cred, session.ClientOptions)
	if err != nil {
		logger.Error("error while creating management policies client", "client_error", err)
		return nil, err
	}

	op, err := client.Get(ctx, accountData.ResourceGroup, accountData.Name, "default", nil)
	if err != nil {
		logger.Error("error getting storage account management policy", "error", err)
		return nil, err
	}

	// Direct assignment returns ManagementPolicyProperties only
	objectMap := make(map[string]interface{})
	if op.ID != nil {
		objectMap["id"] = op.ID
	}
	if op.Name != nil {
		objectMap["name"] = op.Name
	}
	if op.Type != nil {
		objectMap["type"] = op.Type
	}
	if op.ManagementPolicy.Properties != nil {
		objectMap["properties"] = op.ManagementPolicy.Properties
	}

	return objectMap, nil
}

// TODO: test fields
func getAzureStorageAccountBlobProperties(ctx context.Context, d *plugin.QueryData, h *plugin.HydrateData) (interface{}, error) {
	accountData := h.Item.(*AccountInfo)

	logger := plugin.Logger(ctx)
	logger.Trace("getAzureStorageAccountBlobProperties")

	// Blob is not supported for the account if storage type is FileStorage
	if *accountData.Account.Kind == "FileStorage" {
		return nil, nil
	}

	// Create session
	session, err := GetNewSessionUpdated(ctx, d)
	if err != nil {
		plugin.Logger(ctx).Error("azure_role_assignment.listIamRoleAssignments", "session_error", err)
		return nil, err
	}

	// Create client
	client, err := armstorage.NewBlobServicesClient(session.SubscriptionID, session.Cred, session.ClientOptions)
	if err != nil {
		logger.Error("error while creating blob services client", "client_error", err)
		return nil, err
	}

	op, err := client.GetServiceProperties(ctx, accountData.ResourceGroup, accountData.Name, nil)
	if err != nil {
		logger.Error("error getting storage account blob service properties", "api_error", err)
		return nil, err
	}

	return op.BlobServiceProperties, nil
}

func getAzureStorageAccountTableProperties(ctx context.Context, d *plugin.QueryData, h *plugin.HydrateData) (interface{}, error) {
	accountData := h.Item.(*AccountInfo)

	logger := plugin.Logger(ctx)
	logger.Trace("getAzureStorageAccountTableProperties")

	// Table is not supported for the account if storage type is FileStorage
	if *accountData.Account.Kind == "FileStorage" {
		return nil, nil
	}

	// Create session
	session, err := GetNewSessionUpdated(ctx, d)
	if err != nil {
		plugin.Logger(ctx).Error("azure_role_assignment.listIamRoleAssignments", "session_error", err)
		return nil, err
	}

	// Create client
	client, err := armstorage.NewTableServicesClient(session.SubscriptionID, session.Cred, session.ClientOptions)
	if err != nil {
		logger.Error("error while creating table services client", "client_error", err)
		return nil, err
	}

	op, err := client.GetServiceProperties(ctx, accountData.ResourceGroup, accountData.Name, nil)
	if err != nil {
		logger.Error("error getting storage account table properties", "api_error", err)
		return nil, err
	}

	return op.TableServiceProperties, nil
}

func listAzureStorageAccountEncryptionScope(ctx context.Context, d *plugin.QueryData, h *plugin.HydrateData) (interface{}, error) {
	accountData := h.Item.(*AccountInfo)

	logger := plugin.Logger(ctx)
	logger.Trace("listAzureStorageAccountEncryptionScope")

	// Table is not supported for FileStorage accounts type
	if *accountData.Account.Kind == "FileStorage" {
		return nil, nil
	}

	// Create session
	session, err := GetNewSessionUpdated(ctx, d)
	if err != nil {
		plugin.Logger(ctx).Error("azure_role_assignment.listIamRoleAssignments", "session_error", err)
		return nil, err
	}

	// Create client
	client, err := armstorage.NewEncryptionScopesClient(session.SubscriptionID, session.Cred, session.ClientOptions)
	if err != nil {
		logger.Error("error while creating encryption scopes client", "client_error", err)
		return nil, err
	}

	// Limiting the results
	limit := d.QueryContext.Limit
	maxResult := 1000
	if d.QueryContext.Limit != nil {
		if *limit < 1000 {
			maxResult = int(*limit)
		}
	}
	maxResultInt := int32(maxResult)

	pager := client.NewListPager(accountData.ResourceGroup, accountData.Name, &armstorage.EncryptionScopesClientListOptions{Maxpagesize: &maxResultInt})

	var encryptionScopes []map[string]interface{}

	for pager.More() {
		// apply rate limiting
		d.WaitForListRateLimit(ctx)

		resp, err := pager.NextPage(ctx)
		if err != nil {
			logger.Error("error listing next page", "api_error", err)
			return nil, err
		}

		for _, v := range resp.Value {
			encryptionScopes = append(encryptionScopes, storageAccountEncryptionScopeMap(*v))
		}
	}

	return encryptionScopes, nil
}

func listAzureStorageAccountAccessKeys(ctx context.Context, d *plugin.QueryData, h *plugin.HydrateData) (interface{}, error) {
	accountData := h.Item.(*AccountInfo)

	// Create session
	session, err := GetNewSession(ctx, d, "MANAGEMENT")
	if err != nil {
		plugin.Logger(ctx).Error("azure_storage_account.listAzureStorageAccountAccessKeys", "session_error", err)
		return nil, err
	}
	subscriptionID := session.SubscriptionID

	storageClient := storage.NewAccountsClientWithBaseURI(session.ResourceManagerEndpoint, subscriptionID)
	storageClient.Authorizer = session.Authorizer

	// Apply Retry rule
	ApplyRetryRules(ctx, &storageClient, d.Connection)

	keys, err := storageClient.ListKeys(ctx, accountData.ResourceGroup, accountData.Name, "")
	if err != nil {
		plugin.Logger(ctx).Error("azure_storage_account.listAzureStorageAccountAccessKeys", "api_error", err)
		return nil, err
	}
	var keysMap []map[string]interface{}
	if len(*keys.Keys) > 0 {
		for _, key := range *keys.Keys {
			keyMap := make(map[string]interface{})
			if key.KeyName != nil {
				keyMap["KeyName"] = *key.KeyName
			}
			if key.Value != nil {
				keyMap["Value"] = *key.Value
			}
			if key.Permissions != "" {
				keyMap["Permissions"] = key.Permissions
			}
			keysMap = append(keysMap, keyMap)
		}
	}

	return keysMap, nil
}

func getAzureStorageAccountBlobServiceLogging(ctx context.Context, d *plugin.QueryData, h *plugin.HydrateData) (interface{}, error) {
	accountData := h.Item.(*AccountInfo)

	// Blob is not supported for the account if storage type is FileStorage
	if *accountData.Account.Kind == "FileStorage" {
		return nil, nil
	}

	// Create session
	session, err := GetNewSession(ctx, d, "MANAGEMENT")
	if err != nil {
		return nil, err
	}
	subscriptionID := session.SubscriptionID

	storageClient := storage.NewAccountsClientWithBaseURI(session.ResourceManagerEndpoint, subscriptionID)
	storageClient.Authorizer = session.Authorizer

	// Apply Retry rule
	ApplyRetryRules(ctx, &storageClient, d.Connection)

	accountKeys, err := storageClient.ListKeys(ctx, accountData.ResourceGroup, accountData.Name, "")
	if err != nil {
		// storage.AccountsClient#ListKeys: Failure sending request: StatusCode=409 -- Original Error: autorest/azure: Service returned an error. Status=<nil> Code="ScopeLocked"
		// Message="The scope '/subscriptions/********-****-****-****-************/resourceGroups/turbot_rg/providers/Microsoft.Storage/storageAccounts/delmett'
		// cannot perform write operation because following scope(s) are locked: '/subscriptions/********-****-****-****-************/resourcegroups/turbot_rg/providers/Microsoft.Storage/storageAccounts/delmett'.
		// Please remove the lock and try again."
		if strings.Contains(err.Error(), "ScopeLocked") {
			return nil, nil
		}
		return nil, err
	}

	if *accountKeys.Keys != nil || len(*accountKeys.Keys) > 0 {
		key := (*accountKeys.Keys)[0]
		storageAuth, err := autorest.NewSharedKeyAuthorizer(accountData.Name, *key.Value, autorest.SharedKeyLite)
		if err != nil {
			return nil, err
		}

		client := accounts.New()
		client.Client.Authorizer = storageAuth
		client.BaseURI = session.StorageEndpointSuffix

		resp, err := client.GetServiceProperties(ctx, accountData.Name)
		if err != nil {
			if strings.Contains(err.Error(), "FeatureNotSupportedForAccount") {
				return nil, nil
			}
			return nil, err
		}
		return resp.StorageServiceProperties.Logging, nil
	}
	return nil, nil
}

func getAzureStorageAccountFileProperties(ctx context.Context, d *plugin.QueryData, h *plugin.HydrateData) (interface{}, error) {
	accountData := h.Item.(*AccountInfo)

	logger := plugin.Logger(ctx)
	logger.Trace("getAzureStorageAccountFileProperties")

	// Table is not supported for the account if storage type is BlobStorage
	if *accountData.Account.Kind == "BlobStorage" {
		return nil, nil
	}

	// Create session
	session, err := GetNewSessionUpdated(ctx, d)
	if err != nil {
		plugin.Logger(ctx).Error("azure_role_assignment.listIamRoleAssignments", "session_error", err)
		return nil, err
	}

	// Create client
	client, err := armstorage.NewFileServicesClient(session.SubscriptionID, session.Cred, session.ClientOptions)
	if err != nil {
		logger.Error("error while creating file services client", "client_error", err)
		return nil, err
	}

	op, err := client.GetServiceProperties(ctx, accountData.ResourceGroup, accountData.Name, nil)
	if err != nil {
		logger.Error("error getting storage account file service properties", "api_error", err)
		return nil, err
	}

	return op.FileServiceProperties, nil
}

func getAzureStorageAccountQueueProperties(ctx context.Context, d *plugin.QueryData, h *plugin.HydrateData) (interface{}, error) {
	accountData := h.Item.(*AccountInfo)

	logger := plugin.Logger(ctx)
	logger.Trace("getAzureStorageAccountQueueProperties")

	// Create session
	session, err := GetNewSessionUpdated(ctx, d)
	if err != nil {
		plugin.Logger(ctx).Error("azure_role_assignment.listIamRoleAssignments", "session_error", err)
		return nil, err
	}

	// Create client
	client, err := armstorage.NewQueueServicesClient(session.SubscriptionID, session.Cred, session.ClientOptions)
	if err != nil {
		logger.Error("error while creating queue services client", "client_error", err)
		return nil, err
	}

	op, err := client.GetServiceProperties(ctx, accountData.ResourceGroup, accountData.Name, nil)
	if err != nil {
		logger.Error("error getting storage account queue service properties", "api_error", err)
		return nil, err
	}

	return op.QueueServiceProperties, nil
}

func listStorageAccountDiagnosticSettings(ctx context.Context, d *plugin.QueryData, h *plugin.HydrateData) (interface{}, error) {
	plugin.Logger(ctx).Trace("listStorageAccountDiagnosticSettings")
	accountData := h.Item.(*AccountInfo)
	id := *accountData.Account.ID

	// Create session
	session, err := GetNewSession(ctx, d, "MANAGEMENT")
	if err != nil {
		return nil, err
	}
	subscriptionID := session.SubscriptionID

	client := insights.NewDiagnosticSettingsClientWithBaseURI(session.ResourceManagerEndpoint, subscriptionID)
	client.Authorizer = session.Authorizer

	// Apply Retry rule
	ApplyRetryRules(ctx, &client, d.Connection)

	op, err := client.List(ctx, id)
	if err != nil {
		return nil, err
	}

	// If we return the API response directly, the output only gives top level
	// contents of DiagnosticSettings
	var diagnosticSettings []map[string]interface{}
	for _, i := range *op.Value {
		objectMap := make(map[string]interface{})
		if i.ID != nil {
			objectMap["ID"] = i.ID
		}
		if i.Name != nil {
			objectMap["Name"] = i.Name
		}
		if i.Type != nil {
			objectMap["Type"] = i.Type
		}
		if i.DiagnosticSettings != nil {
			objectMap["DiagnosticSettings"] = i.DiagnosticSettings
		}
		diagnosticSettings = append(diagnosticSettings, objectMap)
	}

	return diagnosticSettings, nil
}

// If we return the API response directly, the output only gives the top level property
func storageAccountEncryptionScopeMap(scope armstorage.EncryptionScope) map[string]interface{} {
	objMap := make(map[string]interface{})
	if scope.ID != nil {
		objMap["Id"] = scope.ID
	}
	if scope.Name != nil {
		objMap["Name"] = scope.Name
	}
	if scope.Type != nil {
		objMap["Type"] = scope.Type
	}
	if scope.EncryptionScopeProperties != nil {
		if scope.EncryptionScopeProperties.Source != nil && *scope.EncryptionScopeProperties.Source != "" {
			objMap["Source"] = scope.EncryptionScopeProperties.Source
		}
		if scope.EncryptionScopeProperties.State != nil && *scope.EncryptionScopeProperties.State != "" {
			objMap["State"] = scope.EncryptionScopeProperties.State
		}
		if scope.EncryptionScopeProperties.CreationTime != nil {
			objMap["CreationTime"] = scope.EncryptionScopeProperties.CreationTime
		}
		if scope.EncryptionScopeProperties.LastModifiedTime != nil {
			objMap["LastModifiedTime"] = scope.EncryptionScopeProperties.LastModifiedTime
		}
		if scope.EncryptionScopeProperties.KeyVaultProperties != nil {
			if scope.EncryptionScopeProperties.KeyVaultProperties.KeyURI != nil {
				objMap["KeyURI"] = scope.EncryptionScopeProperties.KeyVaultProperties.KeyURI
			}
		}
	}
	return objMap
}

// transformToString is a transform function that converts the value to a string
// It also works for custom types that are string aliases
func transformToString(ctx context.Context, d *transform.TransformData) (any, error) {
	if d.Value == nil {
		return nil, nil
	}

	val := d.Value
	v := reflect.ValueOf(val)

	elem := v.Elem()

	// Check if the underlying type is based on string
	if elem.Kind() == reflect.String {
		return elem.String(), nil
	}

	return transform.ToString(ctx, d)
}
