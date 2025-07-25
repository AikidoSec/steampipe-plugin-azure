package azure

import (
	"context"
	"fmt"

	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/storage/armstorage"
	"github.com/turbot/go-kit/types"
	"github.com/turbot/steampipe-plugin-sdk/v5/grpc/proto"
	"github.com/turbot/steampipe-plugin-sdk/v5/plugin"
	"github.com/turbot/steampipe-plugin-sdk/v5/plugin/transform"
)

//// TABLE DEFINITION

func tableAzureStorageContainer(_ context.Context) *plugin.Table {
	return &plugin.Table{
		Name:        "azure_storage_container",
		Description: "Azure Storage Container",
		Get: &plugin.GetConfig{
			KeyColumns: plugin.AllColumns([]string{"name", "resource_group", "storage_account_name"}),
			Hydrate:    getStorageContainer,
			Tags: map[string]string{
				"service": "Microsoft.Storage",
				"action":  "storageAccounts/blobServices/containers/read",
			},
			IgnoreConfig: &plugin.IgnoreConfig{
				ShouldIgnoreErrorFunc: isNotFoundError([]string{"ResourceNotFound", "ResourceGroupNotFound", "ContainerNotFound"}),
			},
		},
		List: &plugin.ListConfig{
			Hydrate: listStorageContainers,
			KeyColumns: plugin.KeyColumnSlice{
				{Name: "resource_group", Require: plugin.Required},
				{Name: "storage_account_name", Require: plugin.Required},
			},
			Tags: map[string]string{
				"service": "Microsoft.Storage",
				"action":  "storageAccounts/blobServices/containers/read",
			},
		},

		Columns: azureColumns([]*plugin.Column{
			{
				Name:        "name",
				Description: "The friendly name that identifies the container.",
				Type:        proto.ColumnType_STRING,
			},
			{
				Name:        "id",
				Description: "Contains ID to identify a container uniquely.",
				Type:        proto.ColumnType_STRING,
				Transform:   transform.FromGo(),
			},
			{
				Name:        "storage_account_name",
				Description: "The friendly name that identifies the storage account.",
				Type:        proto.ColumnType_STRING,
				Transform:   transform.FromField("StorageAccountName"),
			},
			{
				Name:        "deleted",
				Description: "Indicates whether the blob container was deleted.",
				Type:        proto.ColumnType_BOOL,
				Transform:   transform.FromField("ContainerProperties.Deleted"),
			},
			{
				Name:        "public_access",
				Description: "Specifies whether data in the container may be accessed publicly and the level of access.",
				Type:        proto.ColumnType_STRING,
				Transform:   transform.FromField("ContainerProperties.PublicAccess").Transform(transformToString),
			},
			{
				Name:        "type",
				Description: "Specifies the type of the container.",
				Type:        proto.ColumnType_STRING,
			},
			{
				Name:        "default_encryption_scope",
				Description: "Default the container to use specified encryption scope for all writes.",
				Type:        proto.ColumnType_STRING,
				Transform:   transform.FromField("ContainerProperties.DefaultEncryptionScope"),
			},
			{
				Name:        "deleted_time",
				Description: "Specifies the time when the container was deleted.",
				Type:        proto.ColumnType_TIMESTAMP,
				Transform:   transform.FromField("ContainerProperties.DeletedTime").Transform(transform.NullIfZeroValue),
			},
			{
				Name:        "deny_encryption_scope_override",
				Description: "Indicates whether block override of encryption scope from the container default, or not.",
				Type:        proto.ColumnType_BOOL,
				Transform:   transform.FromField("ContainerProperties.DenyEncryptionScopeOverride"),
			},
			{
				Name:        "has_immutability_policy",
				Description: "The hasImmutabilityPolicy public property is set to true by SRP if ImmutabilityPolicy has been created for this container. The hasImmutabilityPolicy public property is set to false by SRP if ImmutabilityPolicy has not been created for this container.",
				Type:        proto.ColumnType_BOOL,
				Transform:   transform.FromField("ContainerProperties.HasImmutabilityPolicy"),
			},
			{
				Name:        "has_legal_hold",
				Description: "The hasLegalHold public property is set to true by SRP if there are at least one existing tag. The hasLegalHold public property is set to false by SRP if all existing legal hold tags are cleared out. There can be a maximum of 1000 blob containers with hasLegalHold=true for a given account.",
				Type:        proto.ColumnType_BOOL,
				Transform:   transform.FromField("ContainerProperties.HasLegalHold"),
			},
			{
				Name:        "last_modified_time",
				Description: "Specifies the date and time the container was last modified.",
				Type:        proto.ColumnType_TIMESTAMP,
				Transform:   transform.FromField("ContainerProperties.LastModifiedTime").Transform(transform.NullIfZeroValue),
			},
			{
				Name:        "lease_status",
				Description: "Specifies the lease status of the container.",
				Type:        proto.ColumnType_STRING,
				Transform:   transform.FromField("ContainerProperties.LeaseStatus").Transform(transformToString),
			},
			{
				Name:        "lease_state",
				Description: "Specifies the lease state of the container.",
				Type:        proto.ColumnType_STRING,
				Transform:   transform.FromField("ContainerProperties.LeaseState").Transform(transformToString),
			},
			{
				Name:        "lease_duration",
				Description: "Specifies whether the lease on a container is of infinite or fixed duration, only when the container is leased. Possible values are: 'Infinite', 'Fixed'.",
				Type:        proto.ColumnType_STRING,
				Transform:   transform.FromField("ContainerProperties.LeaseDuration").Transform(transformToString),
			},
			{
				Name:        "remaining_retention_days",
				Description: "Remaining retention days for soft deleted blob container.",
				Type:        proto.ColumnType_INT,
				Transform:   transform.FromField("ContainerProperties.RemainingRetentionDays"),
			},
			{
				Name:        "version",
				Description: "The version of the deleted blob container.",
				Type:        proto.ColumnType_STRING,
				Transform:   transform.FromField("ContainerProperties.Version"),
			},
			{
				Name:        "immutability_policy",
				Description: "The ImmutabilityPolicy property of the container.",
				Type:        proto.ColumnType_JSON,
				Transform:   transform.FromField("ContainerProperties.ImmutabilityPolicy"),
			},
			{
				Name:        "legal_hold",
				Description: "The LegalHold property of the container.",
				Type:        proto.ColumnType_JSON,
				Transform:   transform.FromField("ContainerProperties.LegalHold"),
			},
			{
				Name:        "metadata",
				Description: "A name-value pair to associate with the container as metadata.",
				Type:        proto.ColumnType_JSON,
				Transform:   transform.FromField("ContainerProperties.Metadata"),
			},

			// Steampipe standard columns
			{
				Name:        "title",
				Description: ColumnDescriptionTitle,
				Type:        proto.ColumnType_STRING,
				Transform:   transform.FromField("Name"),
			},
			{
				Name:        "akas",
				Description: ColumnDescriptionAkas,
				Type:        proto.ColumnType_JSON,
				Transform:   transform.FromField("ID").Transform(idToAkas),
			},

			// Azure standard columns
			{
				Name:        "resource_group",
				Description: ColumnDescriptionResourceGroup,
				Type:        proto.ColumnType_STRING,
				Transform:   transform.FromField("ResourceGroup"),
			},
		}),
	}
}

type ContainerInfo = struct {
	armstorage.ContainerProperties
	Name               string
	ID                 string
	Type               string
	StorageAccountName string
	ResourceGroup      string
	SubscriptionID     string
}

//// LIST FUNCTION

func listStorageContainers(ctx context.Context, d *plugin.QueryData, _ *plugin.HydrateData) (interface{}, error) {
	logger := plugin.Logger(ctx)
	logger.Trace("listStorageContainers")

	resourceGroup := d.EqualsQualString("resource_group")
	storageAccountName := d.EqualsQualString("storage_account_name")

	if resourceGroup == "" {
		return nil, fmt.Errorf("you must specify `resource_group` in the query parameter to query this table")
	}

	if storageAccountName == "" {
		return nil, fmt.Errorf("you must specify `storage_account_name` in the query parameter to query this table")
	}

	// Create session
	session, err := GetNewSessionUpdated(ctx, d)
	if err != nil {
		plugin.Logger(ctx).Error("azure_role_assignment.listIamRoleAssignments", "session_error", err)
		return nil, err
	}

	// Create client
	client, err := armstorage.NewBlobContainersClient(session.SubscriptionID, session.Cred, session.ClientOptions)
	if err != nil {
		logger.Error("error while creating containers client", "client_error", err)
		return nil, err
	}

	// Limiting the results
	limit := d.QueryContext.Limit
	maxResult := "1000"
	if d.QueryContext.Limit != nil {
		if *limit < 1000 {
			maxResult = types.IntToString(*limit)
		}
	}

	pager := client.NewListPager(resourceGroup, storageAccountName, &armstorage.BlobContainersClientListOptions{
		Maxpagesize: &maxResult,
	})

	for pager.More() {
		// apply rate limiting
		d.WaitForListRateLimit(ctx)

		resp, err := pager.NextPage(ctx)
		if err != nil {
			logger.Error("error listing next page", "api_error", err)
			return nil, err
		}

		for _, v := range resp.Value {
			d.StreamListItem(ctx, &ContainerInfo{
				ContainerProperties: *v.Properties,
				Name:                *v.Name,
				ID:                  *v.ID,
				Type:                *v.Type,
				StorageAccountName:  storageAccountName,
				ResourceGroup:       resourceGroup,
				SubscriptionID:      session.SubscriptionID,
			})

			// Check if the context has been canceled or if the limit has been hit (if specified)
			if d.RowsRemaining(ctx) == 0 {
				return nil, nil
			}
		}
	}

	return nil, nil
}

//// GET FUNCTION

func getStorageContainer(ctx context.Context, d *plugin.QueryData, _ *plugin.HydrateData) (interface{}, error) {
	logger := plugin.Logger(ctx)
	logger.Trace("getStorageContainer")

	resourceGroup := d.EqualsQualString("resource_group")
	storageAccountName := d.EqualsQualString("account_name")
	name := d.EqualsQualString("name")

	if resourceGroup == "" {
		return nil, fmt.Errorf("you must specify `resource_group` in the query parameter to query this table")
	}

	if storageAccountName == "" {
		return nil, fmt.Errorf("you must specify `account_name` in the query parameter to query this table")
	}

	if name == "" {
		return nil, fmt.Errorf("you must specify `name` in the query parameter to query this table")
	}

	// Create session
	session, err := GetNewSessionUpdated(ctx, d)
	if err != nil {
		plugin.Logger(ctx).Error("azure_role_assignment.listIamRoleAssignments", "session_error", err)
		return nil, err
	}

	// Create client
	client, err := armstorage.NewBlobContainersClient(session.SubscriptionID, session.Cred, session.ClientOptions)
	if err != nil {
		logger.Error("error while creating file shares client", "client_error", err)
		return nil, err
	}

	resp, err := client.Get(ctx, resourceGroup, storageAccountName, name, nil)
	if err != nil {
		logger.Error("error getting storage container", "api_error", err)
		return nil, err
	}

	if resp.ContainerProperties == nil {
		return nil, nil // No container found
	}

	return &ContainerInfo{
		ContainerProperties: *resp.ContainerProperties,
		Name:                *resp.Name,
		ID:                  *resp.ID,
		Type:                *resp.Type,
		StorageAccountName:  storageAccountName,
		ResourceGroup:       resourceGroup,
		SubscriptionID:      session.SubscriptionID,
	}, nil
}
