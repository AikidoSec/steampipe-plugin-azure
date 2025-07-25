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

func tableAzureStorageShareFile(_ context.Context) *plugin.Table {
	return &plugin.Table{
		Name:        "azure_storage_share_file",
		Description: "Azure Storage Share File",
		Get: &plugin.GetConfig{
			KeyColumns: plugin.AllColumns([]string{"name", "storage_account_name", "resource_group"}),
			Hydrate:    getStorageAccountsFileShare,
			Tags: map[string]string{
				"service": "Microsoft.Storage",
				"action":  "fileServices/shares/read",
			},
			IgnoreConfig: &plugin.IgnoreConfig{
				ShouldIgnoreErrorFunc: isNotFoundError([]string{"ResourceGroupNotFound", "ResourceNotFound", "404"}),
			},
		},
		List: &plugin.ListConfig{
			Hydrate: listStorageAccountsFileShares,
			KeyColumns: plugin.KeyColumnSlice{
				{Name: "resource_group", Require: plugin.Required},
				{Name: "storage_account_name", Require: plugin.Required},
			},
			Tags: map[string]string{
				"service": "Microsoft.Storage",
				"action":  "fileServices/shares/read",
			},
		},
		Columns: azureColumns([]*plugin.Column{
			{
				Name:        "name",
				Type:        proto.ColumnType_STRING,
				Description: "The name of the resource.",
			},
			{
				Name:        "storage_account_name",
				Type:        proto.ColumnType_STRING,
				Description: "The name of the storage account.",
			},
			{
				Name:        "id",
				Type:        proto.ColumnType_STRING,
				Description: "Fully qualified resource ID for the resource.",
				Transform:   transform.FromField("ID"),
			},
			{
				Name:        "type",
				Type:        proto.ColumnType_STRING,
				Description: "The type of the resource.",
			},
			{
				Name:        "access_tier",
				Type:        proto.ColumnType_STRING,
				Description: "Access tier for specific share. GpV2 account can choose between TransactionOptimized (default), Hot, and Cool.",
				Transform:   transform.FromField("FileShareProperties.AccessTier"),
			},
			{
				Name:        "access_tier_change_time",
				Type:        proto.ColumnType_TIMESTAMP,
				Description: "Indicates the last modification time for share access tier.",
				Transform:   transform.FromField("FileShareProperties.AccessTierChangeTime").Transform(transform.NullIfZeroValue),
			},
			{
				Name:        "access_tier_status",
				Type:        proto.ColumnType_STRING,
				Description: "Indicates if there is a pending transition for access tier.",
				Transform:   transform.FromField("FileShareProperties.AccessTierStatus"),
			},
			{
				Name:        "last_modified_time",
				Type:        proto.ColumnType_TIMESTAMP,
				Description: "Returns the date and time the share was last modified.",
				Transform:   transform.FromField("FileShareProperties.LastModifiedTime").Transform(transform.NullIfZeroValue),
			},
			{
				Name:        "deleted",
				Type:        proto.ColumnType_BOOL,
				Description: "Indicates whether the share was deleted.",
				Transform:   transform.FromField("FileShareProperties.Deleted"),
			},
			{
				Name:        "deleted_time",
				Type:        proto.ColumnType_TIMESTAMP,
				Description: "The deleted time if the share was deleted.",
				Transform:   transform.FromField("FileShareProperties.DeletedTime").Transform(transform.NullIfZeroValue),
			},
			{
				Name:        "enabled_protocols",
				Type:        proto.ColumnType_STRING,
				Description: "The authentication protocol that is used for the file share. Can only be specified when creating a share. Possible values include: 'SMB', 'NFS'.",
				Transform:   transform.FromField("FileShareProperties.EnabledProtocols"),
			},
			{
				Name:        "remaining_retention_days",
				Type:        proto.ColumnType_INT,
				Description: "Remaining retention days for share that was soft deleted.",
				Transform:   transform.FromField("FileShareProperties.RemainingRetentionDays"),
			},
			{
				Name:        "root_squash",
				Type:        proto.ColumnType_STRING,
				Description: "The property is for NFS share only. The default is NoRootSquash. Possible values include: 'NoRootSquash', 'RootSquash', 'AllSquash'.",
				Transform:   transform.FromField("FileShareProperties.RootSquash"),
			},
			{
				Name:        "share_quota",
				Type:        proto.ColumnType_INT,
				Description: "The maximum size of the share, in gigabytes. Must be greater than 0, and less than or equal to 5TB (5120). For Large File Shares, the maximum size is 102400.",
				Transform:   transform.FromField("FileShareProperties.ShareQuota"),
			},
			{
				Name:        "share_usage_bytes",
				Type:        proto.ColumnType_INT,
				Description: "The approximate size of the data stored on the share. Note that this value may not include all recently created or recently resized files.",
				Transform:   transform.FromField("FileShareProperties.ShareUsageBytes"),
			},
			{
				Name:        "version",
				Type:        proto.ColumnType_STRING,
				Description: "The version of the share.",
				Transform:   transform.FromField("FileShareProperties.Version"),
			},
			{
				Name:        "metadata",
				Type:        proto.ColumnType_JSON,
				Description: "A name-value pair to associate with the share as metadata.",
				Transform:   transform.FromField("FileShareProperties.Metadata"),
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

type FileShareInfo struct {
	armstorage.FileShareProperties
	Name               string
	ID                 string
	Type               string
	StorageAccountName string
	ResourceGroup      string
	SubscriptionID     string
}

// LIST FUNCTION
func listStorageAccountsFileShares(ctx context.Context, d *plugin.QueryData, _ *plugin.HydrateData) (interface{}, error) {
	logger := plugin.Logger(ctx)
	logger.Trace("listStorageAccountsFileShares")

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
	client, err := armstorage.NewFileSharesClient(session.SubscriptionID, session.Cred, session.ClientOptions)
	if err != nil {
		logger.Error("error while creating file shares client", "client_error", err)
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

	pager := client.NewListPager(resourceGroup, storageAccountName, &armstorage.FileSharesClientListOptions{
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

		for _, fileShare := range resp.Value {
			d.StreamListItem(ctx, &FileShareInfo{
				FileShareProperties: *fileShare.Properties,
				Name:                *fileShare.Name,
				ID:                  *fileShare.ID,
				Type:                *fileShare.Type,
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

func getStorageAccountsFileShare(ctx context.Context, d *plugin.QueryData, _ *plugin.HydrateData) (interface{}, error) {
	logger := plugin.Logger(ctx)
	logger.Trace("getStorageAccountsFileShare")

	resourceGroup := d.EqualsQualString("resource_group")
	storageAccountName := d.EqualsQualString("storage_account_name")
	name := d.EqualsQualString("name")

	if resourceGroup == "" {
		return nil, fmt.Errorf("you must specify `resource_group` in the query parameter to query this table")
	}

	if storageAccountName == "" {
		return nil, fmt.Errorf("you must specify `storage_account_name` in the query parameter to query this table")
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
	client, err := armstorage.NewFileSharesClient(session.SubscriptionID, session.Cred, session.ClientOptions)
	if err != nil {
		logger.Error("error while creating file shares client", "client_error", err)
		return nil, err
	}

	fs, err := client.Get(ctx, resourceGroup, storageAccountName, name, nil)
	if err != nil {
		logger.Error("error while getting file share", "file_share_error", err)
		return nil, err
	}

	if fs.FileShareProperties == nil {
		return nil, nil // No file share properties found, return nil
	}

	return &FileShareInfo{
		FileShareProperties: *fs.FileShareProperties,
		Name:                *fs.Name,
		ID:                  *fs.ID,
		Type:                *fs.Type,
		StorageAccountName:  storageAccountName,
		ResourceGroup:       resourceGroup,
	}, nil
}
