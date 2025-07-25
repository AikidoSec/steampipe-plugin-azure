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

func tableAzureStorageQueue(_ context.Context) *plugin.Table {
	return &plugin.Table{
		Name:        "azure_storage_queue",
		Description: "Azure Storage Queue",
		Get: &plugin.GetConfig{
			KeyColumns: plugin.AllColumns([]string{"name", "storage_account_name", "resource_group"}),
			Hydrate:    getStorageQueue,
			Tags: map[string]string{
				"service": "Microsoft.Storage",
				"action":  "storageAccounts/queueServices/queues/read",
			},
			IgnoreConfig: &plugin.IgnoreConfig{
				ShouldIgnoreErrorFunc: isNotFoundError([]string{"ResourceNotFound", "ResourceGroupNotFound", "QueueNotFound"}),
			},
		},
		List: &plugin.ListConfig{
			Hydrate: listStorageQueues,
			KeyColumns: plugin.KeyColumnSlice{
				{Name: "resource_group", Require: plugin.Required},
				{Name: "storage_account_name", Require: plugin.Required},
			},
			Tags: map[string]string{
				"service": "Microsoft.Storage",
				"action":  "storageAccounts/queueServices/queues/read",
			},
		},
		Columns: azureColumns([]*plugin.Column{
			{
				Name:        "name",
				Type:        proto.ColumnType_STRING,
				Description: "The friendly name that identifies the queue.",
			},
			{
				Name:        "id",
				Description: "Contains ID to identify a queue uniquely.",
				Type:        proto.ColumnType_STRING,
				Transform:   transform.FromField("ID"),
			},
			{
				Name:        "storage_account_name",
				Description: "An unique read-only string that changes whenever the resource is updated.",
				Type:        proto.ColumnType_STRING,
				Transform:   transform.FromField("StorageAccountName"),
			},
			{
				Name:        "type",
				Description: "Type of the resource.",
				Type:        proto.ColumnType_STRING,
				Transform:   transform.FromField("Type"),
			},
			{
				Name:        "metadata",
				Description: "A name-value pair that represents queue metadata.",
				Type:        proto.ColumnType_JSON,
				Transform:   transform.FromField("Metadata"),
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
				Name:        "region",
				Description: ColumnDescriptionRegion,
				Type:        proto.ColumnType_STRING,
				Transform:   transform.FromField("Location").Transform(toLower),
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

type QueueInfo = struct {
	Metadata           map[string]string
	Name               string
	ID                 string
	Type               string
	StorageAccountName string
	ResourceGroup      string
	SubscriptionID     string
}

//// LIST FUNCTION

func listStorageQueues(ctx context.Context, d *plugin.QueryData, _ *plugin.HydrateData) (interface{}, error) {
	logger := plugin.Logger(ctx)
	logger.Trace("listStorageQueues")

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
	client, err := armstorage.NewQueueClient(session.SubscriptionID, session.Cred, session.ClientOptions)
	if err != nil {
		logger.Error("error while creating queues client", "client_error", err)
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

	pager := client.NewListPager(resourceGroup, storageAccountName, &armstorage.QueueClientListOptions{
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
			metadata := make(map[string]string)
			for key, value := range v.QueueProperties.Metadata {
				metadata[key] = *value
			}
			d.StreamListItem(ctx, &QueueInfo{
				Metadata:           metadata,
				Name:               *v.Name,
				ID:                 *v.ID,
				Type:               *v.Type,
				StorageAccountName: storageAccountName,
				ResourceGroup:      resourceGroup,
				SubscriptionID:     session.SubscriptionID,
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

func getStorageQueue(ctx context.Context, d *plugin.QueryData, _ *plugin.HydrateData) (interface{}, error) {
	logger := plugin.Logger(ctx)
	logger.Trace("getStorageQueue")

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
	client, err := armstorage.NewQueueClient(session.SubscriptionID, session.Cred, session.ClientOptions)
	if err != nil {
		logger.Error("error while creating file shares client", "client_error", err)
		return nil, err
	}

	resp, err := client.Get(ctx, resourceGroup, storageAccountName, name, nil)
	if err != nil {
		logger.Error("error getting storage container", "api_error", err)
		return nil, err
	}

	if resp.QueueProperties == nil {
		return nil, nil // No queue found
	}

	metadata := make(map[string]string)
	for key, value := range resp.QueueProperties.Metadata {
		metadata[key] = *value
	}

	return &QueueInfo{
		Metadata:           metadata,
		Name:               *resp.Name,
		ID:                 *resp.ID,
		Type:               *resp.Type,
		StorageAccountName: storageAccountName,
		ResourceGroup:      resourceGroup,
		SubscriptionID:     session.SubscriptionID,
	}, nil
}
