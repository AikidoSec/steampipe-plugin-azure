package azure

import (
	"context"
	"fmt"

	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/storage/armstorage"
	"github.com/turbot/steampipe-plugin-sdk/v5/grpc/proto"
	"github.com/turbot/steampipe-plugin-sdk/v5/plugin"
	"github.com/turbot/steampipe-plugin-sdk/v5/plugin/transform"
)

//// TABLE DEFINITION

func tableAzureStorageTable(_ context.Context) *plugin.Table {
	return &plugin.Table{
		Name:        "azure_storage_table",
		Description: "Azure Storage Table",
		Get: &plugin.GetConfig{
			KeyColumns: plugin.AllColumns([]string{"name", "storage_account_name", "resource_group"}),
			Hydrate:    getStorageTable,
			Tags: map[string]string{
				"service": "Microsoft.Storage",
				"action":  "storageAccounts/tableServices/tables/read",
			},
			IgnoreConfig: &plugin.IgnoreConfig{
				ShouldIgnoreErrorFunc: isNotFoundError([]string{"ResourceNotFound", "ResourceGroupNotFound", "OperationNotAllowedOnKind", "TableNotFound"}),
			},
		},
		List: &plugin.ListConfig{
			Hydrate: listStorageTables,
			KeyColumns: plugin.KeyColumnSlice{
				{Name: "resource_group", Require: plugin.Required},
				{Name: "storage_account_name", Require: plugin.Required},
			},
			Tags: map[string]string{
				"service": "Microsoft.Storage",
				"action":  "storageAccounts/tableServices/tables/read",
			},
		},
		Columns: azureColumns([]*plugin.Column{
			{
				Name:        "name",
				Type:        proto.ColumnType_STRING,
				Description: "The friendly name that identifies the table service",
			},
			{
				Name:        "id",
				Description: "Contains ID to identify a table service uniquely",
				Type:        proto.ColumnType_STRING,
				Transform:   transform.FromField("ID"),
			},
			{
				Name:        "storage_account_name",
				Description: "An unique read-only string that changes whenever the resource is updated",
				Type:        proto.ColumnType_STRING,
				Transform:   transform.FromField("StorageAccountName"),
			},
			{
				Name:        "signed_identifiers",
				Description: "Type of the resource",
				Type:        proto.ColumnType_JSON,
				Transform:   transform.FromField("Table.SignedIdentifiers"),
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
				Transform:   transform.FromField("ResourceGroup").Transform(toLower),
			},
		}),
	}
}

type TableInfo = struct {
	Table              armstorage.TableProperties
	Name               string
	ID                 string
	Type               string
	StorageAccountName string
	ResourceGroup      string
	SubscriptionID     string
}

//// LIST FUNCTION

func listStorageTables(ctx context.Context, d *plugin.QueryData, _ *plugin.HydrateData) (interface{}, error) {
	logger := plugin.Logger(ctx)
	logger.Trace("listStorageTables")

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
	client, err := armstorage.NewTableClient(session.SubscriptionID, session.Cred, session.ClientOptions)
	if err != nil {
		logger.Error("error while creating tables client", "client_error", err)
		return nil, err
	}

	pager := client.NewListPager(resourceGroup, storageAccountName, nil)

	for pager.More() {
		// apply rate limiting
		d.WaitForListRateLimit(ctx)

		resp, err := pager.NextPage(ctx)
		if err != nil {
			logger.Error("error listing next page", "api_error", err)
			return nil, err
		}

		for _, v := range resp.Value {
			d.StreamListItem(ctx, &TableInfo{
				Table:              *v.TableProperties,
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

func getStorageTable(ctx context.Context, d *plugin.QueryData, _ *plugin.HydrateData) (interface{}, error) {
	logger := plugin.Logger(ctx)
	logger.Trace("getStorageTable")

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
	client, err := armstorage.NewTableClient(session.SubscriptionID, session.Cred, session.ClientOptions)
	if err != nil {
		logger.Error("error while creating file shares client", "client_error", err)
		return nil, err
	}

	resp, err := client.Get(ctx, resourceGroup, storageAccountName, name, nil)
	if err != nil {
		logger.Error("error getting storage container", "api_error", err)
		return nil, err
	}

	if resp.TableProperties == nil {
		return nil, nil // No table found
	}

	return &TableInfo{
		Table:              *resp.TableProperties,
		Name:               *resp.Name,
		ID:                 *resp.ID,
		Type:               *resp.Type,
		StorageAccountName: storageAccountName,
		ResourceGroup:      resourceGroup,
		SubscriptionID:     session.SubscriptionID,
	}, nil
}
