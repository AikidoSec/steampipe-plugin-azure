package azure

import (
	"context"
	"strings"

	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/containerregistry/armcontainerregistry"
	"github.com/turbot/steampipe-plugin-sdk/v5/grpc/proto"
	"github.com/turbot/steampipe-plugin-sdk/v5/plugin"
	"github.com/turbot/steampipe-plugin-sdk/v5/plugin/transform"
)

//// TABLE DEFINITION

func tableAzureContainerRegistry(_ context.Context) *plugin.Table {
	return &plugin.Table{
		Name:        "azure_container_registry",
		Description: "Azure Container Registry",
		Get: &plugin.GetConfig{
			KeyColumns: plugin.AllColumns([]string{"name", "resource_group"}),
			Hydrate:    getContainerRegistry,
			Tags: map[string]string{
				"service": "Microsoft.ContainerRegistry",
				"action":  "registries/read",
			},
			IgnoreConfig: &plugin.IgnoreConfig{
				ShouldIgnoreErrorFunc: isNotFoundError([]string{"ResourceGroupNotFound", "ResourceNotFound"}),
			},
		},
		List: &plugin.ListConfig{
			Hydrate: listContainerRegistries,
			Tags: map[string]string{
				"service": "Microsoft.ContainerRegistry",
				"action":  "registries/read",
			},
		},
		HydrateConfig: []plugin.HydrateConfig{
			{
				Func: listContainerRegistryLoginCredentials,
				Tags: map[string]string{
					"service": "Microsoft.ContainerRegistry",
					"action":  "registries/listCredentials/action",
				},
			},
			{
				Func: listContainerRegistryWebhooks,
				Tags: map[string]string{
					"service": "Microsoft.ContainerRegistry",
					"action":  "registries/webhooks/read",
				},
			},
			{
				Func: listContainerRegistryUsages,
				Tags: map[string]string{
					"service": "Microsoft.ContainerRegistry",
					"action":  "registries/listUsages/read",
				},
			},
		},
		Columns: azureColumns([]*plugin.Column{
			{
				Name:        "name",
				Description: "The name of the resource.",
				Type:        proto.ColumnType_STRING,
			},
			{
				Name:        "id",
				Description: "The unique id identifying the resource in subscription.",
				Type:        proto.ColumnType_STRING,
				Transform:   transform.FromGo(),
			},
			{
				Name:        "type",
				Description: "The type of the resource.",
				Type:        proto.ColumnType_STRING,
			},
			{
				Name:        "provisioning_state",
				Description: "The provisioning state of the container registry at the time the operation was called. Valid values are: 'Creating', 'Updating', 'Deleting', 'Succeeded', 'Failed', 'Canceled'.",
				Type:        proto.ColumnType_STRING,
				Transform:   transform.FromField("Properties.ProvisioningState").Transform(transformToString),
			},
			{
				Name:        "creation_date",
				Description: "The creation date of the container registry.",
				Type:        proto.ColumnType_TIMESTAMP,
				Transform:   transform.FromField("Properties.CreationDate"),
			},
			{
				Name:        "admin_user_enabled",
				Description: "Indicates whether the admin user is enabled, or not.",
				Type:        proto.ColumnType_BOOL,
				Transform:   transform.FromField("Properties.AdminUserEnabled"),
			},
			{
				Name:        "data_endpoint_enabled",
				Description: "Enable a single data endpoint per region for serving data.",
				Type:        proto.ColumnType_BOOL,
				Transform:   transform.FromField("Properties.DataEndpointEnabled"),
			},
			{
				Name:        "login_server",
				Description: "The URL that can be used to log into the container registry.",
				Type:        proto.ColumnType_STRING,
				Transform:   transform.FromField("Properties.LoginServer"),
			},
			{
				Name:        "network_rule_bypass_options",
				Description: "Indicates whether to allow trusted Azure services to access a network restricted registry. Valid values are: 'AzureServices', 'None'.",
				Type:        proto.ColumnType_STRING,
				Transform:   transform.FromField("Properties.NetworkRuleBypassOptions").Transform(transformToString),
			},
			{
				Name:        "public_network_access",
				Description: "Indicates whether or not public network access is allowed for the container registry. Valid values are: 'Enabled', 'Disabled'.",
				Type:        proto.ColumnType_STRING,
				Transform:   transform.FromField("Properties.PublicNetworkAccess").Transform(transformToString),
			},
			{
				Name:        "sku_name",
				Description: "The SKU name of the container registry. Required for registry creation. Valid values are: 'Classic', 'Basic', 'Standard', 'Premium'.",
				Type:        proto.ColumnType_STRING,
				Transform:   transform.FromField("SKU.Name").Transform(transformToString),
			},
			{
				Name:        "sku_tier",
				Description: "The SKU tier based on the SKU name. Valid values are: 'Classic', 'Basic', 'Standard', 'Premium'.",
				Type:        proto.ColumnType_STRING,
				Transform:   transform.FromField("SKU.Tier").Transform(transformToString),
			},
			{
				Name:        "status",
				Description: "The current status of the resource.",
				Type:        proto.ColumnType_STRING,
				Transform:   transform.FromField("Properties.Status.DisplayStatus"),
			},
			{
				Name:        "status_message",
				Description: "The detailed message for the status, including alerts and error messages.",
				Type:        proto.ColumnType_STRING,
				Transform:   transform.FromField("Properties.Status.Message"),
			},
			{
				Name:        "status_timestamp",
				Description: "The timestamp when the status was changed to the current value.",
				Type:        proto.ColumnType_TIMESTAMP,
				Transform:   transform.FromField("Properties.Status.Timestamp"),
			},
			{
				Name:        "storage_account_id",
				Description: "The resource ID of the storage account. Only applicable to Classic SKU.",
				Type:        proto.ColumnType_STRING,
				Transform:   transform.FromField("Properties.StorageAccount.ID"),
			},
			{
				Name:        "zone_redundancy",
				Description: "Indicates whether or not zone redundancy is enabled for this container registry. Valid values are: 'Enabled', 'Disabled'.",
				Type:        proto.ColumnType_STRING,
				Transform:   transform.FromField("Properties.ZoneRedundancy").Transform(transformToString),
			},
			{
				Name:        "data_endpoint_host_names",
				Description: "A list of host names that will serve data when dataEndpointEnabled is true.",
				Type:        proto.ColumnType_JSON,
				Transform:   transform.FromField("Properties.DataEndpointHostNames"),
			},
			{
				Name:        "encryption",
				Description: "The encryption settings of container registry.",
				Type:        proto.ColumnType_JSON,
				Transform:   transform.FromField("Properties.Encryption"),
			},
			{
				Name:        "identity",
				Description: "The identity of the container registry.",
				Type:        proto.ColumnType_JSON,
			},
			{
				Name:        "login_credentials",
				Description: "The login credentials for the specified container registry.",
				Type:        proto.ColumnType_JSON,
				Hydrate:     listContainerRegistryLoginCredentials,
				Transform:   transform.FromValue(),
			},
			{
				Name:        "network_rule_set",
				Description: "The network rule set for a container registry.",
				Type:        proto.ColumnType_JSON,
				Transform:   transform.FromField("Properties.NetworkRuleSet"),
			},
			{
				Name:        "policies",
				Description: "The policies for a container registry.",
				Type:        proto.ColumnType_JSON,
				Transform:   transform.FromField("Properties.Policies"),
			},
			{
				Name:        "private_endpoint_connections",
				Description: "A list of private endpoint connections for a container registry.",
				Type:        proto.ColumnType_JSON,
				Transform:   transform.FromField("Properties.PrivateEndpointConnections"),
			},
			{
				Name:        "system_data",
				Description: "Metadata pertaining to creation and last modification of the resource.",
				Type:        proto.ColumnType_JSON,
			},
			{
				Name:        "usages",
				Description: "Specifies the quota usages for the specified container registry.",
				Type:        proto.ColumnType_JSON,
				Hydrate:     listContainerRegistryUsages,
				Transform:   transform.FromValue(),
			},
			{
				Name:        "webhooks",
				Description: "Webhooks in Azure Container Registry provide a way to trigger custom actions in response to events happening within the registry.",
				Type:        proto.ColumnType_JSON,
				Hydrate:     listContainerRegistryWebhooks,
				Transform:   transform.FromValue(),
			},
			{
				Name:        "anonymous_pull_enabled",
				Description: "Enables registry-wide pull from unauthenticated clients.",
				Type:        proto.ColumnType_BOOL,
				Transform:   transform.FromField("Properties.AnonymousPullEnabled"),
			},
			{
				Name:        "auto_generated_domain_name_label_scope",
				Description: "Determines the domain name label reuse scope.",
				Type:        proto.ColumnType_STRING,
				Transform:   transform.FromField("Properties.AutoGeneratedDomainNameLabelScope").Transform(transformToString),
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
				Transform:   transform.FromField("ID").Transform(extractResourceGroupFromID),
			},
		}),
	}
}

//// LIST FUNCTION

func listContainerRegistries(ctx context.Context, d *plugin.QueryData, _ *plugin.HydrateData) (interface{}, error) {
	logger := plugin.Logger(ctx)
	logger.Trace("listContainerRegistries")

	session, err := GetNewSessionUpdated(ctx, d)
	if err != nil {
		logger.Error("azure_container_registry.listContainerRegistries", "session_error", err)
		return nil, err
	}

	f, err := armcontainerregistry.NewClientFactory(session.SubscriptionID, session.Cred, session.ClientOptions)
	if err != nil {
		return nil, err
	}

	client := f.NewRegistriesClient()

	pager := client.NewListPager(nil)
	for pager.More() {
		// Wait for rate limiter
		d.WaitForListRateLimit(ctx)

		resp, err := pager.NextPage(ctx)
		if err != nil {
			logger.Error("error listing next page", "api_error", err)
			return nil, err
		}

		for _, v := range resp.Value {
			d.StreamListItem(ctx, v)

			// Check if the context has been canceled or if the limit has been hit (if specified)
			if d.RowsRemaining(ctx) == 0 {
				return nil, nil
			}
		}
	}

	return nil, nil
}

//// HYDRATE FUNCTIONS

func getContainerRegistry(ctx context.Context, d *plugin.QueryData, _ *plugin.HydrateData) (interface{}, error) {
	logger := plugin.Logger(ctx)
	logger.Trace("getContainerRegistry")

	name := d.EqualsQuals["name"].GetStringValue()
	resourceGroup := d.EqualsQuals["resource_group"].GetStringValue()

	// Return nil, if no input provided
	if name == "" || resourceGroup == "" {
		return nil, nil
	}

	session, err := GetNewSessionUpdated(ctx, d)
	if err != nil {
		logger.Error("azure_container_registry.getContainerRegistry", "session_error", err)
		return nil, err
	}

	f, err := armcontainerregistry.NewClientFactory(session.SubscriptionID, session.Cred, session.ClientOptions)
	if err != nil {
		return nil, err
	}

	client := f.NewRegistriesClient()

	op, err := client.Get(ctx, resourceGroup, name, nil)
	if err != nil {
		return nil, err
	}

	return op, nil
}

func listContainerRegistryLoginCredentials(ctx context.Context, d *plugin.QueryData, h *plugin.HydrateData) (interface{}, error) {
	logger := plugin.Logger(ctx)
	logger.Trace("listContainerRegistryLoginCredentials")

	session, err := GetNewSessionUpdated(ctx, d)
	if err != nil {
		logger.Error("azure_container_registry.listContainerRegistryLoginCredentials", "session_error", err)
		return nil, err
	}

	f, err := armcontainerregistry.NewClientFactory(session.SubscriptionID, session.Cred, session.ClientOptions)
	if err != nil {
		return nil, err
	}

	client := f.NewRegistriesClient()

	data := h.Item.(*armcontainerregistry.Registry)
	resourceGroup := strings.Split(*data.ID, "/")[4]

	op, err := client.ListCredentials(ctx, resourceGroup, *data.Name, nil)
	if err != nil {
		if strings.Contains(err.Error(), "UnauthorizedForCredentialOperations") {
			return nil, nil
		}
		return nil, err
	}

	return op, nil
}

func listContainerRegistryWebhooks(ctx context.Context, d *plugin.QueryData, h *plugin.HydrateData) (interface{}, error) {
	logger := plugin.Logger(ctx)
	logger.Trace("listContainerRegistryWebhooks")

	session, err := GetNewSessionUpdated(ctx, d)
	if err != nil {
		logger.Error("azure_container_registry.listContainerRegistryWebhooks", "session_error", err)
		return nil, err
	}

	f, err := armcontainerregistry.NewClientFactory(session.SubscriptionID, session.Cred, session.ClientOptions)
	if err != nil {
		return nil, err
	}

	client := f.NewWebhooksClient()

	data := h.Item.(*armcontainerregistry.Registry)
	resourceGroup := strings.Split(*data.ID, "/")[4]

	webhooks := make([]*armcontainerregistry.Webhook, 0)

	pager := client.NewListPager(resourceGroup, *data.Name, nil)
	for pager.More() {
		// Wait for rate limiter
		d.WaitForListRateLimit(ctx)

		resp, err := pager.NextPage(ctx)
		if err != nil {
			logger.Error("error listing next page", "api_error", err)
			return nil, err
		}

		for _, v := range resp.Value {
			webhooks = append(webhooks, v)

			// Check if the context has been canceled or if the limit has been hit (if specified)
			if d.RowsRemaining(ctx) == 0 {
				return nil, nil
			}
		}
	}
	return webhooks, nil
}

func listContainerRegistryUsages(ctx context.Context, d *plugin.QueryData, h *plugin.HydrateData) (interface{}, error) {
	logger := plugin.Logger(ctx)
	logger.Trace("listContainerRegistryUsages")

	session, err := GetNewSessionUpdated(ctx, d)
	if err != nil {
		logger.Error("azure_container_registry.listContainerRegistryUsages", "session_error", err)
		return nil, err
	}

	f, err := armcontainerregistry.NewClientFactory(session.SubscriptionID, session.Cred, session.ClientOptions)
	if err != nil {
		return nil, err
	}

	client := f.NewRegistriesClient()

	data := h.Item.(*armcontainerregistry.Registry)
	resourceGroup := strings.Split(*data.ID, "/")[4]

	op, err := client.ListUsages(ctx, resourceGroup, *data.Name, nil)
	if err != nil {
		return nil, err
	}

	return op, nil
}
