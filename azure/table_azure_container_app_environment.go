package azure

import (
	"context"

	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/appcontainers/armappcontainers"
	"github.com/turbot/steampipe-plugin-sdk/v5/grpc/proto"
	"github.com/turbot/steampipe-plugin-sdk/v5/plugin"
	"github.com/turbot/steampipe-plugin-sdk/v5/plugin/transform"
)

//// TABLE DEFINITION

func tableAzureContainerAppEnvironment(_ context.Context) *plugin.Table {
	return &plugin.Table{
		Name:        "azure_container_app_environment",
		Description: "Azure Container App Environment",
		Get: &plugin.GetConfig{
			KeyColumns: plugin.AllColumns([]string{"name", "resource_group"}),
			Hydrate:    getContainerAppEnvironment,
			Tags: map[string]string{
				"service": "Microsoft.App",
				"action":  "managedEnvironments/read",
			},
			IgnoreConfig: &plugin.IgnoreConfig{
				ShouldIgnoreErrorFunc: isNotFoundError([]string{"ResourceNotFound", "ResourceGroupNotFound", "404"}),
			},
		},
		List: &plugin.ListConfig{
			Hydrate: listContainerAppEnvironments,
			Tags: map[string]string{
				"service": "Microsoft.App",
				"action":  "managedEnvironments/read",
			},
		},
		Columns: azureColumns([]*plugin.Column{
			{
				Name:        "name",
				Description: "The name of the managed environment.",
				Type:        proto.ColumnType_STRING,
			},
			{
				Name:        "id",
				Description: "The resource ID.",
				Type:        proto.ColumnType_STRING,
				Transform:   transform.FromField("ID"),
			},
			{
				Name:        "type",
				Description: "The resource type.",
				Type:        proto.ColumnType_STRING,
			},
			{
				Name:        "provisioning_state",
				Description: "The provisioning state of the managed environment.",
				Type:        proto.ColumnType_STRING,
				Transform:   transform.FromField("Properties.ProvisioningState").Transform(transformToString),
			},
			{
				Name:        "default_domain",
				Description: "The default domain name for the managed environment.",
				Type:        proto.ColumnType_STRING,
				Transform:   transform.FromField("Properties.DefaultDomain"),
			},
			{
				Name:        "static_ip",
				Description: "The static IP address of the managed environment.",
				Type:        proto.ColumnType_IPADDR,
				Transform:   transform.FromField("Properties.StaticIP"),
			},
			{
				Name:        "zone_redundant",
				Description: "Indicates whether the managed environment is zone redundant.",
				Type:        proto.ColumnType_BOOL,
				Transform:   transform.FromField("Properties.ZoneRedundant"),
			},
			{
				Name:        "deployment_errors",
				Description: "Any errors that occurred during deployment or deployment validation.",
				Type:        proto.ColumnType_STRING,
				Transform:   transform.FromField("Properties.DeploymentErrors"),
			},
			{
				Name:        "dapr_ai_instrumentation_key",
				Description: "The Azure Monitor instrumentation key used by Dapr to export service-to-service communication telemetry.",
				Type:        proto.ColumnType_STRING,
				Transform:   transform.FromField("Properties.DaprAIInstrumentationKey"),
			},
			{
				Name:        "app_logs_configuration",
				Description: "The application logs configuration for the managed environment.",
				Type:        proto.ColumnType_JSON,
				Transform:   transform.FromField("Properties.AppLogsConfiguration"),
			},
			{
				Name:        "vnet_configuration",
				Description: "The virtual network configuration for the managed environment.",
				Type:        proto.ColumnType_JSON,
				Transform:   transform.FromField("Properties.VnetConfiguration"),
			},
			{
				Name:        "properties",
				Description: "The managed environment resource properties.",
				Type:        proto.ColumnType_JSON,
			},
			{
				Name:        "system_data",
				Description: "Azure Resource Manager metadata containing created and modified information.",
				Type:        proto.ColumnType_JSON,
			},
			{
				Name:        "created_time",
				Description: "The timestamp of resource creation.",
				Type:        proto.ColumnType_TIMESTAMP,
				Transform:   transform.FromField("SystemData.CreatedAt"),
			},
			{
				Name:        "changed_time",
				Description: "The timestamp of resource last modification.",
				Type:        proto.ColumnType_TIMESTAMP,
				Transform:   transform.FromField("SystemData.LastModifiedAt"),
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

func listContainerAppEnvironments(ctx context.Context, d *plugin.QueryData, _ *plugin.HydrateData) (interface{}, error) {
	session, err := GetNewSessionUpdated(ctx, d)
	if err != nil {
		plugin.Logger(ctx).Error("azure_container_app_environment.listContainerAppEnvironments", "session_error", err)
		return nil, err
	}

	client, err := armappcontainers.NewManagedEnvironmentsClient(session.SubscriptionID, session.Cred, session.ClientOptions)
	if err != nil {
		plugin.Logger(ctx).Error("azure_container_app_environment.listContainerAppEnvironments", "client_error", err)
		return nil, err
	}

	pager := client.NewListBySubscriptionPager(nil)
	for pager.More() {
		d.WaitForListRateLimit(ctx)
		
		page, err := pager.NextPage(ctx)
		if err != nil {
			plugin.Logger(ctx).Error("azure_container_app_environment.listContainerAppEnvironments", "api_error", err)
			return nil, err
		}

		for _, environment := range page.Value {
			d.StreamListItem(ctx, environment)
			if d.RowsRemaining(ctx) == 0 {
				return nil, nil
			}
		}
	}

	return nil, nil
}

//// HYDRATE FUNCTIONS

func getContainerAppEnvironment(ctx context.Context, d *plugin.QueryData, _ *plugin.HydrateData) (interface{}, error) {
	name := d.EqualsQualString("name")
	resourceGroup := d.EqualsQualString("resource_group")

	if name == "" || resourceGroup == "" {
		return nil, nil
	}

	session, err := GetNewSessionUpdated(ctx, d)
	if err != nil {
		plugin.Logger(ctx).Error("azure_container_app_environment.getContainerAppEnvironment", "session_error", err)
		return nil, err
	}

	client, err := armappcontainers.NewManagedEnvironmentsClient(session.SubscriptionID, session.Cred, session.ClientOptions)
	if err != nil {
		plugin.Logger(ctx).Error("azure_container_app_environment.getContainerAppEnvironment", "client_error", err)
		return nil, err
	}

	environment, err := client.Get(ctx, resourceGroup, name, nil)
	if err != nil {
		plugin.Logger(ctx).Error("azure_container_app_environment.getContainerAppEnvironment", "api_error", err)
		return nil, err
	}

	if environment.ID != nil {
		return &environment.ManagedEnvironment, nil
	}

	return nil, nil
}
