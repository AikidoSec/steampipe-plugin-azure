package azure

import (
	"context"

	"github.com/Azure/azure-sdk-for-go/profiles/latest/network/mgmt/network"
	"github.com/turbot/steampipe-plugin-sdk/v5/grpc/proto"
	"github.com/turbot/steampipe-plugin-sdk/v5/plugin"
	"github.com/turbot/steampipe-plugin-sdk/v5/plugin/transform"
)

func tableAzurePrivateLinkService(_ context.Context) *plugin.Table {
	return &plugin.Table{
		Name:        "azure_private_link_service",
		Description: "Azure Private Link Service",
		Get: &plugin.GetConfig{
			KeyColumns: plugin.AllColumns([]string{"name", "resource_group"}),
			Hydrate:    getPrivateLinkService,
			Tags: map[string]string{
				"service": "Microsoft.Network",
				"action":  "privateLinkServices/read",
			},
			IgnoreConfig: &plugin.IgnoreConfig{
				ShouldIgnoreErrorFunc: isNotFoundError([]string{"ResourceNotFound", "ResourceGroupNotFound", "404"}),
			},
		},
		List: &plugin.ListConfig{
			Hydrate: listPrivateLinkServices,
			Tags: map[string]string{
				"service": "Microsoft.Network",
				"action":  "privateLinkServices/read",
			},
		},
		Columns: azureColumns([]*plugin.Column{
			{
				Name:        "name",
				Description: "The friendly name that identifies the private link service.",
				Type:        proto.ColumnType_STRING,
				Transform:   transform.FromField("Name"),
			},
			{
				Name:        "id",
				Description: "Contains ID to identify a private link service uniquely.",
				Type:        proto.ColumnType_STRING,
				Transform:   transform.FromGo(),
			},
			{
				Name:        "etag",
				Description: "A unique read-only string that changes whenever the resource is updated.",
				Type:        proto.ColumnType_STRING,
			},
			{
				Name:        "type",
				Description: "The resource type of the private link service.",
				Type:        proto.ColumnType_STRING,
			},
			{
				Name:        "provisioning_state",
				Description: "The provisioning state of the private link service resource.",
				Type:        proto.ColumnType_STRING,
				Transform:   transform.FromField("PrivateLinkServiceProperties.ProvisioningState").Transform(transform.ToString),
			},
			{
				Name:        "alias",
				Description: "The alias of the private link service.",
				Type:        proto.ColumnType_STRING,
				Transform:   transform.FromField("PrivateLinkServiceProperties.Alias"),
			},
			{
				Name:        "enable_proxy_protocol",
				Description: "Indicates whether the private link service is enabled for proxy protocol.",
				Type:        proto.ColumnType_BOOL,
				Transform:   transform.FromField("PrivateLinkServiceProperties.EnableProxyProtocol"),
			},
			{
				Name:        "extended_location",
				Description: "The extended location of the private link service.",
				Type:        proto.ColumnType_JSON,
			},
			{
				Name:        "fqdns",
				Description: "The list of FQDNs associated with the private link service.",
				Type:        proto.ColumnType_JSON,
				Transform:   transform.FromField("PrivateLinkServiceProperties.Fqdns"),
			},
			{
				Name:        "visibility_subscriptions",
				Description: "The subscriptions allowed in the visibility list of the private link service.",
				Type:        proto.ColumnType_JSON,
				Transform:   transform.FromField("PrivateLinkServiceProperties.Visibility.Subscriptions"),
			},
			{
				Name:        "auto_approval_subscriptions",
				Description: "The subscriptions included in the auto-approval list of the private link service.",
				Type:        proto.ColumnType_JSON,
				Transform:   transform.FromField("PrivateLinkServiceProperties.AutoApproval.Subscriptions"),
			},
			{
				Name:        "ip_configurations",
				Description: "An array of private link service IP configurations.",
				Type:        proto.ColumnType_JSON,
				Transform:   transform.FromField("PrivateLinkServiceProperties.IPConfigurations"),
			},
			{
				Name:        "load_balancer_frontend_ip_configurations",
				Description: "An array of references to the load balancer frontend IP configurations.",
				Type:        proto.ColumnType_JSON,
				Transform:   transform.FromField("PrivateLinkServiceProperties.LoadBalancerFrontendIPConfigurations"),
			},
			{
				Name:        "network_interfaces",
				Description: "An array of references to the network interfaces created for this private link service.",
				Type:        proto.ColumnType_JSON,
				Transform:   transform.FromField("PrivateLinkServiceProperties.NetworkInterfaces"),
			},
			{
				Name:        "private_endpoint_connections",
				Description: "An array of private endpoint connections to this private link service.",
				Type:        proto.ColumnType_JSON,
				Transform:   transform.FromField("PrivateLinkServiceProperties.PrivateEndpointConnections"),
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

func listPrivateLinkServices(ctx context.Context, d *plugin.QueryData, _ *plugin.HydrateData) (interface{}, error) {
	session, err := GetNewSession(ctx, d, "MANAGEMENT")
	if err != nil {
		return nil, err
	}
	subscriptionID := session.SubscriptionID

	client := network.NewPrivateLinkServicesClientWithBaseURI(session.ResourceManagerEndpoint, subscriptionID)
	client.Authorizer = session.Authorizer

	ApplyRetryRules(ctx, &client, d.Connection)

	result, err := client.ListBySubscription(ctx)
	if err != nil {
		return nil, err
	}

	for _, service := range result.Values() {
		d.StreamListItem(ctx, service)
		if d.RowsRemaining(ctx) == 0 {
			return nil, nil
		}
	}

	for result.NotDone() {
		d.WaitForListRateLimit(ctx)

		err = result.NextWithContext(ctx)
		if err != nil {
			return nil, err
		}

		for _, service := range result.Values() {
			d.StreamListItem(ctx, service)
			if d.RowsRemaining(ctx) == 0 {
				return nil, nil
			}
		}
	}

	return nil, nil
}

func getPrivateLinkService(ctx context.Context, d *plugin.QueryData, h *plugin.HydrateData) (interface{}, error) {
	plugin.Logger(ctx).Trace("getPrivateLinkService")

	name := d.EqualsQuals["name"].GetStringValue()
	resourceGroup := d.EqualsQuals["resource_group"].GetStringValue()

	if name == "" || resourceGroup == "" {
		return nil, nil
	}

	session, err := GetNewSession(ctx, d, "MANAGEMENT")
	if err != nil {
		return nil, err
	}
	subscriptionID := session.SubscriptionID

	client := network.NewPrivateLinkServicesClientWithBaseURI(session.ResourceManagerEndpoint, subscriptionID)
	client.Authorizer = session.Authorizer

	ApplyRetryRules(ctx, &client, d.Connection)

	op, err := client.Get(ctx, resourceGroup, name, "")
	if err != nil {
		return nil, err
	}

	if op.ID != nil {
		return op, nil
	}

	return nil, nil
}
