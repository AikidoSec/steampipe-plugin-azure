package azure

import (
	"context"
	"strings"

	"github.com/Azure/azure-sdk-for-go/profiles/preview/preview/monitor/mgmt/insights"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/eventhub/armeventhub"
	"github.com/turbot/steampipe-plugin-sdk/v5/grpc/proto"
	"github.com/turbot/steampipe-plugin-sdk/v5/plugin"
	"github.com/turbot/steampipe-plugin-sdk/v5/plugin/transform"
)

//// TABLE DEFINITION

func tableAzureEventHubNamespace(_ context.Context) *plugin.Table {
	return &plugin.Table{
		Name:        "azure_eventhub_namespace",
		Description: "Azure Event Hub Namespace",
		Get: &plugin.GetConfig{
			KeyColumns: plugin.AllColumns([]string{"name", "resource_group"}),
			Hydrate:    getEventHubNamespace,
			Tags: map[string]string{
				"service": "Microsoft.EventHub",
				"action":  "namespaces/read",
			},
			IgnoreConfig: &plugin.IgnoreConfig{
				ShouldIgnoreErrorFunc: isNotFoundError([]string{"ResourceNotFound", "ResourceGroupNotFound", "400", "404"}),
			},
		},
		List: &plugin.ListConfig{
			Hydrate: listEventHubNamespaces,
			Tags: map[string]string{
				"service": "Microsoft.EventHub",
				"action":  "namespaces/read",
			},
		},
		HydrateConfig: []plugin.HydrateConfig{
			{
				Func: listEventHubNamespaceDiagnosticSettings,
				Tags: map[string]string{
					"service": "Microsoft.EventHub",
					"action":  "namespaces/providers/Microsoft.Insights/diagnosticSettings/read",
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
				Description: "The ID of the resource.",
				Type:        proto.ColumnType_STRING,
				Transform:   transform.FromGo(),
			},
			{
				Name:        "type",
				Description: "The resource type.",
				Type:        proto.ColumnType_STRING,
			},
			{
				Name:        "provisioning_state",
				Description: "Provisioning state of the namespace.",
				Type:        proto.ColumnType_STRING,
				Transform:   transform.FromField("Properties.ProvisioningState"),
			},
			{
				Name:        "created_at",
				Description: "The time the namespace was created.",
				Type:        proto.ColumnType_TIMESTAMP,
				Transform:   transform.FromField("Properties.CreatedAt"),
			},
			{
				Name:        "cluster_arm_id",
				Description: "Cluster ARM ID of the namespace.",
				Type:        proto.ColumnType_STRING,
				Transform:   transform.FromField("Properties.ClusterArmID"),
			},
			{
				Name:        "is_auto_inflate_enabled",
				Description: "Indicates whether auto-inflate is enabled for eventhub namespace.",
				Type:        proto.ColumnType_BOOL,
				Transform:   transform.FromField("Properties.IsAutoInflateEnabled"),
			},
			{
				Name:        "kafka_enabled",
				Description: "Indicates whether kafka is enabled for eventhub namespace, or not.",
				Type:        proto.ColumnType_BOOL,
				Transform:   transform.FromField("Properties.KafkaEnabled"),
			},
			{
				Name:        "maximum_throughput_units",
				Description: "Upper limit of throughput units when auto-inflate is enabled, value should be within 0 to 20 throughput units.",
				Type:        proto.ColumnType_INT,
				Transform:   transform.FromField("Properties.MaximumThroughputUnits"),
			},
			{
				Name:        "metric_id",
				Description: "Identifier for azure insights metrics.",
				Type:        proto.ColumnType_STRING,
				Transform:   transform.FromField("Properties.Metric_id"),
			},
			{
				Name:        "service_bus_endpoint",
				Description: "Endpoint you can use to perform service bus operations.",
				Type:        proto.ColumnType_STRING,
				Transform:   transform.FromField("Properties.ServiceBusEndpoint"),
			},
			{
				Name:        "sku_capacity",
				Description: "The Event Hubs throughput units, value should be 0 to 20 throughput units.",
				Type:        proto.ColumnType_INT,
				Transform:   transform.FromField("SKU.Capacity"),
			},
			{
				Name:        "sku_name",
				Description: "Name of this SKU. Possible values include: 'Basic', 'Standard'.",
				Type:        proto.ColumnType_STRING,
				Transform:   transform.FromField("SKU.Name").Transform(transform.ToString),
			},
			{
				Name:        "sku_tier",
				Description: "The billing tier of this particular SKU. Valid values are: 'Basic', 'Standard', 'Premium'.",
				Type:        proto.ColumnType_STRING,
				Transform:   transform.FromField("SKU.Tier"),
			},
			{
				Name:        "updated_at",
				Description: "The time the namespace was updated.",
				Type:        proto.ColumnType_TIMESTAMP,
				Transform:   transform.FromField("Properties.UpdatedAt"),
			},
			{
				Name:        "zone_redundant",
				Description: "Enabling this property creates a standard event hubs namespace in regions supported availability zones.",
				Type:        proto.ColumnType_BOOL,
				Transform:   transform.FromField("Properties.ZoneRedundant"),
			},
			{
				Name:        "network_rule_set",
				Description: "The network rule set for the event hub namespace.",
				Type:        proto.ColumnType_JSON,
				Transform:   transform.FromField("Properties.NetworkRuleSet"),
			},
			{
				Name:        "diagnostic_settings",
				Description: "A list of active diagnostic settings for the eventhub namespace.",
				Type:        proto.ColumnType_JSON,
				Hydrate:     listEventHubNamespaceDiagnosticSettings,
				Transform:   transform.FromValue(),
			},
			{
				Name:        "encryption",
				Description: "Properties of BYOK encryption description.",
				Type:        proto.ColumnType_JSON,
				Transform:   transform.FromField("Properties.Encryption"),
			},
			{
				Name:        "identity",
				Description: "Describes the properties of BYOK encryption description.",
				Type:        proto.ColumnType_JSON,
				Transform:   transform.FromField("Properties.Encryption"),
			},
			{
				Name:        "network_rule_set",
				Description: "Describes the network rule set for specified namespace. The EventHub Namespace must be Premium in order to attach a EventHub Namespace Network Rule Set.",
				Type:        proto.ColumnType_JSON,
				Hydrate:     getNetworkRuleSet,
				Transform:   transform.FromValue(),
			},
			{
				Name:        "private_endpoint_connections",
				Description: "The private endpoint connections of the namespace.",
				Type:        proto.ColumnType_JSON,
				Hydrate:     listEventHubNamespacePrivateEndpointConnections,
				Transform:   transform.FromValue(),
			},
			{
				Name:        "minimum_tls_version_allowed",
				Description: "This determines the minimum TLS version required for traffic to the domain.",
				Type:        proto.ColumnType_STRING,
				Transform:   transform.FromField("Properties.MinimumTLSVersion").Transform(transformToString),
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
				Transform:   transform.FromField("Location").Transform(formatRegion).Transform(toLower),
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

func listEventHubNamespaces(ctx context.Context, d *plugin.QueryData, _ *plugin.HydrateData) (interface{}, error) {
	logger := plugin.Logger(ctx)
	logger.Trace("listEventHubNamespaces")

	session, err := GetNewSessionUpdated(ctx, d)
	if err != nil {
		logger.Error("azure_eventhub_namespace.listEventHubNamespaces", "session_error", err)
		return nil, err
	}

	f, err := armeventhub.NewClientFactory(session.SubscriptionID, session.Cred, session.ClientOptions)
	if err != nil {
		return nil, err
	}

	client := f.NewNamespacesClient()

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

func getEventHubNamespace(ctx context.Context, d *plugin.QueryData, _ *plugin.HydrateData) (interface{}, error) {
	logger := plugin.Logger(ctx)
	logger.Trace("getEventHubNamespace")

	name := d.EqualsQuals["name"].GetStringValue()
	resourceGroup := d.EqualsQuals["resource_group"].GetStringValue()

	// Return nil, if no input provided
	if name == "" || resourceGroup == "" {
		return nil, nil
	}

	session, err := GetNewSessionUpdated(ctx, d)
	if err != nil {
		logger.Error("azure_eventhub_namespace.getEventHubNamespace", "session_error", err)
		return nil, err
	}

	f, err := armeventhub.NewClientFactory(session.SubscriptionID, session.Cred, session.ClientOptions)
	if err != nil {
		return nil, err
	}

	client := f.NewNamespacesClient()
	op, err := client.Get(ctx, resourceGroup, name, nil)
	if err != nil {
		logger.Error("getEventGridDomain", "get", err)
		return nil, err
	}

	return op.EHNamespace, nil
}

func getNetworkRuleSet(ctx context.Context, d *plugin.QueryData, h *plugin.HydrateData) (interface{}, error) {
	logger := plugin.Logger(ctx)
	logger.Trace("getNetworkRuleSet")

	namespace := h.Item.(*armeventhub.EHNamespace)
	resourceGroupName := strings.Split(*namespace.ID, "/")[4]

	session, err := GetNewSessionUpdated(ctx, d)
	if err != nil {
		logger.Error("azure_eventhub_namespace.getEventHubNamespace", "session_error", err)
		return nil, err
	}

	f, err := armeventhub.NewClientFactory(session.SubscriptionID, session.Cred, session.ClientOptions)
	if err != nil {
		return nil, err
	}
	client := f.NewNamespacesClient()

	op, err := client.GetNetworkRuleSet(ctx, resourceGroupName, *namespace.Name, nil)
	if err != nil {
		return nil, err
	}

	return op, nil
}

func listEventHubNamespaceDiagnosticSettings(ctx context.Context, d *plugin.QueryData, h *plugin.HydrateData) (interface{}, error) {
	plugin.Logger(ctx).Trace("listEventHubNamespaceDiagnosticSettings")
	id := *h.Item.(*armeventhub.EHNamespace).ID

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
		plugin.Logger(ctx).Error("listEventHubNamespaceDiagnosticSettings", "list", err)
		return nil, err
	}

	// If we return the API response directly, the output does not provide all
	// the contents of DiagnosticSettings
	var diagnosticSettings []map[string]interface{}
	for _, i := range *op.Value {
		objectMap := make(map[string]interface{})
		if i.ID != nil {
			objectMap["id"] = i.ID
		}
		if i.Name != nil {
			objectMap["name"] = i.Name
		}
		if i.Type != nil {
			objectMap["type"] = i.Type
		}
		if i.DiagnosticSettings != nil {
			objectMap["properties"] = i.DiagnosticSettings
		}
		diagnosticSettings = append(diagnosticSettings, objectMap)
	}
	return diagnosticSettings, nil
}

func listEventHubNamespacePrivateEndpointConnections(ctx context.Context, d *plugin.QueryData, h *plugin.HydrateData) (interface{}, error) {
	logger := plugin.Logger(ctx)
	logger.Trace("listEventHubNamespacePrivateEndpointConnections")

	namespace := h.Item.(*armeventhub.EHNamespace)
	resourceGroup := strings.Split(*namespace.ID, "/")[4]
	namespaceName := *namespace.Name

	session, err := GetNewSessionUpdated(ctx, d)
	if err != nil {
		logger.Error("azure_eventhub_namespace.listEventHubNamespacePrivateEndpointConnections", "session_error", err)
		return nil, err
	}

	f, err := armeventhub.NewClientFactory(session.SubscriptionID, session.Cred, session.ClientOptions)
	if err != nil {
		return nil, err
	}
	client := f.NewPrivateEndpointConnectionsClient()

	pager := client.NewListPager(resourceGroup, namespaceName, nil)

	var eventHubNamespacePrivateEndpointConnections []map[string]any
	for pager.More() {
		// Wait for rate limiter
		d.WaitForListRateLimit(ctx)

		resp, err := pager.NextPage(ctx)
		if err != nil {
			logger.Error("error listing next page", "api_error", err)
			return nil, err
		}

		for _, v := range resp.Value {
			eventHubNamespacePrivateEndpointConnections = append(eventHubNamespacePrivateEndpointConnections, extractEventHubNamespacePrivateEndpointConnections(v))

			// Check if the context has been canceled or if the limit has been hit (if specified)
			if d.RowsRemaining(ctx) == 0 {
				return nil, nil
			}
		}
	}

	return nil, nil
}

// If we return the API response directly, the output will not provide the properties of PrivateEndpointConnections

func extractEventHubNamespacePrivateEndpointConnections(i *armeventhub.PrivateEndpointConnection) map[string]interface{} {
	eventHubNamespacePrivateEndpointConnection := make(map[string]interface{})
	if i.ID != nil {
		eventHubNamespacePrivateEndpointConnection["id"] = *i.ID
	}
	if i.Name != nil {
		eventHubNamespacePrivateEndpointConnection["name"] = *i.Name
	}
	if i.Type != nil {
		eventHubNamespacePrivateEndpointConnection["type"] = *i.Type
	}
	if i.Properties != nil {
		if i.Properties.ProvisioningState != nil {
			eventHubNamespacePrivateEndpointConnection["provisioningState"] = *i.Properties.ProvisioningState
		}
		if i.Properties.PrivateLinkServiceConnectionState != nil {
			eventHubNamespacePrivateEndpointConnection["privateLinkServiceConnectionState"] = *i.Properties.PrivateLinkServiceConnectionState
		}
		if i.Properties.PrivateEndpoint != nil && i.Properties.PrivateEndpoint.ID != nil {
			eventHubNamespacePrivateEndpointConnection["privateEndpointPropertyID"] = *i.Properties.PrivateEndpoint.ID
		}
	}
	return eventHubNamespacePrivateEndpointConnection
}
