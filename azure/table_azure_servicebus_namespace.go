package azure

import (
	"context"
	"strings"

	"github.com/Azure/azure-sdk-for-go/profiles/preview/preview/monitor/mgmt/insights"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/servicebus/armservicebus/v2"

	"github.com/turbot/steampipe-plugin-sdk/v5/grpc/proto"
	"github.com/turbot/steampipe-plugin-sdk/v5/plugin"
	"github.com/turbot/steampipe-plugin-sdk/v5/plugin/transform"
)

//// TABLE DEFINITION

func tableAzureServiceBusNamespace(_ context.Context) *plugin.Table {
	return &plugin.Table{
		Name:        "azure_servicebus_namespace",
		Description: "Azure ServiceBus Namespace",
		Get: &plugin.GetConfig{
			KeyColumns: plugin.AllColumns([]string{"name", "resource_group"}),
			Hydrate:    getServiceBusNamespace,
			Tags: map[string]string{
				"service": "Microsoft.ServiceBus",
				"action":  "namespaces/read",
			},
			IgnoreConfig: &plugin.IgnoreConfig{
				ShouldIgnoreErrorFunc: isNotFoundError([]string{"ResourceGroupNotFound", "ResourceNotFound", "400", "404"}),
			},
		},
		List: &plugin.ListConfig{
			Hydrate: listServiceBusNamespaces,
			Tags: map[string]string{
				"service": "Microsoft.ServiceBus",
				"action":  "namespaces/read",
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
				Description: "The provisioning state of the namespace.",
				Type:        proto.ColumnType_STRING,
				Transform:   transform.FromField("Properties.ProvisioningState"),
			},
			{
				Name:        "zone_redundant",
				Description: "Enabling this property creates a Premium Service Bus Namespace in regions supported availability zones.",
				Type:        proto.ColumnType_BOOL,
				Transform:   transform.FromField("Properties.ZoneRedundant"),
			},
			{
				Name:        "created_at",
				Description: "The time the namespace was created.",
				Type:        proto.ColumnType_TIMESTAMP,
				Transform:   transform.FromField("Properties.CreatedAt"),
			},
			{
				Name:        "disable_local_auth",
				Description: "This property disables SAS authentication for the Service Bus namespace.",
				Type:        proto.ColumnType_BOOL,
				Transform:   transform.FromField("Properties.DisableLocalAuth"),
			},
			{
				Name:        "metric_id",
				Description: "The identifier for Azure insights metrics.",
				Type:        proto.ColumnType_STRING,
				Transform:   transform.FromField("Properties.MetricID"),
			},
			{
				Name:        "servicebus_endpoint",
				Description: "Specifies the endpoint used to perform Service Bus operations.",
				Type:        proto.ColumnType_STRING,
				Transform:   transform.FromField("Properties.ServiceBusEndpoint"),
			},
			{
				Name:        "sku_capacity",
				Description: "The specified messaging units for the tier. For Premium tier, capacity are 1,2 and 4.",
				Type:        proto.ColumnType_INT,
				Transform:   transform.FromField("SKU.Capacity"),
			},
			{
				Name:        "sku_name",
				Description: "Name of this SKU. Valid valuer are: 'Basic', 'Standard', 'Premium'.",
				Type:        proto.ColumnType_STRING,
				Transform:   transform.FromField("SKU.Name").Transform(transformToString),
			},
			{
				Name:        "sku_tier",
				Description: "The billing tier of this particular SKU. Valid values are: 'Basic', 'Standard', 'Premium'.",
				Type:        proto.ColumnType_STRING,
				Transform:   transform.FromField("SKU.Tier"),
			},
			{
				Name:        "status",
				Description: "Status of the namespace.",
				Type:        proto.ColumnType_STRING,
				Transform:   transform.FromField("Properties.Status"),
			},
			{
				Name:        "updated_at",
				Description: "The time the namespace was updated.",
				Type:        proto.ColumnType_TIMESTAMP,
				Transform:   transform.FromField("Properties.UpdatedAt"),
			},
			{
				Name:        "diagnostic_settings",
				Description: "A list of active diagnostic settings for the servicebus namespace.",
				Type:        proto.ColumnType_JSON,
				Hydrate:     listServiceBusNamespaceDiagnosticSettings,
				Transform:   transform.FromValue(),
			},
			{
				Name:        "encryption",
				Description: "Specifies the properties of BYOK encryption configuration. Customer-managed key encryption at rest (Bring Your Own Key) is only available on Premium namespaces.",
				Type:        proto.ColumnType_JSON,
				Transform:   transform.FromField("Properties.Encryption"),
			},
			{
				Name:        "network_rule_set",
				Description: "Describes the network rule set for specified namespace. The ServiceBus Namespace must be Premium in order to attach a ServiceBus Namespace Network Rule Set.",
				Type:        proto.ColumnType_JSON,
				Hydrate:     getServiceBusNamespaceNetworkRuleSet,
				Transform:   transform.FromValue(),
			},
			{
				Name:        "private_endpoint_connections",
				Description: "The private endpoint connections of the namespace.",
				Type:        proto.ColumnType_JSON,
				Hydrate:     listServiceBusNamespacePrivateEndpointConnections,
				Transform:   transform.FromValue(),
			},
			{
				Name:        "authorization_rules",
				Description: "The authorization rules for a namespace.",
				Type:        proto.ColumnType_JSON,
				Hydrate:     listServiceBusNamespaceAuthorizationRules,
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

func listServiceBusNamespaces(ctx context.Context, d *plugin.QueryData, _ *plugin.HydrateData) (any, error) {
	logger := plugin.Logger(ctx)
	logger.Trace("listServiceBusNamespaces")

	session, err := GetNewSessionUpdated(ctx, d)
	if err != nil {
		logger.Error("azure_servicebus_namespace.listServiceBusNamespaces", "session_error", err)
		return nil, err
	}

	f, err := armservicebus.NewClientFactory(session.SubscriptionID, session.Cred, session.ClientOptions)
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

func getServiceBusNamespace(ctx context.Context, d *plugin.QueryData, h *plugin.HydrateData) (any, error) {
	logger := plugin.Logger(ctx)
	logger.Trace("getServiceBusNamespace")

	name := d.EqualsQuals["name"].GetStringValue()
	resourceGroup := d.EqualsQuals["resource_group"].GetStringValue()

	// Return nil, if no input provided
	if name == "" || resourceGroup == "" {
		return nil, nil
	}

	session, err := GetNewSessionUpdated(ctx, d)
	if err != nil {
		logger.Error("azure_servicebus_namespace.getServiceBusNamespace", "session_error", err)
		return nil, err
	}

	f, err := armservicebus.NewClientFactory(session.SubscriptionID, session.Cred, session.ClientOptions)
	if err != nil {
		return nil, err
	}

	client := f.NewNamespacesClient()
	op, err := client.Get(ctx, resourceGroup, name, nil)
	if err != nil {
		logger.Error("getEventGridDomain", "get", err)
		return nil, err
	}

	return op.SBNamespace, nil
}

func getServiceBusNamespaceNetworkRuleSet(ctx context.Context, d *plugin.QueryData, h *plugin.HydrateData) (any, error) {
	logger := plugin.Logger(ctx)
	logger.Trace("getServiceBusNamespaceNetworkRuleSet")

	data := h.Item.(*armservicebus.SBNamespace)
	resourceGroup := strings.Split(*data.ID, "/")[4]

	session, err := GetNewSessionUpdated(ctx, d)
	if err != nil {
		logger.Error("azure_servicebus_namespace.getServiceBusNamespaceNetworkRuleSet", "session_error", err)
		return nil, err
	}

	f, err := armservicebus.NewClientFactory(session.SubscriptionID, session.Cred, session.ClientOptions)
	if err != nil {
		return nil, err
	}
	client := f.NewNamespacesClient()

	op, err := client.GetNetworkRuleSet(ctx, resourceGroup, *data.Name, nil)
	if err != nil {
		return nil, err
	}

	return op, nil
}

func listServiceBusNamespaceDiagnosticSettings(ctx context.Context, d *plugin.QueryData, h *plugin.HydrateData) (any, error) {
	plugin.Logger(ctx).Trace("listServiceBusNamespaceDiagnosticSettings")
	id := *h.Item.(*armservicebus.SBNamespace).ID

	// Create session
	session, err := GetNewSession(ctx, d, "MANAGEMENT")
	if err != nil {
		return nil, err
	}
	subscriptionID := session.SubscriptionID

	client := insights.NewDiagnosticSettingsClientWithBaseURI(session.ResourceManagerEndpoint, subscriptionID)
	client.Authorizer = session.Authorizer

	op, err := client.List(ctx, id)
	if err != nil {
		return nil, err
	}

	// If we return the API response directly, the output only gives
	// the contents of DiagnosticSettings
	var diagnosticSettings []map[string]any
	for _, i := range *op.Value {
		objectMap := make(map[string]any)
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

func listServiceBusNamespacePrivateEndpointConnections(ctx context.Context, d *plugin.QueryData, h *plugin.HydrateData) (any, error) {
	logger := plugin.Logger(ctx)
	logger.Trace("listServiceBusNamespacePrivateEndpointConnections")

	namespace := h.Item.(*armservicebus.SBNamespace)
	resourceGroup := strings.Split(*namespace.ID, "/")[4]
	namespaceName := *namespace.Name

	session, err := GetNewSessionUpdated(ctx, d)
	if err != nil {
		logger.Error("azure_servicebus_namespace.listServiceBusNamespacePrivateEndpointConnections", "session_error", err)
		return nil, err
	}

	f, err := armservicebus.NewClientFactory(session.SubscriptionID, session.Cred, session.ClientOptions)
	if err != nil {
		return nil, err
	}
	client := f.NewPrivateEndpointConnectionsClient()

	pager := client.NewListPager(resourceGroup, namespaceName, nil)

	var serviceBusNamespacePrivateEndpointConnections []map[string]any
	for pager.More() {
		// Wait for rate limiter
		d.WaitForListRateLimit(ctx)

		resp, err := pager.NextPage(ctx)
		if err != nil {
			logger.Error("error listing next page", "api_error", err)
			return nil, err
		}

		for _, v := range resp.Value {
			serviceBusNamespacePrivateEndpointConnections = append(serviceBusNamespacePrivateEndpointConnections, extractServiceBusNamespacePrivateEndpointConnection(v))

			// Check if the context has been canceled or if the limit has been hit (if specified)
			if d.RowsRemaining(ctx) == 0 {
				return nil, nil
			}
		}
	}

	return nil, nil
}

func listServiceBusNamespaceAuthorizationRules(ctx context.Context, d *plugin.QueryData, h *plugin.HydrateData) (any, error) {
	logger := plugin.Logger(ctx)
	logger.Trace("listServiceBusNamespaceAuthorizationRules")

	namespace := h.Item.(*armservicebus.SBNamespace)
	resourceGroup := strings.Split(*namespace.ID, "/")[4]
	namespaceName := *namespace.Name

	session, err := GetNewSessionUpdated(ctx, d)
	if err != nil {
		logger.Error("azure_servicebus_namespace.listServiceBusNamespaceAuthorizationRules", "session_error", err)
		return nil, err
	}

	f, err := armservicebus.NewClientFactory(session.SubscriptionID, session.Cred, session.ClientOptions)
	if err != nil {
		return nil, err
	}
	client := f.NewNamespacesClient()

	pager := client.NewListAuthorizationRulesPager(resourceGroup, namespaceName, nil)
	var serviceBusNamespaceAuthorizationRules []map[string]any
	for pager.More() {
		// Wait for rate limiter
		d.WaitForListRateLimit(ctx)

		resp, err := pager.NextPage(ctx)
		if err != nil {
			logger.Error("error listing next page", "api_error", err)
			return nil, err
		}

		for _, v := range resp.Value {
			serviceBusNamespaceAuthorizationRules = append(serviceBusNamespaceAuthorizationRules, extractServiceBusNamespacAuthRule(v))

			// Check if the context has been canceled or if the limit has been hit (if specified)
			if d.RowsRemaining(ctx) == 0 {
				return nil, nil
			}
		}
	}

	return nil, nil
}

// If we return the API response directly, the output will not provide the properties of AuthorizationRuleProperties
func extractServiceBusNamespacAuthRule(i *armservicebus.SBAuthorizationRule) map[string]any {
	serviceBusNamespaceAuthRule := make(map[string]any)
	if i.ID != nil {
		serviceBusNamespaceAuthRule["id"] = *i.ID
	}
	if i.Name != nil {
		serviceBusNamespaceAuthRule["name"] = *i.Name
	}
	if i.Type != nil {
		serviceBusNamespaceAuthRule["type"] = *i.Type
	}
	if i.SystemData != nil {
		serviceBusNamespaceAuthRule["systemData"] = *i.SystemData
	}
	if i.Properties != nil {
		if i.Properties.Rights != nil {
			serviceBusNamespaceAuthRule["properties"] = map[string]any{
				"rights": i.Properties.Rights,
			}
		}
	}
	return serviceBusNamespaceAuthRule
}

// If we return the API response directly, the output will not provide the properties of PrivateEndpointConnections
func extractServiceBusNamespacePrivateEndpointConnection(i *armservicebus.PrivateEndpointConnection) map[string]any {
	serviceBusNamespacePrivateEndpointConnection := make(map[string]any)
	if i.ID != nil {
		serviceBusNamespacePrivateEndpointConnection["id"] = *i.ID
	}
	if i.Name != nil {
		serviceBusNamespacePrivateEndpointConnection["name"] = *i.Name
	}
	if i.Type != nil {
		serviceBusNamespacePrivateEndpointConnection["type"] = *i.Type
	}
	if i.Properties != nil {
		if i.Properties.ProvisioningState != nil {
			serviceBusNamespacePrivateEndpointConnection["provisioningState"] = *i.Properties.ProvisioningState
		}
		if i.Properties.PrivateLinkServiceConnectionState != nil {
			serviceBusNamespacePrivateEndpointConnection["privateLinkServiceConnectionState"] = *i.Properties.PrivateLinkServiceConnectionState
		}
		if i.Properties.PrivateEndpoint != nil && i.Properties.PrivateEndpoint.ID != nil {
			serviceBusNamespacePrivateEndpointConnection["privateEndpointPropertyID"] = *i.Properties.PrivateEndpoint.ID
		}
	}
	return serviceBusNamespacePrivateEndpointConnection
}
