package azure

import (
	"context"

	"github.com/Azure/azure-sdk-for-go/profiles/latest/eventgrid/mgmt/eventgrid"
	"github.com/Azure/azure-sdk-for-go/profiles/preview/preview/monitor/mgmt/insights"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/eventgrid/armeventgrid/v2"

	"github.com/turbot/steampipe-plugin-sdk/v5/grpc/proto"
	"github.com/turbot/steampipe-plugin-sdk/v5/plugin"
	"github.com/turbot/steampipe-plugin-sdk/v5/plugin/transform"
)

//// TABLE DEFINITION

func tableAzureEventGridTopic(_ context.Context) *plugin.Table {
	return &plugin.Table{
		Name:        "azure_eventgrid_topic",
		Description: "Azure Event Grid Topic",
		Get: &plugin.GetConfig{
			KeyColumns: plugin.AllColumns([]string{"name", "resource_group"}),
			Hydrate:    getEventGridTopic,
			Tags: map[string]string{
				"service": "Microsoft.EventGrid",
				"action":  "topics/read",
			},
			IgnoreConfig: &plugin.IgnoreConfig{
				ShouldIgnoreErrorFunc: isNotFoundError([]string{"ResourceNotFound", "ResourceGroupNotFound", "400", "404"}),
			},
		},
		List: &plugin.ListConfig{
			Hydrate: listEventGridTopics,
			Tags: map[string]string{
				"service": "Microsoft.EventGrid",
				"action":  "topics/read",
			},
		},
		HydrateConfig: []plugin.HydrateConfig{
			{
				Func: listEventGridTopicDiagnosticSettings,
				Tags: map[string]string{
					"service": "Microsoft.EventGrid",
					"action":  "topics/providers/Microsoft.Insights/diagnosticSettings/read",
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
				Description: "Fully qualified identifier of the resource.",
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
				Description: "Provisioning state of the event grid topic resource. Possible values include: 'Creating', 'Updating', 'Deleting', 'Succeeded', 'Canceled', 'Failed'.",
				Type:        proto.ColumnType_STRING,
				Transform:   transform.FromField("Properties.ProvisioningState"),
			},
			{
				Name:        "created_at",
				Description: "The timestamp of resource creation (UTC).",
				Type:        proto.ColumnType_TIMESTAMP,
				Transform:   transform.FromField("SystemData.CreatedAt").Transform(convertDateToTime),
			},
			{
				Name:        "created_by",
				Description: "The identity that created the resource.",
				Type:        proto.ColumnType_STRING,
				Transform:   transform.FromField("SystemData.CreatedBy"),
			},
			{
				Name:        "created_by_type",
				Description: "The type of identity that created the resource.",
				Type:        proto.ColumnType_STRING,
				Transform:   transform.FromField("SystemData.CreatedByType"),
			},
			{
				Name:        "disable_local_auth",
				Description: "This boolean is used to enable or disable local auth. Default value is false. When the property is set to true, only AAD token will be used to authenticate if user is allowed to publish to the topic.",
				Type:        proto.ColumnType_BOOL,
				Transform:   transform.FromField("Properties.DisableLocalAuth"),
				Default:     false,
			},
			{
				Name:        "endpoint",
				Description: "Endpoint for the event grid topic resource which is used for publishing the events.",
				Type:        proto.ColumnType_STRING,
				Transform:   transform.FromField("Properties.Endpoint"),
			},
			{
				Name:        "input_schema",
				Description: "This determines the format that event grid should expect for incoming events published to the event grid topic resource. Possible values include: 'EventGridSchema', 'CustomEventSchema', 'CloudEventSchemaV10'.",
				Type:        proto.ColumnType_STRING,
				Transform:   transform.FromField("Properties.InputSchema"),
			},
			{
				Name:        "kind",
				Description: "Kind of the resource.",
				Type:        proto.ColumnType_STRING,
			},
			{
				Name:        "last_modified_at",
				Description: "The timestamp of resource last modification (UTC).",
				Type:        proto.ColumnType_TIMESTAMP,
				Transform:   transform.FromField("SystemData.LastModifiedAt").Transform(convertDateToTime),
			},
			{
				Name:        "last_modified_by",
				Description: "The identity that last modified the resource.",
				Type:        proto.ColumnType_STRING,
				Transform:   transform.FromField("SystemData.LastModifiedBy"),
			},
			{
				Name:        "last_modified_by_type",
				Description: "The type of identity that last modified the resource.",
				Type:        proto.ColumnType_STRING,
				Transform:   transform.FromField("SystemData.LastModifiedByType"),
			},
			{
				Name:        "location",
				Description: "Location of the resource.",
				Type:        proto.ColumnType_STRING,
			},
			{
				Name:        "public_network_access",
				Description: "This determines if traffic is allowed over public network. By default it is enabled.",
				Type:        proto.ColumnType_STRING,
				Transform:   transform.FromField("Properties.PublicNetworkAccess"),
			},
			{
				Name:        "sku_name",
				Description: "Name of this SKU. Possible values include: 'Basic', 'Standard'.",
				Type:        proto.ColumnType_STRING,
				Transform:   transform.FromField("SKU.Name").Transform(transform.ToString),
			},
			{
				Name:        "diagnostic_settings",
				Description: "A list of active diagnostic settings for the eventgrid topic.",
				Type:        proto.ColumnType_JSON,
				Hydrate:     listEventGridTopicDiagnosticSettings,
				Transform:   transform.FromValue(),
			},
			{
				Name:        "extended_location",
				Description: "Extended location of the resource.",
				Type:        proto.ColumnType_JSON,
			},
			{
				Name:        "identity",
				Description: "Identity information for the resource.",
				Type:        proto.ColumnType_JSON,
			},
			{
				Name:        "inbound_ip_rules",
				Description: "This can be used to restrict traffic from specific IPs instead of all IPs. Note: These are considered only if PublicNetworkAccess is enabled.",
				Type:        proto.ColumnType_JSON,
				Transform:   transform.FromField("Properties.InboundIPRules"),
			},
			{
				Name:        "input_schema_mapping",
				Description: "Information about the InputSchemaMapping which specified the info about mapping event payload.",
				Type:        proto.ColumnType_JSON,
				Transform:   transform.FromField("Properties.InputSchemaMapping"),
			},
			{
				Name:        "private_endpoint_connections",
				Description: "List of private endpoint connections for the event grid topic.",
				Type:        proto.ColumnType_JSON,
				Transform:   transform.From(extractEventgridTopicPrivaterEndPointConnections),
			},
			{
				Name:        "minimum_tls_version_allowed",
				Description: "This determines the minimum TLS version required for traffic to the topic.",
				Type:        proto.ColumnType_STRING,
				Transform:   transform.FromField("Properties.MinimumTLSVersionAllowed").Transform(transformToString),
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

func listEventGridTopics(ctx context.Context, d *plugin.QueryData, _ *plugin.HydrateData) (interface{}, error) {
	logger := plugin.Logger(ctx)
	logger.Trace("listEventGridTopics")

	session, err := GetNewSessionUpdated(ctx, d)
	if err != nil {
		logger.Error("azure_eventgrid_topic.listEventGridTopics", "session_error", err)
		return nil, err
	}

	f, err := armeventgrid.NewClientFactory(session.SubscriptionID, session.Cred, session.ClientOptions)
	if err != nil {
		return nil, err
	}

	client := f.NewTopicsClient()

	pager := client.NewListBySubscriptionPager(nil)
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

func getEventGridTopic(ctx context.Context, d *plugin.QueryData, _ *plugin.HydrateData) (interface{}, error) {
	logger := plugin.Logger(ctx)
	logger.Trace("getEventGridTopic")

	name := d.EqualsQuals["name"].GetStringValue()
	resourceGroup := d.EqualsQuals["resource_group"].GetStringValue()

	// Return nil, if no input provided
	if name == "" || resourceGroup == "" {
		return nil, nil
	}

	session, err := GetNewSessionUpdated(ctx, d)
	if err != nil {
		logger.Error("azure_eventgrid_topic.listEventGridTopics", "session_error", err)
		return nil, err
	}

	f, err := armeventgrid.NewClientFactory(session.SubscriptionID, session.Cred, session.ClientOptions)
	if err != nil {
		return nil, err
	}

	client := f.NewTopicsClient()
	op, err := client.Get(ctx, resourceGroup, name, nil)
	if err != nil {
		logger.Error("getEventGridTopic", "get", err)
		return nil, err
	}

	return op.Topic, nil
}

func listEventGridTopicDiagnosticSettings(ctx context.Context, d *plugin.QueryData, h *plugin.HydrateData) (interface{}, error) {
	plugin.Logger(ctx).Trace("listEventGridTopicDiagnosticSettings")
	id := *h.Item.(eventgrid.Topic).ID

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
		plugin.Logger(ctx).Error("listEventGridTopicDiagnosticSettings", "list", err)
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

//// TRANSFORM FUNCTIONS

// If we return the private endpoint connection directly from api response we will not receive all the properties of private endpoint connections.
func extractEventgridTopicPrivaterEndPointConnections(ctx context.Context, d *transform.TransformData) (interface{}, error) {
	plugin.Logger(ctx).Trace("extractEventgridTopicPrivaterEndPointConnections")
	topic := d.HydrateItem.(*armeventgrid.Topic)
	var privateEndpointConnectionsInfo []map[string]interface{}
	if topic.Properties.PrivateEndpointConnections != nil {
		privateEndpointConnections := topic.Properties.PrivateEndpointConnections
		for _, endpoint := range privateEndpointConnections {
			objectMap := make(map[string]interface{})

			if endpoint.ID != nil {
				objectMap["id"] = endpoint.ID
			}

			if endpoint.Name != nil {
				objectMap["name"] = endpoint.Name
			}

			if endpoint.Type != nil {
				objectMap["type"] = endpoint.Type
			}

			if endpoint.Properties != nil {
				if endpoint.Properties.PrivateEndpoint != nil {
					if endpoint.Properties.PrivateEndpoint.ID != nil {
						objectMap["endpointId"] = endpoint.Properties.PrivateEndpoint.ID
					}
				}
				if endpoint.Properties.GroupIDs != nil {
					objectMap["groupIds"] = endpoint.Properties.GroupIDs
				}
				if endpoint.Properties.ProvisioningState != nil {
					objectMap["provisioningState"] = *endpoint.Properties.ProvisioningState
				}
				if endpoint.Properties.PrivateLinkServiceConnectionState != nil {
					if endpoint.Properties.PrivateLinkServiceConnectionState.Status != nil {
						objectMap["privateLinkServiceConnectionStateStatus"] = *endpoint.Properties.PrivateLinkServiceConnectionState.Status
					}
					if endpoint.Properties.PrivateLinkServiceConnectionState.Description != nil {
						objectMap["privateLinkServiceConnectionStateDescription"] = *endpoint.Properties.PrivateLinkServiceConnectionState.Description
					}
					if endpoint.Properties.PrivateLinkServiceConnectionState.ActionsRequired != nil {
						objectMap["privateLinkServiceConnectionStateActionsRequired"] = *endpoint.Properties.PrivateLinkServiceConnectionState.ActionsRequired
					}
				}
			}
			privateEndpointConnectionsInfo = append(privateEndpointConnectionsInfo, objectMap)
		}
	}
	return privateEndpointConnectionsInfo, nil
}
