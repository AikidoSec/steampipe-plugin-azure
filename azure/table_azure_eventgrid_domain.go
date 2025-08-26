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

func tableAzureEventGridDomain(_ context.Context) *plugin.Table {
	return &plugin.Table{
		Name:        "azure_eventgrid_domain",
		Description: "Azure Event Grid Domain",
		Get: &plugin.GetConfig{
			KeyColumns: plugin.AllColumns([]string{"name", "resource_group"}),
			Hydrate:    getEventGridDomain,
			Tags: map[string]string{
				"service": "Microsoft.EventGrid",
				"action":  "domains/read",
			},
			IgnoreConfig: &plugin.IgnoreConfig{
				ShouldIgnoreErrorFunc: isNotFoundError([]string{"ResourceNotFound", "ResourceGroupNotFound", "400", "404"}),
			},
		},
		List: &plugin.ListConfig{
			Hydrate: listEventGridDomains,
			Tags: map[string]string{
				"service": "Microsoft.EventGrid",
				"action":  "domains/read",
			},
		},
		HydrateConfig: []plugin.HydrateConfig{
			{
				Func: listEventGridDomainDiagnosticSettings,
				Tags: map[string]string{
					"service": "Microsoft.Insights",
					"action":  "diagnosticSettings/read",
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
				Description: "Provisioning state of the event grid domain resource. Possible values include: 'Creating', 'Updating', 'Deleting', 'Succeeded', 'Canceled', 'Failed'.",
				Type:        proto.ColumnType_STRING,
				Transform:   transform.FromField("Properties.ProvisioningState"),
			},
			{
				Name:        "auto_create_topic_with_first_subscription",
				Description: "This Boolean is used to specify the creation mechanism for 'all' the event grid domain topics associated with this event grid domain resource.",
				Type:        proto.ColumnType_BOOL,
				Transform:   transform.FromField("Properties.AutoCreateTopicWithFirstSubscription"),
			},
			{
				Name:        "auto_delete_topic_with_last_subscription",
				Description: "This Boolean is used to specify the deletion mechanism for 'all' the Event Grid Domain Topics associated with this Event Grid Domain resource.",
				Type:        proto.ColumnType_BOOL,
				Transform:   transform.FromField("Properties.AutoDeleteTopicWithLastSubscription"),
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
				Description: "This boolean is used to enable or disable local auth. Default value is false. When the property is set to true, only AAD token will be used to authenticate if user is allowed to publish to the domain.",
				Type:        proto.ColumnType_BOOL,
				Transform:   transform.FromField("Properties.DisableLocalAuth"),
			},
			{
				Name:        "endpoint",
				Description: "Endpoint for the Event Grid Domain Resource which is used for publishing the events.",
				Type:        proto.ColumnType_STRING,
				Transform:   transform.FromField("Properties.Endpoint"),
			},
			{
				Name:        "identity_type",
				Description: "The type of managed identity used. The type 'SystemAssigned, UserAssigned' includes both an implicitly created identity and a set of user-assigned identities. The type 'None' will remove any identity. Possible values include: 'None', 'SystemAssigned', 'UserAssigned', 'SystemAssignedUserAssigned'.",
				Type:        proto.ColumnType_STRING,
				Transform:   transform.FromField("Identity.Type").Transform(transform.ToString),
			},
			{
				Name:        "input_schema",
				Description: "This determines the format that Event Grid should expect for incoming events published to the Event Grid Domain Resource. Possible values include: 'EventGridSchema', 'CustomEventSchema', 'CloudEventSchemaV10'.",
				Type:        proto.ColumnType_STRING,
				Transform:   transform.FromField("Properties.InputSchema"),
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
				Name:        "principal_id",
				Description: "The principal ID of resource identity.",
				Type:        proto.ColumnType_STRING,
				Transform:   transform.FromField("Identity.PrincipalID").Transform(transform.ToString),
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
				Transform:   transform.FromField("Sku.Name").Transform(transform.ToString),
			},
			{
				Name:        "user_assigned_identities",
				Description: "The list of user identities associated with the resource. The user identity dictionary key references will be ARM resource ids.",
				Type:        proto.ColumnType_JSON,
				Transform:   transform.FromField("Identity.UserAssignedIdentities"),
			},
			{
				Name:        "diagnostic_settings",
				Description: "A list of active diagnostic settings for the eventgrid domain.",
				Type:        proto.ColumnType_JSON,
				Hydrate:     listEventGridDomainDiagnosticSettings,
				Transform:   transform.FromValue(),
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
				Description: "List of private endpoint connections.",
				Type:        proto.ColumnType_JSON,
				Transform:   transform.From(extractEventgridDomainPrivaterEndPointConnections),
			},
			{
				Name:        "minimum_tls_version_allowed",
				Description: "This determines the minimum TLS version required for traffic to the domain.",
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

func listEventGridDomains(ctx context.Context, d *plugin.QueryData, _ *plugin.HydrateData) (interface{}, error) {
	logger := plugin.Logger(ctx)
	logger.Trace("listEventGridDomains")

	session, err := GetNewSessionUpdated(ctx, d)
	if err != nil {
		logger.Error("azure_eventgrid_domain.listEventGridDomains", "session_error", err)
		return nil, err
	}

	f, err := armeventgrid.NewClientFactory(session.SubscriptionID, session.Cred, session.ClientOptions)
	if err != nil {
		return nil, err
	}

	client := f.NewDomainsClient()

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

func getEventGridDomain(ctx context.Context, d *plugin.QueryData, _ *plugin.HydrateData) (interface{}, error) {
	logger := plugin.Logger(ctx)
	logger.Trace("getEventGridDomain")

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

	client := f.NewDomainsClient()
	op, err := client.Get(ctx, resourceGroup, name, nil)
	if err != nil {
		logger.Error("getEventGridDomain", "get", err)
		return nil, err
	}

	return op.Domain, nil
}

func listEventGridDomainDiagnosticSettings(ctx context.Context, d *plugin.QueryData, h *plugin.HydrateData) (interface{}, error) {
	plugin.Logger(ctx).Trace("listEventGridDomainDiagnosticSettings")
	id := *h.Item.(eventgrid.Domain).ID

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
		plugin.Logger(ctx).Error("listEventGridDomainDiagnosticSettings", "list", err)
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
func extractEventgridDomainPrivaterEndPointConnections(ctx context.Context, d *transform.TransformData) (interface{}, error) {
	plugin.Logger(ctx).Trace("extractEventgridDomainPrivaterEndPointConnections")
	domain := d.HydrateItem.(*armeventgrid.Domain)
	var privateEndpointConnectionsInfo []map[string]interface{}
	if domain.Properties.PrivateEndpointConnections != nil {
		privateEndpointConnections := domain.Properties.PrivateEndpointConnections
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
						objectMap["endpointId"] = *endpoint.Properties.PrivateEndpoint.ID
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
						objectMap["privateLinkServiceConnectionStateDescription"] = endpoint.Properties.PrivateLinkServiceConnectionState.Description
					}
					if endpoint.Properties.PrivateLinkServiceConnectionState.ActionsRequired != nil {
						objectMap["privateLinkServiceConnectionStateActionsRequired"] = endpoint.Properties.PrivateLinkServiceConnectionState.ActionsRequired
					}
				}
			}
			privateEndpointConnectionsInfo = append(privateEndpointConnectionsInfo, objectMap)
		}
	}
	return privateEndpointConnectionsInfo, nil
}
