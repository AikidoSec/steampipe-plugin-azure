package azure

import (
	"context"

	"github.com/Azure/azure-sdk-for-go/profiles/latest/resources/mgmt/resources"
	"github.com/turbot/steampipe-plugin-sdk/v5/grpc/proto"
	"github.com/turbot/steampipe-plugin-sdk/v5/plugin/transform"

	"github.com/turbot/steampipe-plugin-sdk/v5/plugin"
)

//// TABLE DEFINITION

func tableAzureProvider(_ context.Context) *plugin.Table {
	return &plugin.Table{
		Name:        "azure_provider",
		Description: "Azure Provider",
		Get: &plugin.GetConfig{
			KeyColumns: plugin.SingleColumn("namespace"),
			Hydrate:    getProvider,
			Tags: map[string]string{
				"service": "Microsoft.Resources",
				"action":  "providers/read",
			},
			IgnoreConfig: &plugin.IgnoreConfig{
				ShouldIgnoreErrorFunc: isNotFoundError([]string{"InvalidResourceNamespace"}),
			},
		},
		List: &plugin.ListConfig{
			Hydrate: listProviders,
			Tags: map[string]string{
				"service": "Microsoft.Resources",
				"action":  "providers/read",
			},
		},
		Columns: azureColumns([]*plugin.Column{
			{
				Name:        "namespace",
				Type:        proto.ColumnType_STRING,
				Description: "The friendly name that identifies the resource provider.",
			},
			{
				Name:        "id",
				Description: "Contains ID to identify a resource provider uniquely.",
				Type:        proto.ColumnType_STRING,
				Transform:   transform.FromGo(),
			},
			{
				Name:        "registration_state",
				Description: "Contains the current registration state of the resource provider.",
				Type:        proto.ColumnType_STRING,
			},
			{
				Name:        "resource_types",
				Description: "A list of provider resource types.",
				Type:        proto.ColumnType_JSON,
			},

			// Steampipe standard columns
			{
				Name:        "title",
				Description: ColumnDescriptionTitle,
				Type:        proto.ColumnType_STRING,
				Transform:   transform.FromField("Namespace"),
			},
			{
				Name:        "akas",
				Description: ColumnDescriptionAkas,
				Type:        proto.ColumnType_JSON,
				Transform:   transform.FromField("ID").Transform(idToAkas),
			},
		}),
	}
}

//// LIST FUNCTION

func listProviders(ctx context.Context, d *plugin.QueryData, _ *plugin.HydrateData) (interface{}, error) {
	session, err := GetNewSession(ctx, d, "MANAGEMENT")
	if err != nil {
		return nil, err
	}
	subscriptionID := session.SubscriptionID

	resourcesClient := resources.NewProvidersClientWithBaseURI(session.ResourceManagerEndpoint, subscriptionID)
	resourcesClient.Authorizer = session.Authorizer

	// Apply Retry rule
	ApplyRetryRules(ctx, &resourcesClient, d.Connection)

	result, err := resourcesClient.List(ctx, "")
	if err != nil {
		return nil, err
	}
	for _, provider := range result.Values() {
		d.StreamListItem(ctx, provider)
		// Check if context has been cancelled or if the limit has been hit (if specified)
		// if there is a limit, it will return the number of rows required to reach this limit
		if d.RowsRemaining(ctx) == 0 {
			return nil, nil
		}
	}

	for result.NotDone() {
		// Wait for rate limiting
		d.WaitForListRateLimit(ctx)

		err = result.NextWithContext(ctx)
		if err != nil {
			return nil, err
		}

		for _, provider := range result.Values() {
			d.StreamListItem(ctx, provider)
			// Check if context has been cancelled or if the limit has been hit (if specified)
			// if there is a limit, it will return the number of rows required to reach this limit
			if d.RowsRemaining(ctx) == 0 {
				return nil, nil
			}
		}
	}

	return nil, err
}

//// HYDRATE FUNCTIONS

func getProvider(ctx context.Context, d *plugin.QueryData, h *plugin.HydrateData) (interface{}, error) {
	plugin.Logger(ctx).Trace("getProvider")

	session, err := GetNewSession(ctx, d, "MANAGEMENT")
	if err != nil {
		return nil, err
	}
	subscriptionID := session.SubscriptionID
	namespace := d.EqualsQuals["namespace"].GetStringValue()

	resourcesClient := resources.NewProvidersClientWithBaseURI(session.ResourceManagerEndpoint, subscriptionID)
	resourcesClient.Authorizer = session.Authorizer

	// Apply Retry rule
	ApplyRetryRules(ctx, &resourcesClient, d.Connection)

	op, err := resourcesClient.Get(ctx, namespace, "")
	if err != nil {
		return nil, err
	}

	return op, nil
}
