package azure

import (
	"context"
	"strings"

	"github.com/Azure/azure-sdk-for-go/profiles/latest/cdn/mgmt/cdn"
	"github.com/turbot/steampipe-plugin-sdk/v5/grpc/proto"
	"github.com/turbot/steampipe-plugin-sdk/v5/plugin"
	"github.com/turbot/steampipe-plugin-sdk/v5/plugin/transform"
)

func tableAzureCDNFrontDoorOriginGroup(_ context.Context) *plugin.Table {
	return &plugin.Table{
		Name:        "azure_cdn_frontdoor_origin_group",
		Description: "Azure CDN Front Door Origin Group",
		Get: &plugin.GetConfig{
			KeyColumns: plugin.AllColumns([]string{"name", "profile_name", "resource_group"}),
			Hydrate:    getAzureCDNFrontDoorOriginGroup,
			Tags: map[string]string{
				"service": "Microsoft.Cdn",
				"action":  "originGroups/read",
			},
			IgnoreConfig: &plugin.IgnoreConfig{
				ShouldIgnoreErrorFunc: isNotFoundError([]string{"ResourceNotFound", "ResourceGroupNotFound", "404"}),
			},
		},
		List: &plugin.ListConfig{
			ParentHydrate: listAzureCDNFrontDoorProfiles,
			Hydrate:       listAzureCDNFrontDoorOriginGroups,
			Tags: map[string]string{
				"service": "Microsoft.Cdn",
				"action":  "originGroups/read",
			},
			KeyColumns: plugin.KeyColumnSlice{
				{Name: "profile_name", Require: plugin.Optional, Operators: []string{"="}},
				{Name: "resource_group", Require: plugin.Optional, Operators: []string{"="}},
				{Name: "name", Require: plugin.Optional, Operators: []string{"=", "<>"}},
			},
		},
		Columns: azureColumns([]*plugin.Column{
			{
				Name:        "name",
				Description: "The name of the origin group.",
				Type:        proto.ColumnType_STRING,
				Transform:   transform.FromField("Name"),
			},
			{
				Name:        "id",
				Description: "The resource identifier.",
				Type:        proto.ColumnType_STRING,
				Transform:   transform.FromGo(),
			},
			{
				Name:        "profile_name",
				Description: "The name of the Front Door profile.",
				Type:        proto.ColumnType_STRING,
				Transform:   transform.FromField("AFDOriginGroupProperties.ProfileName"),
			},
			{
				Name:        "type",
				Description: "The resource type.",
				Type:        proto.ColumnType_STRING,
			},
			{
				Name:        "session_affinity_state",
				Description: "Whether session affinity is enabled for this origin group.",
				Type:        proto.ColumnType_STRING,
				Transform:   transform.FromField("AFDOriginGroupProperties.SessionAffinityState"),
			},
			{
				Name:        "provisioning_state",
				Description: "Provisioning status of the origin group.",
				Type:        proto.ColumnType_STRING,
				Transform:   transform.FromField("AFDOriginGroupProperties.ProvisioningState"),
			},
			{
				Name:        "deployment_status",
				Description: "Deployment status of the origin group.",
				Type:        proto.ColumnType_STRING,
				Transform:   transform.FromField("AFDOriginGroupProperties.DeploymentStatus"),
			},
			{
				Name:        "traffic_restoration_time_to_healed_or_new_endpoints_in_minutes",
				Description: "Traffic restoration time in minutes when an unhealthy endpoint recovers or a new endpoint is added.",
				Type:        proto.ColumnType_INT,
				Transform:   transform.FromField("AFDOriginGroupProperties.TrafficRestorationTimeToHealedOrNewEndpointsInMinutes"),
			},
			{
				Name:        "load_balancing_settings",
				Description: "Load balancing settings for the origin group.",
				Type:        proto.ColumnType_JSON,
				Transform:   transform.FromField("AFDOriginGroupProperties.LoadBalancingSettings"),
			},
			{
				Name:        "health_probe_settings",
				Description: "Health probe settings for the origin group.",
				Type:        proto.ColumnType_JSON,
				Transform:   transform.FromField("AFDOriginGroupProperties.HealthProbeSettings"),
			},
			{
				Name:        "system_data",
				Description: "Azure system metadata for the origin group.",
				Type:        proto.ColumnType_JSON,
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
				Name:        "resource_group",
				Description: ColumnDescriptionResourceGroup,
				Type:        proto.ColumnType_STRING,
				Transform:   transform.FromField("ID").Transform(extractResourceGroupFromID),
			},
		}),
	}
}

func listAzureCDNFrontDoorOriginGroups(ctx context.Context, d *plugin.QueryData, h *plugin.HydrateData) (interface{}, error) {
	profile := h.Item.(cdn.Profile)
	profileName := *profile.Name
	resourceGroup := strings.Split(*profile.ID, "/")[4]

	if qual := d.EqualsQualString("profile_name"); qual != "" && qual != profileName {
		return nil, nil
	}
	if qual := d.EqualsQualString("resource_group"); qual != "" && qual != resourceGroup {
		return nil, nil
	}

	session, err := GetNewSession(ctx, d, "MANAGEMENT")
	if err != nil {
		plugin.Logger(ctx).Error("azure_cdn_frontdoor_origin_group.listAzureCDNFrontDoorOriginGroups", "session_error", err)
		return nil, err
	}

	client := cdn.NewAFDOriginGroupsClientWithBaseURI(session.ResourceManagerEndpoint, session.SubscriptionID)
	client.Authorizer = session.Authorizer

	ApplyRetryRules(ctx, &client, d.Connection)

	result, err := client.ListByProfile(ctx, resourceGroup, profileName)
	if err != nil {
		plugin.Logger(ctx).Error("azure_cdn_frontdoor_origin_group.listAzureCDNFrontDoorOriginGroups", "api_error", err)
		return nil, err
	}

	for _, originGroup := range result.Values() {
		if shouldIgnoreOriginGroupByName(d, originGroup) {
			continue
		}
		d.StreamListItem(ctx, originGroup)
		if d.RowsRemaining(ctx) == 0 {
			return nil, nil
		}
	}

	for result.NotDone() {
		d.WaitForListRateLimit(ctx)

		err = result.NextWithContext(ctx)
		if err != nil {
			plugin.Logger(ctx).Error("azure_cdn_frontdoor_origin_group.listAzureCDNFrontDoorOriginGroups", "paging_error", err)
			return nil, err
		}
		for _, originGroup := range result.Values() {
			if shouldIgnoreOriginGroupByName(d, originGroup) {
				continue
			}
			d.StreamListItem(ctx, originGroup)
			if d.RowsRemaining(ctx) == 0 {
				return nil, nil
			}
		}
	}

	return nil, nil
}

func getAzureCDNFrontDoorOriginGroup(ctx context.Context, d *plugin.QueryData, h *plugin.HydrateData) (interface{}, error) {
	name := d.EqualsQuals["name"].GetStringValue()
	profileName := d.EqualsQuals["profile_name"].GetStringValue()
	resourceGroup := d.EqualsQuals["resource_group"].GetStringValue()

	if name == "" || profileName == "" || resourceGroup == "" {
		return nil, nil
	}

	session, err := GetNewSession(ctx, d, "MANAGEMENT")
	if err != nil {
		plugin.Logger(ctx).Error("azure_cdn_frontdoor_origin_group.getAzureCDNFrontDoorOriginGroup", "session_error", err)
		return nil, err
	}

	client := cdn.NewAFDOriginGroupsClientWithBaseURI(session.ResourceManagerEndpoint, session.SubscriptionID)
	client.Authorizer = session.Authorizer

	ApplyRetryRules(ctx, &client, d.Connection)

	originGroup, err := client.Get(ctx, resourceGroup, profileName, name)
	if err != nil {
		plugin.Logger(ctx).Error("azure_cdn_frontdoor_origin_group.getAzureCDNFrontDoorOriginGroup", "api_error", err)
		return nil, err
	}

	if originGroup.ID != nil {
		return originGroup, nil
	}

	return nil, nil
}

func shouldIgnoreOriginGroupByName(d *plugin.QueryData, originGroup cdn.AFDOriginGroup) bool {
	if d.Quals["name"] == nil {
		return false
	}

	name := ""
	if originGroup.Name != nil {
		name = *originGroup.Name
	}

	for _, q := range d.Quals["name"].Quals {
		switch q.Operator {
		case "=":
			if name != q.Value.GetStringValue() {
				return true
			}
		case "<>":
			if name == q.Value.GetStringValue() {
				return true
			}
		}
	}

	return false
}
