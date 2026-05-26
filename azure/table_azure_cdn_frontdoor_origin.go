package azure

import (
	"context"
	"strings"

	"github.com/Azure/azure-sdk-for-go/profiles/latest/cdn/mgmt/cdn"
	"github.com/turbot/go-kit/types"
	"github.com/turbot/steampipe-plugin-sdk/v5/grpc/proto"
	"github.com/turbot/steampipe-plugin-sdk/v5/plugin"
	"github.com/turbot/steampipe-plugin-sdk/v5/plugin/transform"
)

func tableAzureCDNFrontDoorOrigin(_ context.Context) *plugin.Table {
	return &plugin.Table{
		Name:        "azure_cdn_frontdoor_origin",
		Description: "Azure CDN Front Door Origin",
		Get: &plugin.GetConfig{
			KeyColumns: plugin.AllColumns([]string{"name", "origin_group_name", "profile_name", "resource_group"}),
			Hydrate:    getAzureCDNFrontDoorOrigin,
			Tags: map[string]string{
				"service": "Microsoft.Cdn",
				"action":  "origins/read",
			},
			IgnoreConfig: &plugin.IgnoreConfig{
				ShouldIgnoreErrorFunc: isNotFoundError([]string{"ResourceNotFound", "ResourceGroupNotFound", "404"}),
			},
		},
		List: &plugin.ListConfig{
			ParentHydrate: listAzureCDNFrontDoorOriginGroups,
			Hydrate:       listAzureCDNFrontDoorOrigins,
			Tags: map[string]string{
				"service": "Microsoft.Cdn",
				"action":  "origins/read",
			},
			KeyColumns: plugin.KeyColumnSlice{
				{Name: "profile_name", Require: plugin.Optional, Operators: []string{"="}},
				{Name: "origin_group_name", Require: plugin.Optional, Operators: []string{"="}},
				{Name: "resource_group", Require: plugin.Optional, Operators: []string{"="}},
				{Name: "name", Require: plugin.Optional, Operators: []string{"=", "<>"}},
			},
		},
		Columns: azureColumns([]*plugin.Column{
			{
				Name:        "name",
				Description: "The name of the origin.",
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
				Transform:   transform.FromField("ID").Transform(extractCDNFrontDoorProfileNameFromOriginID),
			},
			{
				Name:        "origin_group_name",
				Description: "The name of the origin group containing this origin.",
				Type:        proto.ColumnType_STRING,
				Transform:   transform.FromField("AFDOriginProperties.OriginGroupName"),
			},
			{
				Name:        "type",
				Description: "The resource type.",
				Type:        proto.ColumnType_STRING,
			},
			{
				Name:        "host_name",
				Description: "The address of the origin.",
				Type:        proto.ColumnType_STRING,
				Transform:   transform.FromField("AFDOriginProperties.HostName"),
			},
			{
				Name:        "http_port",
				Description: "The HTTP port of the origin.",
				Type:        proto.ColumnType_INT,
				Transform:   transform.FromField("AFDOriginProperties.HTTPPort"),
			},
			{
				Name:        "https_port",
				Description: "The HTTPS port of the origin.",
				Type:        proto.ColumnType_INT,
				Transform:   transform.FromField("AFDOriginProperties.HTTPSPort"),
			},
			{
				Name:        "origin_host_header",
				Description: "The host header value sent to the origin with each request.",
				Type:        proto.ColumnType_STRING,
				Transform:   transform.FromField("AFDOriginProperties.OriginHostHeader"),
			},
			{
				Name:        "priority",
				Description: "Priority of the origin in its origin group.",
				Type:        proto.ColumnType_INT,
				Transform:   transform.FromField("AFDOriginProperties.Priority"),
			},
			{
				Name:        "weight",
				Description: "Weight of the origin in its origin group.",
				Type:        proto.ColumnType_INT,
				Transform:   transform.FromField("AFDOriginProperties.Weight"),
			},
			{
				Name:        "enabled_state",
				Description: "Whether the origin is enabled.",
				Type:        proto.ColumnType_STRING,
				Transform:   transform.FromField("AFDOriginProperties.EnabledState"),
			},
			{
				Name:        "enforce_certificate_name_check",
				Description: "Whether certificate name check is enabled for the origin.",
				Type:        proto.ColumnType_BOOL,
				Transform:   transform.FromField("AFDOriginProperties.EnforceCertificateNameCheck"),
			},
			{
				Name:        "provisioning_state",
				Description: "Provisioning status of the origin.",
				Type:        proto.ColumnType_STRING,
				Transform:   transform.FromField("AFDOriginProperties.ProvisioningState"),
			},
			{
				Name:        "deployment_status",
				Description: "Deployment status of the origin.",
				Type:        proto.ColumnType_STRING,
				Transform:   transform.FromField("AFDOriginProperties.DeploymentStatus"),
			},
			{
				Name:        "azure_origin",
				Description: "Resource reference to the Azure origin resource.",
				Type:        proto.ColumnType_JSON,
				Transform:   transform.FromField("AFDOriginProperties.AzureOrigin"),
			},
			{
				Name:        "shared_private_link_resource",
				Description: "Shared private link resource properties for the origin.",
				Type:        proto.ColumnType_JSON,
				Transform:   transform.FromField("AFDOriginProperties.SharedPrivateLinkResource"),
			},
			{
				Name:        "system_data",
				Description: "Azure system metadata for the origin.",
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

func listAzureCDNFrontDoorOrigins(ctx context.Context, d *plugin.QueryData, h *plugin.HydrateData) (interface{}, error) {
	originGroup := h.Item.(cdn.AFDOriginGroup)
	resourceGroup := strings.Split(*originGroup.ID, "/")[4]
	profileName := extractCDNFrontDoorProfileName(*originGroup.ID)
	originGroupName := ""
	if originGroup.Name != nil {
		originGroupName = *originGroup.Name
	}

	if qual := d.EqualsQualString("resource_group"); qual != "" && qual != resourceGroup {
		return nil, nil
	}
	if qual := d.EqualsQualString("profile_name"); qual != "" && qual != profileName {
		return nil, nil
	}
	if qual := d.EqualsQualString("origin_group_name"); qual != "" && qual != originGroupName {
		return nil, nil
	}

	session, err := GetNewSession(ctx, d, "MANAGEMENT")
	if err != nil {
		plugin.Logger(ctx).Error("azure_cdn_frontdoor_origin.listAzureCDNFrontDoorOrigins", "session_error", err)
		return nil, err
	}

	client := cdn.NewAFDOriginsClientWithBaseURI(session.ResourceManagerEndpoint, session.SubscriptionID)
	client.Authorizer = session.Authorizer

	ApplyRetryRules(ctx, &client, d.Connection)

	result, err := client.ListByOriginGroup(ctx, resourceGroup, profileName, originGroupName)
	if err != nil {
		plugin.Logger(ctx).Error("azure_cdn_frontdoor_origin.listAzureCDNFrontDoorOrigins", "api_error", err)
		return nil, err
	}

	for _, origin := range result.Values() {
		d.StreamListItem(ctx, origin)
		if d.RowsRemaining(ctx) == 0 {
			return nil, nil
		}
	}

	for result.NotDone() {
		d.WaitForListRateLimit(ctx)

		err = result.NextWithContext(ctx)
		if err != nil {
			plugin.Logger(ctx).Error("azure_cdn_frontdoor_origin.listAzureCDNFrontDoorOrigins", "paging_error", err)
			return nil, err
		}
		for _, origin := range result.Values() {
			d.StreamListItem(ctx, origin)
			if d.RowsRemaining(ctx) == 0 {
				return nil, nil
			}
		}
	}

	return nil, nil
}

func getAzureCDNFrontDoorOrigin(ctx context.Context, d *plugin.QueryData, h *plugin.HydrateData) (interface{}, error) {
	name := d.EqualsQuals["name"].GetStringValue()
	originGroupName := d.EqualsQuals["origin_group_name"].GetStringValue()
	profileName := d.EqualsQuals["profile_name"].GetStringValue()
	resourceGroup := d.EqualsQuals["resource_group"].GetStringValue()

	if name == "" || originGroupName == "" || profileName == "" || resourceGroup == "" {
		return nil, nil
	}

	session, err := GetNewSession(ctx, d, "MANAGEMENT")
	if err != nil {
		plugin.Logger(ctx).Error("azure_cdn_frontdoor_origin.getAzureCDNFrontDoorOrigin", "session_error", err)
		return nil, err
	}

	client := cdn.NewAFDOriginsClientWithBaseURI(session.ResourceManagerEndpoint, session.SubscriptionID)
	client.Authorizer = session.Authorizer

	ApplyRetryRules(ctx, &client, d.Connection)

	origin, err := client.Get(ctx, resourceGroup, profileName, originGroupName, name)
	if err != nil {
		plugin.Logger(ctx).Error("azure_cdn_frontdoor_origin.getAzureCDNFrontDoorOrigin", "api_error", err)
		return nil, err
	}

	if origin.ID != nil {
		return origin, nil
	}

	return nil, nil
}

func extractCDNFrontDoorProfileNameFromOriginID(_ context.Context, d *transform.TransformData) (interface{}, error) {
	id := types.SafeString(d.Value)
	return extractCDNFrontDoorProfileName(id), nil
}

func extractCDNFrontDoorProfileName(id string) string {
	parts := strings.Split(id, "/")
	if len(parts) > 8 {
		return parts[8]
	}
	return ""
}
