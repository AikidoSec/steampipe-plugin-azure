package azure

import (
	"context"
	"fmt"

	"github.com/Azure/azure-sdk-for-go/profiles/latest/web/mgmt/web"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/appservice/armappservice/v4"
	"github.com/turbot/steampipe-plugin-sdk/v5/grpc/proto"
	"github.com/turbot/steampipe-plugin-sdk/v5/plugin"
	"github.com/turbot/steampipe-plugin-sdk/v5/plugin/transform"
)

//// TABLE DEFINITION

func tableAzureAppServiceSiteContainer(_ context.Context) *plugin.Table {
	return &plugin.Table{
		Name:        "azure_app_service_site_container",
		Description: "Azure App Service Site Container",
		Get: &plugin.GetConfig{
			KeyColumns: plugin.AllColumns([]string{"name", "app_name", "resource_group"}),
			Hydrate:    getAppServiceSiteContainer,
			Tags: map[string]string{
				"service": "Microsoft.Web",
				"action":  "sites/sitecontainers/read",
			},
			IgnoreConfig: &plugin.IgnoreConfig{
				ShouldIgnoreErrorFunc: isNotFoundError([]string{"ResourceNotFound", "ResourceGroupNotFound"}),
			},
		},
		List: &plugin.ListConfig{
			ParentHydrate: listAppServiceWebApps,
			Hydrate:       listAppServiceSiteContainers,
			Tags: map[string]string{
				"service": "Microsoft.Web",
				"action":  "sites/sitecontainers/read",
			},
			KeyColumns: []*plugin.KeyColumn{
				{Name: "app_name", Require: plugin.Optional},
			},
		},
		Columns: azureColumns([]*plugin.Column{
			{
				Name:        "name",
				Description: "The friendly name that identifies the site container.",
				Type:        proto.ColumnType_STRING,
				Transform:   transform.FromField("Name").Transform(lastPathElement),
			},
			{
				Name:        "app_name",
				Description: "The name of the app service web app.",
				Type:        proto.ColumnType_STRING,
			},
			{
				Name:        "id",
				Description: "Contains ID to identify a site container uniquely.",
				Type:        proto.ColumnType_STRING,
				Transform:   transform.FromGo(),
			},
			{
				Name:        "type",
				Description: "The resource type of the site container.",
				Type:        proto.ColumnType_STRING,
			},
			{
				Name:        "kind",
				Description: "The kind of the resource.",
				Type:        proto.ColumnType_STRING,
			},
			{
				Name:        "image",
				Description: "The container image name.",
				Type:        proto.ColumnType_STRING,
				Transform:   transform.FromField("Properties.Image"),
			},
			{
				Name:        "is_main",
				Description: "Indicates whether the container is the main site container.",
				Type:        proto.ColumnType_BOOL,
				Transform:   transform.FromField("Properties.IsMain"),
			},
			{
				Name:        "auth_type",
				Description: "The authentication type for the container image registry.",
				Type:        proto.ColumnType_STRING,
				Transform:   transform.FromField("Properties.AuthType").Transform(transformToString),
			},
			{
				Name:        "start_up_command",
				Description: "The container startup command.",
				Type:        proto.ColumnType_STRING,
				Transform:   transform.FromField("Properties.StartUpCommand"),
			},
			{
				Name:        "target_port",
				Description: "The target port for the container.",
				Type:        proto.ColumnType_STRING,
				Transform:   transform.FromField("Properties.TargetPort"),
			},
			{
				Name:        "user_managed_identity_client_id",
				Description: "The client ID of the user managed identity used by the container.",
				Type:        proto.ColumnType_STRING,
				Transform:   transform.FromField("Properties.UserManagedIdentityClientID"),
			},
			{
				Name:        "user_name",
				Description: "The user name for authenticating to the container image registry.",
				Type:        proto.ColumnType_STRING,
				Transform:   transform.FromField("Properties.UserName"),
			},
			{
				Name:        "created_time",
				Description: "The time when the site container was created.",
				Type:        proto.ColumnType_TIMESTAMP,
				Transform:   transform.FromField("Properties.CreatedTime").Transform(transform.NullIfZeroValue),
			},
			{
				Name:        "last_modified_time",
				Description: "The time when the site container was last modified.",
				Type:        proto.ColumnType_TIMESTAMP,
				Transform:   transform.FromField("Properties.LastModifiedTime").Transform(transform.NullIfZeroValue),
			},
			{
				Name:        "environment_variables",
				Description: "The environment variables configured for the site container.",
				Type:        proto.ColumnType_JSON,
				Transform:   transform.FromField("Properties.EnvironmentVariables"),
			},
			{
				Name:        "volume_mounts",
				Description: "The volume mounts configured for the site container.",
				Type:        proto.ColumnType_JSON,
				Transform:   transform.FromField("Properties.VolumeMounts"),
			},

			// Steampipe standard columns
			{
				Name:        "title",
				Description: ColumnDescriptionTitle,
				Type:        proto.ColumnType_STRING,
				Transform:   transform.FromField("Name").Transform(lastPathElement),
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
				Transform:   transform.FromField("ResourceGroup").Transform(toLower),
			},
		}),
	}
}

type SiteContainerInfo struct {
	armappservice.SiteContainer
	AppName       *string
	ResourceGroup *string
}

//// LIST FUNCTION

func listAppServiceSiteContainers(ctx context.Context, d *plugin.QueryData, h *plugin.HydrateData) (interface{}, error) {
	logger := plugin.Logger(ctx)
	logger.Trace("listAppServiceSiteContainers")

	if h.Item == nil {
		return nil, nil
	}

	app, ok := h.Item.(web.Site)
	if !ok {
		return nil, fmt.Errorf("unable to convert site from %+v to web.Site", h.Item)
	}
	if app.Name == nil || app.ResourceGroup == nil {
		return nil, nil
	}

	appName := *app.Name
	resourceGroup := *app.ResourceGroup

	if d.EqualsQualString("app_name") != "" && d.EqualsQualString("app_name") != appName {
		return nil, nil
	}

	session, err := GetNewSessionUpdated(ctx, d)
	if err != nil {
		logger.Error("azure_app_service_site_container.listAppServiceSiteContainers", "session_error", err)
		return nil, err
	}

	client, err := armappservice.NewWebAppsClient(session.SubscriptionID, session.Cred, session.ClientOptions)
	if err != nil {
		logger.Error("azure_app_service_site_container.listAppServiceSiteContainers", "client_error", err)
		return nil, err
	}

	pager := client.NewListSiteContainersPager(resourceGroup, appName, nil)
	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			logger.Error("azure_app_service_site_container.listAppServiceSiteContainers", "api_error", err)
			return nil, err
		}

		for _, container := range page.Value {
			if container == nil {
				continue
			}

			d.StreamListItem(ctx, &SiteContainerInfo{
				SiteContainer: *container,
				AppName:       &appName,
				ResourceGroup: &resourceGroup,
			})

			if d.RowsRemaining(ctx) == 0 {
				return nil, nil
			}
		}
	}

	return nil, nil
}

//// HYDRATE FUNCTIONS

func getAppServiceSiteContainer(ctx context.Context, d *plugin.QueryData, _ *plugin.HydrateData) (interface{}, error) {
	logger := plugin.Logger(ctx)
	logger.Trace("getAppServiceSiteContainer")

	name := d.EqualsQualString("name")
	appName := d.EqualsQualString("app_name")
	resourceGroup := d.EqualsQualString("resource_group")

	if name == "" || appName == "" || resourceGroup == "" {
		return nil, nil
	}

	session, err := GetNewSessionUpdated(ctx, d)
	if err != nil {
		logger.Error("azure_app_service_site_container.getAppServiceSiteContainer", "session_error", err)
		return nil, err
	}

	client, err := armappservice.NewWebAppsClient(session.SubscriptionID, session.Cred, session.ClientOptions)
	if err != nil {
		logger.Error("azure_app_service_site_container.getAppServiceSiteContainer", "client_error", err)
		return nil, err
	}

	resp, err := client.GetSiteContainer(ctx, resourceGroup, appName, name, nil)
	if err != nil {
		logger.Error("azure_app_service_site_container.getAppServiceSiteContainer", "api_error", err)
		return nil, err
	}

	if resp.ID == nil {
		return nil, nil
	}

	return &SiteContainerInfo{
		SiteContainer: resp.SiteContainer,
		AppName:       &appName,
		ResourceGroup: &resourceGroup,
	}, nil
}
