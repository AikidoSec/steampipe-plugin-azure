package azure

import (
	"context"

	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/containerservice/armcontainerservice/v7"
	"github.com/turbot/steampipe-plugin-sdk/v5/grpc/proto"
	"github.com/turbot/steampipe-plugin-sdk/v5/plugin/transform"

	"github.com/turbot/steampipe-plugin-sdk/v5/plugin"
)

//// TABLE DEFINITION

func tableAzureKubernetesCluster(_ context.Context) *plugin.Table {
	return &plugin.Table{
		Name:        "azure_kubernetes_cluster",
		Description: "Azure Kubernetes Cluster",
		Get: &plugin.GetConfig{
			KeyColumns: plugin.AllColumns([]string{"name", "resource_group"}),
			Hydrate:    getKubernetesCluster,
			Tags: map[string]string{
				"service": "Microsoft.ContainerService",
				"action":  "managedClusters/read",
			},
		},
		List: &plugin.ListConfig{
			Hydrate: listKubernetesClusters,
			Tags: map[string]string{
				"service": "Microsoft.ContainerService",
				"action":  "managedClusters/read",
			},
		},
		Columns: azureColumns([]*plugin.Column{
			{
				Name:        "name",
				Type:        proto.ColumnType_STRING,
				Description: "The name of the cluster.",
			},
			{
				Name:        "id",
				Description: "The ID of the cluster.",
				Type:        proto.ColumnType_STRING,
				Transform:   transform.FromGo(),
			},
			{
				Name:        "type",
				Description: "The type of the cluster.",
				Type:        proto.ColumnType_STRING,
			},
			{
				Name:        "location",
				Description: "The location where the cluster is created.",
				Type:        proto.ColumnType_STRING,
			},
			{
				Name:        "azure_portal_fqdn",
				Description: "FQDN for the master pool which used by proxy config.",
				Type:        proto.ColumnType_STRING,
				Transform:   transform.FromField("Properties.AzurePortalFQDN"),
			},
			{
				Name:        "disk_encryption_set_id",
				Description: "ResourceId of the disk encryption set to use for enabling encryption at rest.",
				Type:        proto.ColumnType_STRING,
				Transform:   transform.FromField("Properties.DiskEncryptionSetID"),
			},
			{
				Name:        "dns_prefix",
				Description: "DNS prefix specified when creating the managed cluster.",
				Type:        proto.ColumnType_STRING,
				Transform:   transform.FromField("Properties.DNSPrefix"),
			},
			{
				Name:        "enable_pod_security_policy",
				Description: "Whether to enable Kubernetes pod security policy (preview).",
				Type:        proto.ColumnType_BOOL,
				Transform:   transform.FromField("Properties.EnablePodSecurityPolicy"),
			},
			{
				Name:        "enable_rbac",
				Description: "Whether to enable Kubernetes Role-Based Access Control.",
				Type:        proto.ColumnType_BOOL,
				Transform:   transform.FromField("Properties.EnableRBAC"),
			},
			{
				Name:        "fqdn",
				Description: "FQDN for the master pool.",
				Type:        proto.ColumnType_STRING,
				Transform:   transform.FromField("Properties.Fqdn"),
			},
			{
				Name:        "fqdn_subdomain",
				Description: "FQDN subdomain specified when creating private cluster with custom private dns zone.",
				Type:        proto.ColumnType_STRING,
				Transform:   transform.FromField("Properties.FqdnSubdomain"),
			},
			{
				Name:        "kubernetes_version",
				Description: "Version of Kubernetes specified when creating the managed cluster.",
				Type:        proto.ColumnType_STRING,
				Transform:   transform.FromField("Properties.KubernetesVersion"),
			},
			{
				Name:        "max_agent_pools",
				Description: "The max number of agent pools for the managed cluster.",
				Type:        proto.ColumnType_INT,
				Transform:   transform.FromField("Properties.MaxAgentPools"),
			},
			{
				Name:        "node_resource_group",
				Description: "Name of the resource group containing agent pool nodes.",
				Type:        proto.ColumnType_STRING,
				Transform:   transform.FromField("Properties.NodeResourceGroup"),
			},
			{
				Name:        "private_fqdn",
				Description: "FQDN of private cluster.",
				Type:        proto.ColumnType_STRING,
				Transform:   transform.FromField("Properties.PrivateFQDN"),
			},
			{
				Name:        "provisioning_state",
				Description: "The current deployment or provisioning state.",
				Type:        proto.ColumnType_STRING,
				Transform:   transform.FromField("Properties.ProvisioningState"),
			},
			{
				Name:        "aad_profile",
				Description: "Profile of Azure Active Directory configuration.",
				Type:        proto.ColumnType_JSON,
				Transform:   transform.FromField("Properties.AADProfile"),
			},
			{
				Name:        "addon_profiles",
				Description: "Profile of managed cluster add-on.",
				Type:        proto.ColumnType_JSON,
				Transform:   transform.FromField("Properties.AddonProfiles"),
			},
			{
				Name:        "agent_pool_profiles",
				Description: "Properties of the agent pool.",
				Type:        proto.ColumnType_JSON,
				Transform:   transform.FromField("Properties.AgentPoolProfiles"),
			},
			{
				Name:        "api_server_access_profile",
				Description: "Access profile for managed cluster API server.",
				Type:        proto.ColumnType_JSON,
				Transform:   transform.FromField("Properties.APIServerAccessProfile"),
			},
			{
				Name:        "auto_scaler_profile",
				Description: "Parameters to be applied to the cluster-autoscaler when enabled.",
				Type:        proto.ColumnType_JSON,
				Transform:   transform.FromField("Properties.AutoScalerProfile"),
			},
			{
				Name:        "auto_upgrade_profile",
				Description: "Profile of auto upgrade configuration.",
				Type:        proto.ColumnType_JSON,
				Transform:   transform.FromField("Properties.AutoUpgradeProfile"),
			},
			{
				Name:        "identity",
				Description: "The identity of the managed cluster, if configured.",
				Type:        proto.ColumnType_JSON,
			},
			{
				Name:        "identity_profile",
				Description: "Identities associated with the cluster.",
				Type:        proto.ColumnType_JSON,
				Transform:   transform.FromField("Properties.IdentityProfile"),
			},
			{
				Name:        "linux_profile",
				Description: "Profile for Linux VMs in the container service cluster.",
				Type:        proto.ColumnType_JSON,
				Transform:   transform.FromField("Properties.LinuxProfile"),
			},
			{
				Name:        "network_profile",
				Description: "Profile of network configuration.",
				Type:        proto.ColumnType_JSON,
				Transform:   transform.FromField("Properties.NetworkProfile"),
			},
			{
				Name:        "pod_identity_profile",
				Description: "Profile of managed cluster pod identity.",
				Type:        proto.ColumnType_JSON,
				Transform:   transform.FromField("Properties.PodIdentityProfile"),
			},
			{
				Name:        "power_state",
				Description: "Represents the Power State of the cluster.",
				Type:        proto.ColumnType_JSON,
				Transform:   transform.FromField("Properties.PowerState"),
			},
			{
				Name:        "service_principal_profile",
				Description: "Information about a service principal identity for the cluster to use for manipulating Azure APIs.",
				Type:        proto.ColumnType_JSON,
				Transform:   transform.FromField("Properties.ServicePrincipalProfile"),
			},
			{
				Name:        "sku",
				Description: "The managed cluster SKU.",
				Type:        proto.ColumnType_JSON,
			},
			{
				Name:        "windows_profile",
				Description: "Profile for Windows VMs in the container service cluster.",
				Type:        proto.ColumnType_JSON,
				Transform:   transform.FromField("Properties.WindowsProfile"),
			},
			{
				Name:        "security_profile",
				Description: "Profile of security configuration.",
				Type:        proto.ColumnType_JSON,
				Transform:   transform.FromField("Properties.SecurityProfile"),
			},
			{
				Name:        "disabled_local_accounts",
				Description: "If set to true, getting static credentials will be disabled for this cluster.",
				Type:        proto.ColumnType_JSON,
				Transform:   transform.FromField("Properties.DisableLocalAccounts"),
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

func listKubernetesClusters(ctx context.Context, d *plugin.QueryData, _ *plugin.HydrateData) (interface{}, error) {
	logger := plugin.Logger(ctx)
	logger.Trace("listKubernetesClusters")

	session, err := GetNewSessionUpdated(ctx, d)
	if err != nil {
		logger.Error("azure_kubernetes_cluster.listKubernetesClusters", "session_error", err)
		return nil, err
	}

	client, err := armcontainerservice.NewManagedClustersClient(session.SubscriptionID, session.Cred, session.ClientOptions)
	if err != nil {
		return nil, err
	}

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

func getKubernetesCluster(ctx context.Context, d *plugin.QueryData, _ *plugin.HydrateData) (interface{}, error) {
	logger := plugin.Logger(ctx)
	logger.Trace("getKubernetesCluster")

	resourceName := d.EqualsQuals["name"].GetStringValue()
	resourceGroupName := d.EqualsQuals["resource_group"].GetStringValue()

	if resourceName == "" || resourceGroupName == "" {
		return nil, nil
	}

	session, err := GetNewSessionUpdated(ctx, d)
	if err != nil {
		logger.Error("azure_kubernetes_cluster.listKubernetesClusters", "session_error", err)
		return nil, err
	}

	client, err := armcontainerservice.NewManagedClustersClient(session.SubscriptionID, session.Cred, session.ClientOptions)
	if err != nil {
		return nil, err
	}

	op, err := client.Get(ctx, resourceGroupName, resourceName, nil)
	if err != nil {
		return nil, err
	}

	// In some cases resource does not give any notFound error
	// instead of notFound error, it returns empty data
	if op.ID != nil {
		return op, nil
	}

	return nil, nil
}
