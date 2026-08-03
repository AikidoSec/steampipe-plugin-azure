package azure

import (
	"context"
	"strings"

	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/mongocluster/armmongocluster"
	"github.com/turbot/steampipe-plugin-sdk/v5/grpc/proto"
	"github.com/turbot/steampipe-plugin-sdk/v5/plugin"
	"github.com/turbot/steampipe-plugin-sdk/v5/plugin/transform"
)

//// TABLE DEFINITION

func tableAzureDocumentDBMongoCluster(_ context.Context) *plugin.Table {
	return &plugin.Table{
		Name:        "azure_documentdb_mongo_cluster",
		Description: "Azure DocumentDB Mongo Cluster",
		List: &plugin.ListConfig{
			Hydrate: listDocumentDBMongoClusters,
			Tags: map[string]string{
				"service": "Microsoft.DocumentDB",
				"action":  "mongoClusters/read",
			},
		},
		Columns: azureColumns([]*plugin.Column{
			{
				Name:        "name",
				Description: "The friendly name that identifies the Mongo cluster.",
				Type:        proto.ColumnType_STRING,
			},
			{
				Name:        "id",
				Description: "Contains ID to identify a Mongo cluster uniquely.",
				Type:        proto.ColumnType_STRING,
				Transform:   transform.FromField("ID"),
			},
			{
				Name:        "type",
				Description: "Type of the resource.",
				Type:        proto.ColumnType_STRING,
			},
			{
				Name:        "created_time",
				Description: "The created time of the Mongo cluster.",
				Type:        proto.ColumnType_TIMESTAMP,
				Transform:   transform.FromField("SystemData.CreatedAt"),
			},
			{
				Name:        "changed_time",
				Description: "The changed time of the Mongo cluster.",
				Type:        proto.ColumnType_TIMESTAMP,
				Transform:   transform.FromField("SystemData.LastModifiedAt"),
			},
			{
				Name:        "provisioning_state",
				Description: "The provisioning state of the Mongo cluster.",
				Type:        proto.ColumnType_STRING,
				Hydrate:     getDocumentDBMongoClusterDetails,
				Transform:   transform.FromField("Properties.ProvisioningState").Transform(transformToString),
			},
			{
				Name:        "cluster_status",
				Description: "The status of the Mongo cluster.",
				Type:        proto.ColumnType_STRING,
				Hydrate:     getDocumentDBMongoClusterDetails,
				Transform:   transform.FromField("Properties.ClusterStatus").Transform(transformToString),
			},
			{
				Name:        "create_mode",
				Description: "The mode used to create the Mongo cluster.",
				Type:        proto.ColumnType_STRING,
				Hydrate:     getDocumentDBMongoClusterDetails,
				Transform:   transform.FromField("Properties.CreateMode").Transform(transformToString),
			},
			{
				Name:        "public_network_access",
				Description: "Whether or not public endpoint access is allowed for the Mongo cluster.",
				Type:        proto.ColumnType_STRING,
				Hydrate:     getDocumentDBMongoClusterDetails,
				Transform:   transform.FromField("Properties.PublicNetworkAccess").Transform(transformToString),
			},
			{
				Name:        "ip_rules",
				Description: "A list of firewall rules configured for the Mongo cluster.",
				Type:        proto.ColumnType_JSON,
				Hydrate:     getDocumentDBMongoClusterIPRules,
				Transform:   transform.FromValue(),
			},
			{
				Name:        "server_version",
				Description: "The MongoDB server version.",
				Type:        proto.ColumnType_STRING,
				Hydrate:     getDocumentDBMongoClusterDetails,
				Transform:   transform.FromField("Properties.ServerVersion"),
			},
			{
				Name:        "auth_config",
				Description: "The authentication configuration for the Mongo cluster.",
				Type:        proto.ColumnType_JSON,
				Hydrate:     getDocumentDBMongoClusterDetails,
				Transform:   transform.FromField("Properties.AuthConfig"),
			},
			{
				Name:        "compute",
				Description: "The compute configuration for the Mongo cluster.",
				Type:        proto.ColumnType_JSON,
				Hydrate:     getDocumentDBMongoClusterDetails,
				Transform:   transform.FromField("Properties.Compute"),
			},
			{
				Name:        "high_availability",
				Description: "The high availability configuration for the Mongo cluster.",
				Type:        proto.ColumnType_JSON,
				Hydrate:     getDocumentDBMongoClusterDetails,
				Transform:   transform.FromField("Properties.HighAvailability"),
			},
			{
				Name:        "identity",
				Description: "The managed service identity assigned to the Mongo cluster.",
				Type:        proto.ColumnType_JSON,
			},
			{
				Name:        "network_bypass_mode",
				Description: "The network bypass mode for the Mongo cluster.",
				Type:        proto.ColumnType_STRING,
				Hydrate:     getDocumentDBMongoClusterDetails,
				Transform:   transform.FromField("Properties.NetworkBypassMode").Transform(transformToString),
			},
			{
				Name:        "preview_features",
				Description: "The list of preview features enabled on the Mongo cluster.",
				Type:        proto.ColumnType_JSON,
				Hydrate:     getDocumentDBMongoClusterDetails,
				Transform:   transform.FromField("Properties.PreviewFeatures"),
			},
			{
				Name:        "private_endpoint_connections",
				Description: "A list of private endpoint connections configured for the Mongo cluster.",
				Type:        proto.ColumnType_JSON,
				Hydrate:     getDocumentDBMongoClusterDetails,
				Transform:   transform.FromField("Properties.PrivateEndpointConnections"),
			},
			{
				Name:        "replica",
				Description: "The replication properties for the Mongo cluster.",
				Type:        proto.ColumnType_JSON,
				Hydrate:     getDocumentDBMongoClusterDetails,
				Transform:   transform.FromField("Properties.Replica"),
			},
			{
				Name:        "replica_parameters",
				Description: "The parameters used to create a replica Mongo cluster.",
				Type:        proto.ColumnType_JSON,
				Hydrate:     getDocumentDBMongoClusterDetails,
				Transform:   transform.FromField("Properties.ReplicaParameters"),
			},
			{
				Name:        "restore_parameters",
				Description: "The parameters used to create a point-in-time restored Mongo cluster.",
				Type:        proto.ColumnType_JSON,
				Hydrate:     getDocumentDBMongoClusterDetails,
				Transform:   transform.FromField("Properties.RestoreParameters"),
			},
			{
				Name:        "sharding",
				Description: "The sharding configuration for the Mongo cluster.",
				Type:        proto.ColumnType_JSON,
				Hydrate:     getDocumentDBMongoClusterDetails,
				Transform:   transform.FromField("Properties.Sharding"),
			},
			{
				Name:        "storage",
				Description: "The storage configuration for the Mongo cluster.",
				Type:        proto.ColumnType_JSON,
				Hydrate:     getDocumentDBMongoClusterDetails,
				Transform:   transform.FromField("Properties.Storage"),
			},
			{
				Name:        "properties",
				Description: "The resource properties.",
				Type:        proto.ColumnType_JSON,
				Hydrate:     getDocumentDBMongoClusterDetails,
				Transform:   transform.FromField("Properties"),
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

func listDocumentDBMongoClusters(ctx context.Context, d *plugin.QueryData, _ *plugin.HydrateData) (interface{}, error) {
	session, err := GetNewSessionUpdated(ctx, d)
	if err != nil {
		plugin.Logger(ctx).Error("azure_documentdb_mongo_cluster.listDocumentDBMongoClusters", "session_error", err)
		return nil, err
	}

	client, err := armmongocluster.NewMongoClustersClient(session.SubscriptionID, session.Cred, session.ClientOptions)
	if err != nil {
		plugin.Logger(ctx).Error("azure_documentdb_mongo_cluster.listDocumentDBMongoClusters", "client_error", err)
		return nil, err
	}

	pager := client.NewListPager(nil)
	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			plugin.Logger(ctx).Error("azure_documentdb_mongo_cluster.listDocumentDBMongoClusters", "api_error", err)
			return nil, err
		}
		for _, cluster := range page.Value {
			// Wait for rate limiting
			d.WaitForListRateLimit(ctx)

			d.StreamListItem(ctx, cluster)
			if d.RowsRemaining(ctx) == 0 {
				return nil, nil
			}
		}
	}

	return nil, nil
}

//// HYDRATE FUNCTIONS

func getDocumentDBMongoClusterDetails(ctx context.Context, d *plugin.QueryData, h *plugin.HydrateData) (interface{}, error) {
	cluster := h.Item.(*armmongocluster.MongoCluster)
	if cluster.Properties != nil {
		return cluster, nil
	}

	resourceGroup := documentDBMongoClusterResourceGroup(cluster)
	if resourceGroup == "" || cluster.Name == nil {
		return nil, nil
	}

	session, err := GetNewSessionUpdated(ctx, d)
	if err != nil {
		plugin.Logger(ctx).Error("azure_documentdb_mongo_cluster.getDocumentDBMongoClusterDetails", "session_error", err)
		return nil, err
	}

	client, err := armmongocluster.NewMongoClustersClient(session.SubscriptionID, session.Cred, session.ClientOptions)
	if err != nil {
		plugin.Logger(ctx).Error("azure_documentdb_mongo_cluster.getDocumentDBMongoClusterDetails", "client_error", err)
		return nil, err
	}

	op, err := client.Get(ctx, resourceGroup, *cluster.Name, nil)
	if err != nil {
		plugin.Logger(ctx).Error("azure_documentdb_mongo_cluster.getDocumentDBMongoClusterDetails", "api_error", err)
		return nil, err
	}

	return &op.MongoCluster, nil
}

func getDocumentDBMongoClusterIPRules(ctx context.Context, d *plugin.QueryData, h *plugin.HydrateData) (interface{}, error) {
	cluster := h.Item.(*armmongocluster.MongoCluster)
	resourceGroup := documentDBMongoClusterResourceGroup(cluster)
	if resourceGroup == "" || cluster.Name == nil {
		return nil, nil
	}

	session, err := GetNewSessionUpdated(ctx, d)
	if err != nil {
		plugin.Logger(ctx).Error("azure_documentdb_mongo_cluster.getDocumentDBMongoClusterIPRules", "session_error", err)
		return nil, err
	}

	client, err := armmongocluster.NewFirewallRulesClient(session.SubscriptionID, session.Cred, session.ClientOptions)
	if err != nil {
		plugin.Logger(ctx).Error("azure_documentdb_mongo_cluster.getDocumentDBMongoClusterIPRules", "client_error", err)
		return nil, err
	}

	var ipRules []map[string]interface{}
	pager := client.NewListByMongoClusterPager(resourceGroup, *cluster.Name, nil)
	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			plugin.Logger(ctx).Error("azure_documentdb_mongo_cluster.getDocumentDBMongoClusterIPRules", "api_error", err)
			return nil, err
		}
		for _, rule := range page.Value {
			ipRules = appendDocumentDBMongoClusterIPRule(ipRules, rule)
		}
	}

	if len(ipRules) == 0 {
		return nil, nil
	}

	return ipRules, nil
}

//// TRANSFORM FUNCTIONS

func appendDocumentDBMongoClusterIPRule(ipRules []map[string]interface{}, rule *armmongocluster.FirewallRule) []map[string]interface{} {
	if rule == nil || rule.Properties == nil {
		return ipRules
	}

	ipRule := map[string]interface{}{
		"properties": rule.Properties,
	}
	if rule.Properties.StartIPAddress != nil {
		ipRule["startIpAddress"] = *rule.Properties.StartIPAddress
	}
	if rule.Properties.EndIPAddress != nil {
		ipRule["endIpAddress"] = *rule.Properties.EndIPAddress
	}

	return append(ipRules, ipRule)
}

func documentDBMongoClusterResourceGroup(cluster *armmongocluster.MongoCluster) string {
	if cluster == nil || cluster.ID == nil {
		return ""
	}

	parts := strings.Split(*cluster.ID, "/")
	for i, part := range parts {
		if strings.EqualFold(part, "resourceGroups") && i+1 < len(parts) {
			return parts[i+1]
		}
	}

	return ""
}
