package azure

import (
	"context"
	"strings"

	"github.com/Azure/azure-sdk-for-go/profiles/latest/network/mgmt/network"
	"github.com/turbot/steampipe-plugin-sdk/v5/grpc/proto"
	"github.com/turbot/steampipe-plugin-sdk/v5/plugin"
	"github.com/turbot/steampipe-plugin-sdk/v5/plugin/transform"
)

type firewallPolicyRuleCollectionGroupInfo struct {
	Group          network.FirewallPolicyRuleCollectionGroup
	Name           *string
	FirewallPolicy *string
	ResourceGroup  *string
	Region         *string
}

func tableAzureFirewallPolicyRuleCollectionGroup(_ context.Context) *plugin.Table {
	return &plugin.Table{
		Name:        "azure_firewall_policy_rule_collection_group",
		Description: "Azure Firewall Policy Rule Collection Group",
		Get: &plugin.GetConfig{
			KeyColumns: plugin.AllColumns([]string{"name", "firewall_policy_name", "resource_group"}),
			Hydrate:    getFirewallPolicyRuleCollectionGroup,
			Tags: map[string]string{
				"service": "Microsoft.Network",
				"action":  "firewallPolicies/ruleCollectionGroups/read",
			},
			IgnoreConfig: &plugin.IgnoreConfig{
				ShouldIgnoreErrorFunc: isNotFoundError([]string{"ResourceNotFound", "NotFound", "ResourceGroupNotFound", "404"}),
			},
		},
		List: &plugin.ListConfig{
			ParentHydrate: listFirewallPolicies,
			Hydrate:       listFirewallPolicyRuleCollectionGroups,
			Tags: map[string]string{
				"service": "Microsoft.Network",
				"action":  "firewallPolicies/ruleCollectionGroups/read",
			},
		},
		Columns: azureColumns([]*plugin.Column{
			{
				Name:        "name",
				Description: "The friendly name that identifies the firewall policy rule collection group.",
				Type:        proto.ColumnType_STRING,
				Transform:   transform.FromField("Name"),
			},
			{
				Name:        "id",
				Description: "Contains ID to identify a firewall policy rule collection group uniquely.",
				Type:        proto.ColumnType_STRING,
				Transform:   transform.FromField("Group.ID"),
			},
			{
				Name:        "firewall_policy_name",
				Description: "The friendly name that identifies the parent firewall policy.",
				Type:        proto.ColumnType_STRING,
				Transform:   transform.FromField("FirewallPolicy"),
			},
			{
				Name:        "etag",
				Description: "A unique read-only string that changes whenever the resource is updated.",
				Type:        proto.ColumnType_STRING,
				Transform:   transform.FromField("Group.Etag"),
			},
			{
				Name:        "type",
				Description: "Type of the resource.",
				Type:        proto.ColumnType_STRING,
				Transform:   transform.FromField("Group.Type"),
			},
			{
				Name:        "priority",
				Description: "Priority of the firewall policy rule collection group resource.",
				Type:        proto.ColumnType_INT,
				Transform:   transform.FromField("Group.FirewallPolicyRuleCollectionGroupProperties.Priority"),
			},
			{
				Name:        "provisioning_state",
				Description: "The provisioning state of the firewall policy rule collection group resource.",
				Type:        proto.ColumnType_STRING,
				Transform:   transform.FromField("Group.FirewallPolicyRuleCollectionGroupProperties.ProvisioningState").Transform(transform.ToString),
			},
			{
				Name:        "rule_collections",
				Description: "Group of firewall policy rule collections, including NAT, filter, and other rule collection types.",
				Type:        proto.ColumnType_JSON,
				Transform:   transform.FromField("Group.FirewallPolicyRuleCollectionGroupProperties.RuleCollections"),
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
				Transform:   transform.FromField("Group.ID").Transform(idToAkas),
			},

			// Azure standard columns
			{
				Name:        "region",
				Description: ColumnDescriptionRegion,
				Type:        proto.ColumnType_STRING,
				Transform:   transform.FromField("Region").Transform(toLower),
			},
			{
				Name:        "resource_group",
				Description: ColumnDescriptionResourceGroup,
				Type:        proto.ColumnType_STRING,
				Transform:   transform.FromField("ResourceGroup").Transform(toLower),
			},
		}),
	}
}

func listFirewallPolicyRuleCollectionGroups(ctx context.Context, d *plugin.QueryData, h *plugin.HydrateData) (interface{}, error) {
	firewallPolicy := h.Item.(network.FirewallPolicy)
	resourceGroupName := strings.Split(*firewallPolicy.ID, "/")[4]

	session, err := GetNewSession(ctx, d, "MANAGEMENT")
	if err != nil {
		return nil, err
	}
	subscriptionID := session.SubscriptionID

	client := network.NewFirewallPolicyRuleCollectionGroupsClientWithBaseURI(session.ResourceManagerEndpoint, subscriptionID)
	client.Authorizer = session.Authorizer

	ApplyRetryRules(ctx, &client, d.Connection)

	result, err := client.List(ctx, resourceGroupName, *firewallPolicy.Name)
	if err != nil {
		return nil, err
	}

	for _, group := range result.Values() {
		d.StreamListItem(ctx, firewallPolicyRuleCollectionGroupInfo{group, group.Name, firewallPolicy.Name, &resourceGroupName, firewallPolicy.Location})
		if d.RowsRemaining(ctx) == 0 {
			return nil, nil
		}
	}

	for result.NotDone() {
		d.WaitForListRateLimit(ctx)

		err = result.NextWithContext(ctx)
		if err != nil {
			return nil, err
		}

		for _, group := range result.Values() {
			d.StreamListItem(ctx, firewallPolicyRuleCollectionGroupInfo{group, group.Name, firewallPolicy.Name, &resourceGroupName, firewallPolicy.Location})
			if d.RowsRemaining(ctx) == 0 {
				return nil, nil
			}
		}
	}

	return nil, nil
}

func getFirewallPolicyRuleCollectionGroup(ctx context.Context, d *plugin.QueryData, h *plugin.HydrateData) (interface{}, error) {
	plugin.Logger(ctx).Trace("getFirewallPolicyRuleCollectionGroup")

	resourceGroup := d.EqualsQuals["resource_group"].GetStringValue()
	firewallPolicyName := d.EqualsQuals["firewall_policy_name"].GetStringValue()
	name := d.EqualsQuals["name"].GetStringValue()

	if resourceGroup == "" || firewallPolicyName == "" || name == "" {
		return nil, nil
	}

	session, err := GetNewSession(ctx, d, "MANAGEMENT")
	if err != nil {
		return nil, err
	}
	subscriptionID := session.SubscriptionID

	client := network.NewFirewallPolicyRuleCollectionGroupsClientWithBaseURI(session.ResourceManagerEndpoint, subscriptionID)
	client.Authorizer = session.Authorizer
	firewallPolicyClient := network.NewFirewallPoliciesClientWithBaseURI(session.ResourceManagerEndpoint, subscriptionID)
	firewallPolicyClient.Authorizer = session.Authorizer

	ApplyRetryRules(ctx, &client, d.Connection)
	ApplyRetryRules(ctx, &firewallPolicyClient, d.Connection)

	op, err := client.Get(ctx, resourceGroup, firewallPolicyName, name)
	if err != nil {
		return nil, err
	}

	if op.ID != nil {
		policy, err := firewallPolicyClient.Get(ctx, resourceGroup, firewallPolicyName, "")
		if err != nil {
			return nil, err
		}

		return firewallPolicyRuleCollectionGroupInfo{op, op.Name, &firewallPolicyName, &resourceGroup, policy.Location}, nil
	}

	return nil, nil
}
