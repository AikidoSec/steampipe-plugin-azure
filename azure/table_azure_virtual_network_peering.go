package azure

import (
	"context"
	"strings"

	"github.com/Azure/azure-sdk-for-go/profiles/latest/network/mgmt/network"
	"github.com/turbot/steampipe-plugin-sdk/v5/grpc/proto"
	"github.com/turbot/steampipe-plugin-sdk/v5/plugin"
	"github.com/turbot/steampipe-plugin-sdk/v5/plugin/transform"
)

type virtualNetworkPeeringInfo struct {
	Peering        network.VirtualNetworkPeering
	Name           *string
	VirtualNetwork *string
	ResourceGroup  *string
}

func tableAzureVirtualNetworkPeering(_ context.Context) *plugin.Table {
	return &plugin.Table{
		Name:        "azure_virtual_network_peering",
		Description: "Azure Virtual Network Peering",
		Get: &plugin.GetConfig{
			KeyColumns: plugin.AllColumns([]string{"name", "virtual_network_name", "resource_group"}),
			Hydrate:    getVirtualNetworkPeering,
			Tags: map[string]string{
				"service": "Microsoft.Network",
				"action":  "virtualNetworks/virtualNetworkPeerings/read",
			},
			IgnoreConfig: &plugin.IgnoreConfig{
				ShouldIgnoreErrorFunc: isNotFoundError([]string{"ResourceNotFound", "NotFound", "ResourceGroupNotFound", "404"}),
			},
		},
		List: &plugin.ListConfig{
			ParentHydrate: listVirtualNetworks,
			Hydrate:       listVirtualNetworkPeerings,
			Tags: map[string]string{
				"service": "Microsoft.Network",
				"action":  "virtualNetworks/virtualNetworkPeerings/read",
			},
		},
		Columns: azureColumns([]*plugin.Column{
			{
				Name:        "name",
				Description: "The friendly name that identifies the virtual network peering.",
				Type:        proto.ColumnType_STRING,
				Transform:   transform.FromField("Name"),
			},
			{
				Name:        "id",
				Description: "Contains ID to identify a virtual network peering uniquely.",
				Type:        proto.ColumnType_STRING,
				Transform:   transform.FromField("Peering.ID"),
			},
			{
				Name:        "virtual_network_name",
				Description: "The friendly name of the virtual network containing the peering.",
				Type:        proto.ColumnType_STRING,
				Transform:   transform.FromField("VirtualNetwork"),
			},
			{
				Name:        "etag",
				Description: "A unique read-only string that changes whenever the resource is updated.",
				Type:        proto.ColumnType_STRING,
				Transform:   transform.FromField("Peering.Etag"),
			},
			{
				Name:        "type",
				Description: "Type of the resource.",
				Type:        proto.ColumnType_STRING,
				Transform:   transform.FromField("Peering.Type"),
			},
			{
				Name:        "provisioning_state",
				Description: "The provisioning state of the virtual network peering resource.",
				Type:        proto.ColumnType_STRING,
				Transform:   transform.FromField("Peering.VirtualNetworkPeeringPropertiesFormat.ProvisioningState").Transform(transform.ToString),
			},
			{
				Name:        "peering_state",
				Description: "The status of the virtual network peering.",
				Type:        proto.ColumnType_STRING,
				Transform:   transform.FromField("Peering.VirtualNetworkPeeringPropertiesFormat.PeeringState").Transform(transform.ToString),
			},
			{
				Name:        "peering_sync_level",
				Description: "The peering sync status of the virtual network peering.",
				Type:        proto.ColumnType_STRING,
				Transform:   transform.FromField("Peering.VirtualNetworkPeeringPropertiesFormat.PeeringSyncLevel").Transform(transform.ToString),
			},
			{
				Name:        "allow_virtual_network_access",
				Description: "Indicates whether the VMs in the local virtual network space can access the VMs in the remote virtual network space.",
				Type:        proto.ColumnType_BOOL,
				Transform:   transform.FromField("Peering.VirtualNetworkPeeringPropertiesFormat.AllowVirtualNetworkAccess"),
			},
			{
				Name:        "allow_forwarded_traffic",
				Description: "Indicates whether forwarded traffic from the local virtual network will be allowed in the remote virtual network.",
				Type:        proto.ColumnType_BOOL,
				Transform:   transform.FromField("Peering.VirtualNetworkPeeringPropertiesFormat.AllowForwardedTraffic"),
			},
			{
				Name:        "allow_gateway_transit",
				Description: "Indicates whether gateway links can be used in remote virtual networking to link to this virtual network.",
				Type:        proto.ColumnType_BOOL,
				Transform:   transform.FromField("Peering.VirtualNetworkPeeringPropertiesFormat.AllowGatewayTransit"),
			},
			{
				Name:        "use_remote_gateways",
				Description: "Indicates whether remote gateways can be used on this virtual network.",
				Type:        proto.ColumnType_BOOL,
				Transform:   transform.FromField("Peering.VirtualNetworkPeeringPropertiesFormat.UseRemoteGateways"),
			},
			{
				Name:        "do_not_verify_remote_gateways",
				Description: "Indicates whether to skip verification of the remote gateway provisioning state.",
				Type:        proto.ColumnType_BOOL,
				Transform:   transform.FromField("Peering.VirtualNetworkPeeringPropertiesFormat.DoNotVerifyRemoteGateways"),
			},
			{
				Name:        "resource_guid",
				Description: "The resource GUID property of the virtual network peering resource.",
				Type:        proto.ColumnType_STRING,
				Transform:   transform.FromField("Peering.VirtualNetworkPeeringPropertiesFormat.ResourceGUID"),
			},
			{
				Name:        "remote_virtual_network_id",
				Description: "The ID of the remote virtual network.",
				Type:        proto.ColumnType_STRING,
				Transform:   transform.FromField("Peering.VirtualNetworkPeeringPropertiesFormat.RemoteVirtualNetwork.ID"),
			},
			{
				Name:        "remote_address_prefixes",
				Description: "The address space peered with the remote virtual network.",
				Type:        proto.ColumnType_JSON,
				Transform:   transform.FromField("Peering.VirtualNetworkPeeringPropertiesFormat.RemoteAddressSpace.AddressPrefixes"),
			},
			{
				Name:        "remote_virtual_network_address_prefixes",
				Description: "The current address space of the remote virtual network.",
				Type:        proto.ColumnType_JSON,
				Transform:   transform.FromField("Peering.VirtualNetworkPeeringPropertiesFormat.RemoteVirtualNetworkAddressSpace.AddressPrefixes"),
			},
			{
				Name:        "remote_bgp_communities",
				Description: "The BGP communities of the remote virtual network.",
				Type:        proto.ColumnType_JSON,
				Transform:   transform.FromField("Peering.VirtualNetworkPeeringPropertiesFormat.RemoteBgpCommunities"),
			},
			{
				Name:        "remote_virtual_network_encryption",
				Description: "The encryption settings of the remote virtual network.",
				Type:        proto.ColumnType_JSON,
				Transform:   transform.FromField("Peering.VirtualNetworkPeeringPropertiesFormat.RemoteVirtualNetworkEncryption"),
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
				Transform:   transform.FromField("Peering.ID").Transform(idToAkas),
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

func listVirtualNetworkPeerings(ctx context.Context, d *plugin.QueryData, h *plugin.HydrateData) (interface{}, error) {
	virtualNetwork := h.Item.(network.VirtualNetwork)
	resourceGroup := strings.Split(*virtualNetwork.ID, "/")[4]

	session, err := GetNewSession(ctx, d, "MANAGEMENT")
	if err != nil {
		return nil, err
	}
	subscriptionID := session.SubscriptionID

	client := network.NewVirtualNetworkPeeringsClientWithBaseURI(session.ResourceManagerEndpoint, subscriptionID)
	client.Authorizer = session.Authorizer

	ApplyRetryRules(ctx, &client, d.Connection)

	result, err := client.List(ctx, resourceGroup, *virtualNetwork.Name)
	if err != nil {
		return nil, err
	}

	for _, peering := range result.Values() {
		d.StreamListItem(ctx, virtualNetworkPeeringInfo{peering, peering.Name, virtualNetwork.Name, &resourceGroup})
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

		for _, peering := range result.Values() {
			d.StreamListItem(ctx, virtualNetworkPeeringInfo{peering, peering.Name, virtualNetwork.Name, &resourceGroup})
			if d.RowsRemaining(ctx) == 0 {
				return nil, nil
			}
		}
	}

	return nil, nil
}

func getVirtualNetworkPeering(ctx context.Context, d *plugin.QueryData, h *plugin.HydrateData) (interface{}, error) {
	plugin.Logger(ctx).Trace("getVirtualNetworkPeering")

	resourceGroup := d.EqualsQuals["resource_group"].GetStringValue()
	virtualNetworkName := d.EqualsQuals["virtual_network_name"].GetStringValue()
	name := d.EqualsQuals["name"].GetStringValue()

	if resourceGroup == "" || virtualNetworkName == "" || name == "" {
		return nil, nil
	}

	session, err := GetNewSession(ctx, d, "MANAGEMENT")
	if err != nil {
		return nil, err
	}
	subscriptionID := session.SubscriptionID

	client := network.NewVirtualNetworkPeeringsClientWithBaseURI(session.ResourceManagerEndpoint, subscriptionID)
	client.Authorizer = session.Authorizer

	ApplyRetryRules(ctx, &client, d.Connection)

	op, err := client.Get(ctx, resourceGroup, virtualNetworkName, name)
	if err != nil {
		return nil, err
	}

	if op.ID != nil {
		return virtualNetworkPeeringInfo{op, op.Name, &virtualNetworkName, &resourceGroup}, nil
	}

	return nil, nil
}
