package azure

import (
	"context"

	"github.com/Azure/azure-sdk-for-go/profiles/latest/compute/mgmt/compute"
	"github.com/turbot/steampipe-plugin-sdk/v5/grpc/proto"
	"github.com/turbot/steampipe-plugin-sdk/v5/plugin"
	"github.com/turbot/steampipe-plugin-sdk/v5/plugin/transform"
)

//// TABLE DEFINITION

func tableAzureComputeVirtualMachineMetricAvailableMemoryHourly(_ context.Context) *plugin.Table {
	return &plugin.Table{
		Name:        "azure_compute_virtual_machine_metric_available_memory_hourly",
		Description: "Azure Compute Virtual Machine Metrics - Memory Available Utilization (Hourly)",
		List: &plugin.ListConfig{
			ParentHydrate: listComputeVirtualMachines,
			Hydrate:       listComputeVirtualMachineMetricAvailableMemoryHourly,
			Tags: map[string]string{
				"service": "Microsoft.Insights",
				"action":  "metrics/read",
			},
		},
		Columns: monitoringMetricColumns([]*plugin.Column{
			{
				Name:        "name",
				Description: "The name of the virtual machine.",
				Type:        proto.ColumnType_STRING,
				Transform:   transform.FromField("DimensionValue").Transform(lastPathElement),
			},
		}),
	}
}

//// LIST FUNCTION

func listComputeVirtualMachineMetricAvailableMemoryHourly(ctx context.Context, d *plugin.QueryData, h *plugin.HydrateData) (interface{}, error) {
	vmInfo := h.Item.(compute.VirtualMachine)

	return listAzureMonitorMetricStatistics(ctx, d, "HOURLY", "Microsoft.Compute/virtualMachines", "Available Memory Bytes", *vmInfo.ID)
}
