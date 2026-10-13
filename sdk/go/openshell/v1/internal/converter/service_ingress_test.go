// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES.
// SPDX-License-Identifier: Apache-2.0

package converter

import (
	"github.com/NVIDIA/OpenShell/sdk/go/openshell/v1/types"
	pb "github.com/NVIDIA/OpenShell/sdk/go/proto/openshellv1"
	"github.com/stretchr/testify/require"
	"testing"
)

func TestServiceIngressResponsePreservesPublicPortAndInstallationStatus(t *testing.T) {
	response := &pb.ServiceEndpointResponse{
		Url:         "https://default--sandbox--web.api.openshell-sandbox-proxy-ingress.my-domain:28443/",
		RoutingMode: pb.ServiceRoutingMode_SERVICE_ROUTING_MODE_SUPERVISOR,
		Status:      pb.ServiceExposureStatus_SERVICE_EXPOSURE_STATUS_ADVERTISED,
	}
	endpoint := ServiceEndpointFromProto(response)
	require.Equal(t, response.Url, endpoint.URL)
	require.Equal(t, types.ServiceRoutingModeSupervisor, endpoint.RoutingMode)
	require.Equal(t, types.ServiceExposureStatusAdvertised, endpoint.Status)
	restored := ServiceEndpointToProto(endpoint)
	require.Equal(t, response.Url, restored.Url)
	require.Equal(t, response.RoutingMode, restored.RoutingMode)
	require.Equal(t, response.Status, restored.Status)
}
