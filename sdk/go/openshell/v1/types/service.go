// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package types

// ServiceAuthorizationMode controls handling of an incoming application Authorization header.
type ServiceAuthorizationMode int32

const (
	// ServiceAuthorizationModeStrip removes Authorization before proxying to the sandbox service.
	ServiceAuthorizationModeStrip ServiceAuthorizationMode = 1
	// ServiceAuthorizationModeBearerPassthrough forwards one valid bearer credential unchanged.
	ServiceAuthorizationModeBearerPassthrough ServiceAuthorizationMode = 2
)

// ServiceExposure describes a loopback HTTP service to expose during sandbox creation.
type ServiceExposure struct {
	Service           string
	TargetPort        uint32
	AuthorizationMode ServiceAuthorizationMode
}

// ServiceEndpoint represents an exposed HTTP service on a sandbox.
type ServiceEndpoint struct {
	ID                string
	SandboxID         string
	Sandbox           string
	Name              string
	TargetPort        uint32
	Domain            bool
	URL               string
	Workspace         string
	AuthorizationMode ServiceAuthorizationMode
	RoutingMode       ServiceRoutingMode
	Status            ServiceExposureStatus
}

// ServiceRoutingMode identifies the configured application data path.
type ServiceRoutingMode int32

const (
	// ServiceRoutingModeUnspecified is returned by older gateways.
	ServiceRoutingModeUnspecified ServiceRoutingMode = 0
	// ServiceRoutingModeGateway uses the gateway listener and relay.
	ServiceRoutingModeGateway ServiceRoutingMode = 1
	// ServiceRoutingModeSupervisor uses the separately configured public ingress.
	ServiceRoutingModeSupervisor ServiceRoutingMode = 2
)

// ServiceExposureStatus describes installation evidence, not application health.
type ServiceExposureStatus int32

const (
	// ServiceExposureStatusUnspecified is returned by older gateways.
	ServiceExposureStatusUnspecified ServiceExposureStatus = 0
	// ServiceExposureStatusConfigured indicates a declaration with installation potentially pending.
	ServiceExposureStatusConfigured ServiceExposureStatus = 1
	// ServiceExposureStatusAdvertised indicates a current, leased supervisor installation.
	ServiceExposureStatusAdvertised ServiceExposureStatus = 2
	// ServiceExposureStatusUnavailable indicates missing runtime, admission, or installation evidence.
	ServiceExposureStatusUnavailable ServiceExposureStatus = 3
)
