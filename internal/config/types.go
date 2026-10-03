package config

import "github.com/astoreyai/hostdesk/internal/model"

// These values are generated on the installation host, never shipped as inventory.
type Config struct {
	Listen                string   `json:"listen"`
	ExternalOrigin        string   `json:"externalOrigin,omitempty"`
	AllowedTailscaleUsers []string `json:"allowedTailscaleUsers"`
	ProjectRoots          []string `json:"projectRoots"`
	BrokerSocket          string   `json:"brokerSocket,omitempty"`
	StateDir              string   `json:"stateDir"`
	RefreshSeconds        int      `json:"refreshSeconds"`
}

// BrokerPolicy is root-owned; an HTTP request cannot widen its authority.
type BrokerPolicy struct {
	AllowedUID           int                 `json:"allowedUID"`
	Socket               string              `json:"socket"`
	StateDir             string              `json:"stateDir"`
	AllowedSystemUnits   []string            `json:"allowedSystemUnits"`
	AllowedContainers    []string            `json:"allowedContainers"`
	ProtectedTCPPorts    []int               `json:"protectedTCPPorts"`
	InitialNetworkPolicy model.NetworkPolicy `json:"initialNetworkPolicy"`
}
