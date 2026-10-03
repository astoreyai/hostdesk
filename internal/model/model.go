package model

import "time"

type Host struct {
	Name         string `json:"name"`
	OS           string `json:"os"`
	Kernel       string `json:"kernel"`
	Architecture string `json:"architecture"`
}

type Source struct {
	Name      string    `json:"name"`
	Available bool      `json:"available"`
	Error     string    `json:"error,omitempty"`
	CheckedAt time.Time `json:"checkedAt"`
}

type Service struct {
	ID               string   `json:"id"`
	Name             string   `json:"name"`
	Manager          string   `json:"manager"`
	Scope            string   `json:"scope"`
	State            string   `json:"state"`
	Substate         string   `json:"substate,omitempty"`
	Enabled          string   `json:"enabled,omitempty"`
	Description      string   `json:"description,omitempty"`
	PID              int      `json:"pid,omitempty"`
	WorkingDirectory string   `json:"workingDirectory,omitempty"`
	Path             string   `json:"path,omitempty"`
	Ports            []int    `json:"ports"`
	Actions          []string `json:"actions"`
	ProtectionReason string   `json:"protectionReason,omitempty"`
}

type Listener struct {
	ID          string `json:"id"`
	Protocol    string `json:"protocol"`
	Address     string `json:"address"`
	Port        int    `json:"port"`
	Family      string `json:"family"`
	Exposure    string `json:"exposure"`
	PID         int    `json:"pid,omitempty"`
	Process     string `json:"process,omitempty"`
	ServiceID   string `json:"serviceId,omitempty"`
	PolicyState string `json:"policyState"`
	Note        string `json:"note,omitempty"`
}

type Project struct {
	ID         string   `json:"id"`
	Name       string   `json:"name"`
	Path       string   `json:"path"`
	Kind       string   `json:"kind"`
	Git        bool     `json:"git"`
	ServiceIDs []string `json:"serviceIds"`
}

type Route struct {
	ID       string `json:"id"`
	Provider string `json:"provider"`
	Address  string `json:"address"`
	Target   string `json:"target"`
	Status   string `json:"status"`
	Public   bool   `json:"public"`
	Error    string `json:"error,omitempty"`
}

type Snapshot struct {
	Version     int        `json:"version"`
	GeneratedAt time.Time  `json:"generatedAt"`
	Host        Host       `json:"host"`
	Sources     []Source   `json:"sources"`
	Services    []Service  `json:"services"`
	Listeners   []Listener `json:"listeners"`
	Projects    []Project  `json:"projects"`
	Routes      []Route    `json:"routes"`
	Warnings    []string   `json:"warnings"`
}

type PrivilegedSnapshot struct {
	Sources   []Source   `json:"sources"`
	Services  []Service  `json:"services"`
	Listeners []Listener `json:"listeners"`
	Routes    []Route    `json:"routes"`
	Warnings  []string   `json:"warnings"`
}

type InterfacePolicy struct {
	Name                  string `json:"name"`
	TCPPorts              []int  `json:"tcpPorts"`
	UDPPorts              []int  `json:"udpPorts"`
	AllowTailscalePeerAPI bool   `json:"allowTailscalePeerAPI"`
}

type NetworkPolicy struct {
	Interfaces []InterfacePolicy `json:"interfaces"`
}

type NetworkState struct {
	Available         bool           `json:"available"`
	Error             string         `json:"error,omitempty"`
	Policy            NetworkPolicy  `json:"policy"`
	Revision          string         `json:"revision"`
	ProtectedTCPPorts []int          `json:"protectedTCPPorts"`
	Pending           *PendingPolicy `json:"pending,omitempty"`
	Rules             string         `json:"rules,omitempty"`
}

type PendingPolicy struct {
	Token     string    `json:"token"`
	ExpiresAt time.Time `json:"expiresAt"`
}

type ActionRequest struct {
	ID        string `json:"id"`
	Operation string `json:"operation"`
}

type Preview struct {
	Token        string    `json:"token"`
	Summary      string    `json:"summary"`
	Confirmation string    `json:"confirmation"`
	Warnings     []string  `json:"warnings"`
	ExpiresAt    time.Time `json:"expiresAt"`
	Rules        string    `json:"rules,omitempty"`
}

type ApplyRequest struct {
	Token        string `json:"token"`
	Confirmation string `json:"confirmation"`
}

type PolicyRequest struct {
	Revision string        `json:"revision"`
	Policy   NetworkPolicy `json:"policy"`
}

type AuditEntry struct {
	Time      time.Time `json:"time"`
	Actor     string    `json:"actor"`
	Operation string    `json:"operation"`
	Target    string    `json:"target"`
	Success   bool      `json:"success"`
	Detail    string    `json:"detail,omitempty"`
}
