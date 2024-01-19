package gen

import "net"

// WgConfig represents a generated wireguard configuration for a single
// peer/server.
type WgConfig struct {
	ID                  uint   `yaml:"id"`
	Config              string `yaml:"config"`              // auto-generated
	Name                string `yaml:"name"`                // user-configurable
	Description         string `yaml:"description"`         // user-configurable
	Extra               string `yaml:"extra"`               // user-configurable
	IP                  string `yaml:"ip"`                  // user-configurable
	AllowedIPs          string `yaml:"allowedIPs"`          // user-configurable
	PersistentKeepAlive uint   `yaml:"persistentKeepAlive"` // user-configurable
	MTU                 uint16 `yaml:"mtu"`                 // user-configurable
	Endpoint            string `yaml:"endpoint"`            // user-configurable
	EndpointPort        uint16 `yaml:"endpointPort"`        // user-configurable
	DNS                 string `yaml:"dns"`                 // user-configurable
	IsServer            bool   `yaml:"isServer"`            // not editable; determined by the GenerationForm
	PrivateKey          string `yaml:"privateKey"`
	PublicKey           string `yaml:"publicKey"`
	PreSharedKey        string `yaml:"preSharedKey"`
}

// GenerationForm represents a user-submitted form.
type GenerationForm struct {
	CIDR                     string `yaml:"cidr"`
	DNS                      string `yaml:"dns"`
	Server                   string `yaml:"server"`          // ip address of the server within CIDR
	ServerInterface          string `yaml:"serverInterface"` // eth0, eno1, etc
	Endpoint                 string `yaml:"endpoint"`
	EndpointPort             uint16 `yaml:"endpointPort"` // publicly exposed wireguard server port
	MTU                      uint16 `yaml:"mtu"`
	AllowedIPs               string `yaml:"allowedIPs"`
	PersistentKeepAlive      uint   `yaml:"persistentKeepAlive"` // if 0, do not set
	Name                     string `yaml:"name"`                // for setting a placeholder name for peers
	Description              string `yaml:"description"`         // for setting a placeholder desc. for peers
	Extra                    string `yaml:"extra"`               // extra interface lines for peers
	RegenerateKeys           bool   `yaml:"regenerateKeys"`
	ResetAll                 bool   `yaml:"resetAll"`                 // if true, deletes everything
	ForceAllowedIPs          bool   `yaml:"forceAllowedIPs"`          // replaces all previous values if true
	ForcePersistentKeepAlive bool   `yaml:"forcePersistentKeepAlive"` // replaces all previous values if true
	ForceMTU                 bool   `yaml:"forceMtu"`                 // replaces all previous values if true
	ForceEndpoint            bool   `yaml:"forceEndpoint"`            // replaces all previous values if true
	ForceEndpointPort        bool   `yaml:"forceEndpointPort"`        // replaces all previous values if true
	ForceDNS                 bool   `yaml:"forceDns"`                 // replaces all previous values if true
	ForceName                bool   `yaml:"forceName"`                // replaces all previous values if true
	ForceDescription         bool   `yaml:"forceDescription"`         // replaces all previous values if true
	ForceExtra               bool   `yaml:"forceExtra"`               // replaces all previous values if true
}

type Configuration struct {
	// These are tweakable parameters, some of which will erase or preserve
	// fields between subsequent runs of this software.
	GenerationParams GenerationForm `yaml:"generationParams"`

	UseGzipDuringProcessing bool `yaml:"-"`

	// this is determined based on values from the GenerationParams
	serverIP net.IP
	// this is determined based on values from the GenerationParams
	firstIP net.IP
	// this is determined based on values from the GenerationParams
	network *net.IPNet

	// Human-readable names of devices, such as "laptop-01" and "server-01". The
	// order of these will be preserved when CIDR changes occur. For example,
	// the first device named "server-01" will have 192.168.1.1 for a CIDR of
	// 192.168.1.0/24, but if you decide to later change the CIDR to
	// 192.168.10.0/24, its new IP will be 192.168.10.1 since it's the first
	// possible member of that network.
	// Devices []string `yaml:"devices"`

	// Each of the peers in the network will be stored in this. This can be huge
	// if the chosen CIDR covers a large range.
	Peers []WgConfig `yaml:"peers"`

	peers map[uint]WgConfig
}
