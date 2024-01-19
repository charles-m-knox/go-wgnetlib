package gen

const (
	HelpTextSelectedDeviceName = "Name of this device. Can be any string."

	HelpTextCIDR           = "IPv4 CIDR range for the mesh network, such as 192.168.1.0/24"
	HelpTextMTU            = "The Maximum Transmission Unit for every connection (suggest 1280-1500)"
	HelpTextPort           = "The port that the server will listen on, typically 51820"
	HelpTextServer         = "IPv4 address of the Wireguard server, within the provided CIDR range"
	HelpTextEndpoint       = "The hostname/IP of the server that each peer will connect to"
	HelpTextRegenerateKeys = "Instead of reusing keys between config changes, generate new ones"
	HelpTextDNS            = "DNS server peers will use, such as 1.1.1.1"
	HelpTextPSK            = "Wireguard Pre-Shared Key (PSK) value ('wg genpsk' on command line)"

	DefaultAllowedIPs          = "0.0.0.0/0"
	DefaultPersistentKeepAlive = uint(25)
	DefaultEndpointPort        = uint16(51820)
	DefaultMTU                 = uint16(1280)
)
