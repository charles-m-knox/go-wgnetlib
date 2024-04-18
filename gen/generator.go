package gen

import (
	"fmt"
	"log"
	"net"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"

	"github.com/pterm/pterm"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

// applySoftRules allows non-empty values to be preserved for existing peers,
// and desired values will be set for all other empty peer values.
func (conf *Configuration) applySoftRules(w *WgConfig) error {
	if w == nil {
		return fmt.Errorf("received nil w ptr when applying soft rules")
	}

	if w.Name == "" {
		w.Name = conf.GenerationParams.Name
		w.Name = strings.ReplaceAll(w.Name, "${id}", strconv.FormatUint(uint64(w.ID), 10))
	}

	if w.Description == "" {
		w.Description = conf.GenerationParams.Description
		w.Description = strings.ReplaceAll(w.Description, "${id}", strconv.FormatUint(uint64(w.ID), 10))
		w.Description = strings.ReplaceAll(w.Description, "${name}", w.Name)
	}

	if w.Extra == "" {
		w.Extra = conf.GenerationParams.Extra
		w.Extra = strings.ReplaceAll(w.Extra, "${id}", strconv.FormatUint(uint64(w.ID), 10))
		w.Extra = strings.ReplaceAll(w.Extra, "${name}", w.Name)
	}

	if w.AllowedIPs == "" {
		if conf.GenerationParams.AllowedIPs == "" {
			w.AllowedIPs = DefaultAllowedIPs
		} else {
			w.AllowedIPs = conf.GenerationParams.AllowedIPs
		}
	}

	if w.DNS == "" && !w.IsServer { // don't set the dns for the server
		w.DNS = conf.GenerationParams.DNS
	}

	if w.PersistentKeepAlive == 0 {
		w.PersistentKeepAlive = conf.GenerationParams.PersistentKeepAlive
	}

	if w.MTU == 0 {
		w.MTU = DefaultMTU
	}

	if w.Endpoint == "" {
		w.Endpoint = conf.GenerationParams.Endpoint
	}

	if w.EndpointPort == 0 {
		w.EndpointPort = conf.GenerationParams.EndpointPort
	}

	return nil
}

// applyKeyRules generates and assigns Wireguard public, private, and pre-shared
// keys.
func (conf *Configuration) applyKeyRules(w *WgConfig) error {
	if w == nil {
		return fmt.Errorf("received nil w ptr when applying key rules")
	}

	if w.PrivateKey == "" || w.PublicKey == "" || conf.GenerationParams.RegenerateKeys {
		privKey, err := wgtypes.GeneratePrivateKey()
		if err != nil {
			return fmt.Errorf(
				"error generating private key: %v",
				err.Error(),
			)
		}

		w.PrivateKey = privKey.String()
		w.PublicKey = privKey.PublicKey().String()
	}

	if w.PreSharedKey == "" || conf.GenerationParams.RegenerateKeys {
		w.PreSharedKey = GeneratePreSharedKey()
	}

	return nil
}

// applyForcedRules ensures that rules to override all other values are obeyed,
// for example, forceably setting the AllowedIPs to the value specified in
// the generation form.
func (conf *Configuration) applyForcedRules(w *WgConfig) error {
	if w == nil {
		return fmt.Errorf("received nil w ptr when applying forced rules")
	}

	if conf.GenerationParams.ForceAllowedIPs {
		w.AllowedIPs = conf.GenerationParams.AllowedIPs
	}

	if conf.GenerationParams.ForcePersistentKeepAlive {
		w.PersistentKeepAlive = conf.GenerationParams.PersistentKeepAlive
	}

	if conf.GenerationParams.ForceMTU {
		w.MTU = conf.GenerationParams.MTU
	}

	if conf.GenerationParams.ForceEndpoint {
		w.Endpoint = conf.GenerationParams.Endpoint
	}

	if conf.GenerationParams.ForceEndpointPort {
		w.EndpointPort = conf.GenerationParams.EndpointPort
	}

	if conf.GenerationParams.ForceDNS && !w.IsServer { // don't set the DNS for the server
		w.DNS = conf.GenerationParams.DNS
	}

	if conf.GenerationParams.ForceName {
		w.Name = conf.GenerationParams.Name
	}

	if conf.GenerationParams.ForceDescription {
		w.Description = conf.GenerationParams.Description
	}

	if conf.GenerationParams.ForceExtra {
		w.Extra = conf.GenerationParams.Extra
	}

	return nil
}

func validateServer(server WgConfig) error {
	// assert that the server.ID is a non-zero value - the lowest possible ID
	// is 1
	if server.ID == 0 {
		return fmt.Errorf("invalid configured server ID 0")
	}

	// do some other basic data quality checks
	if server.PublicKey == "" || server.PrivateKey == "" {
		return fmt.Errorf("configured server has empty public/private key")
	}

	if server.IP == "" {
		return fmt.Errorf("configured server has empty IP address")
	}

	return nil
}

func (w *WgConfig) GenerateConfig(server WgConfig) (string, error) {
	persistentKeepAlive := ""
	if w.PersistentKeepAlive > 0 {
		persistentKeepAlive = "\nPersistentKeepAlive = 25"
	}

	extra := ""
	if w.Extra != "" {
		extra = fmt.Sprintf("\n%v", w.Extra)
	}

	return fmt.Sprintf(`[Interface]%v
PrivateKey = %s
Address = %s/32
DNS = %s
MTU = %v

[Peer]
PublicKey = %s
PresharedKey = %s
Endpoint = %s:%v
AllowedIPs = %v%v
`,
		extra,
		w.PrivateKey,
		w.IP,
		w.DNS,
		w.MTU,
		server.PublicKey,
		w.PreSharedKey,
		w.Endpoint,
		w.EndpointPort,
		w.AllowedIPs,
		persistentKeepAlive,
	), nil
}

// GenerateServerConfig generates a Wireguard configuration that includes
// every possible connectable peer for its defined network CIDR.
// Note that in this function the serverPeers argument is nothing more than
// a string that will be appended after the server's interface config.
func (w *WgConfig) GenerateServerConfig(
	conf *Configuration,
	// serverPeers string,
	spgz []string,
	network *net.IPNet,
) string {
	maskSize, _ := network.Mask.Size()

	extra := ""
	if w.Extra != "" {
		extra = fmt.Sprintf("\n%v", w.Extra)
	}

	dns := ""
	if w.DNS != "" {
		dns = fmt.Sprintf("\nDNS = %v", w.DNS)
	}

	var config strings.Builder

	config.WriteString(fmt.Sprintf(`[Interface]%v
PrivateKey = %s
Address = %s/%d
ListenPort = %v%v
MTU = %v
PostUp = iptables -A FORWARD -i %%i -j ACCEPT; iptables -A FORWARD -o %%i -j ACCEPT; iptables -t nat -A POSTROUTING -o %v -j MASQUERADE
PostDown = iptables -D FORWARD -i %%i -j ACCEPT; iptables -D FORWARD -o %%i -j ACCEPT; iptables -t nat -D POSTROUTING -o %v -j MASQUERADE

`,
		extra,
		w.PrivateKey,
		w.IP,
		maskSize,
		conf.GenerationParams.EndpointPort,
		dns,
		conf.GenerationParams.MTU,
		conf.GenerationParams.ServerInterface,
		conf.GenerationParams.ServerInterface,
	))

	for _, sgz := range spgz {
		if conf.UseGzipDuringProcessing {
			s, err := GunzipString(sgz)
			if err != nil {
				log.Fatalf("failed to gunzip string: %v", err.Error())
			}

			config.WriteString(s)
		} else {
			config.WriteString(sgz)
		}
	}

	return config.String()
}

type IPAddress struct {
	// the ip address as a string value
	S string
	// the IP address as a net.IP value
	IP net.IP
	// whether this IP is the server IP
	IsServerIP bool
}

// Generate is the primary function of this software. It will manipulate the
// peers according to the defined generation parameters. You are responsible for
// serializing & writing the resulting configuration to a yaml (or other
// serializable) file.
//
// Depending on how large your CIDR network is, this may take a while and may
// use a lot of RAM. Use care - make sure to save your valuable work in case
// your system runs out of memory if you did something like a /8 block.
//
// If interactive is true, terminal progress bars and messages will be produced.
func (conf *Configuration) Generate(interactive bool) error {
	var err error

	firstIP, cidrNet, err := net.ParseCIDR(conf.GenerationParams.CIDR)
	if err != nil {
		return fmt.Errorf("failed to parse cidr: %w", err)
	}

	if cidrNet == nil {
		return fmt.Errorf("failed to determine cidr net, check the cidr value")
	}

	// assert that the user provided an aligned CIDR block
	actualCIDR := fmt.Sprintf("%v", cidrNet)
	if actualCIDR != conf.GenerationParams.CIDR {
		return fmt.Errorf(
			"cidr %v is not a correctly aligned subnet; use the correctly aligned subnet %v instead",
			conf.GenerationParams.CIDR,
			actualCIDR,
		)
	}

	parsedServer := net.ParseIP(conf.GenerationParams.Server)
	if parsedServer == nil {
		return fmt.Errorf("server is not an ip address: %v", conf.GenerationParams.Server)
	}

	if cidrNet != nil && !cidrNet.Contains(parsedServer) {
		return fmt.Errorf(
			"server must be an ip address within the range %v: %v",
			conf.GenerationParams.CIDR,
			conf.GenerationParams.Server,
		)
	}

	conf.firstIP = firstIP
	conf.network = cidrNet
	conf.serverIP = parsedServer

	// reset the peers map for the configuration - it's ephemeral
	conf.peers = make(map[uint]WgConfig)

	// First, generate keypairs for every possible IP address within the range,
	// and while doing this, take note of which of them corresponds to the
	// IP address within the range that equals the server's IP address.
	//
	// 1. Generate all possible WgConfig values, ensuring that old name/
	//    description values are preserved, if possible.

	// reset the database if requested.
	if conf.GenerationParams.ResetAll {
		conf.Peers = []WgConfig{}
	}

	// edge case: All values in the database above the generated IP range need
	// to be cleared out - in particular, they need to have their IsServer flag
	// cleared. Start by doing this first.
	for i := range conf.Peers {
		if conf.Peers[i].IsServer {
			conf.Peers[i].IsServer = false
		}

		conf.peers[uint(i)] = conf.Peers[i]
	}

	// take note of the total number of wireguard configs to generate so we
	// can accurately render a progress bar readout.
	wgs := EstimateNetworkSize(conf.network)

	var multi pterm.MultiPrinter

	var pbProcessed *pterm.ProgressbarPrinter

	var pbPreProcessed *pterm.ProgressbarPrinter

	var pbPostProcessing *pterm.ProgressbarPrinter

	pbProcessedIncrement := func() {
		if interactive {
			pbProcessed.Increment()
		}
	}

	pbPreProcessedIncrement := func() {
		if interactive {
			pbPreProcessed.Increment()
		}
	}

	pbPostProcessingIncrement := func() {
		if interactive {
			pbPostProcessing.Increment()
		}
	}

	if interactive {
		multi = pterm.DefaultMultiPrinter
		// need to go through the total list of IP addresses at least twice
		pbPreProcessed, _ = pterm.DefaultProgressbar.WithWriter(multi.NewWriter()).WithTotal(wgs).Start("Pre-processing IPs")
		pbProcessed, _ = pterm.DefaultProgressbar.WithWriter(multi.NewWriter()).WithTotal(wgs).Start("Peers configured")
		pbPostProcessing, _ = pterm.DefaultProgressbar.WithWriter(multi.NewWriter()).WithTotal(wgs).Start(
			"Peers post-processed",
		)
		_, _ = multi.Start()
	}

	// take note of every IP address that we have to operate on
	allIPs := []IPAddress{}
	ip := conf.firstIP
	serverIPIndex := -1

	k := 0

	for {
		pbPreProcessedIncrement()

		ipa := IPAddress{
			S:          ip.String(),
			IP:         ip,
			IsServerIP: false,
		}

		// if the IP address ends with .0 or .255, skip it
		if strings.HasSuffix(ipa.S, ".0") || strings.HasSuffix(ipa.S, ".255") {
			ip = NextIP(ip)

			continue
		}

		if !conf.network.Contains(ip) {
			break
		}

		if ipa.IP.Equal(conf.serverIP) {
			ipa.IsServerIP = true
			serverIPIndex = k
		}

		allIPs = append(allIPs, ipa)
		ip = NextIP(ip)
		k++
	}

	ips := len(allIPs)

	if interactive {
		pbProcessed.Total = ips
		pbPostProcessing.Total = ips
	}

	var progress int64

	var server *WgConfig

	// serverpeer list but each item is gzipped to conserve memory
	spgz := []string{}

	mutex := &sync.Mutex{}

	// take note of the number of pre-existing peers so it doesn't have to be
	// re-checked
	numPeers := uint(len(conf.Peers))

	// prepDevice preps a single device, this is useful for processing
	// the server first before everything else. The logic at this step
	// is the same as all other devices though, only the server will behave
	// slightly different in a few spots.
	prepDevice := func(i uint, ip IPAddress) error {
		// attempt to find any existing record of this config
		var w WgConfig

		if numPeers >= i {
			mutex.Lock()
			w = conf.Peers[i-1] // no need to check if ok; zero-value is fine too
			mutex.Unlock()
		}

		// update values. Note that in general, if a value in the form is
		// left blank, the original value will be preserved where possible.
		w.ID = i
		w.IP = ip.S
		w.IsServer = ip.IsServerIP

		err = conf.applySoftRules(&w)
		if err != nil {
			return err
		}

		err = conf.applyForcedRules(&w)
		if err != nil {
			return err
		}

		err = conf.applyKeyRules(&w)
		if err != nil {
			return err
		}

		if server != nil && !w.IsServer {
			// generate the peer config for this peer
			peerConf, err := w.GenerateConfig(*server)
			if err != nil {
				return fmt.Errorf("error generating config for client %v: %w", i, err)
			}

			w.Config = peerConf

			serverPeer := fmt.Sprintf(
				"[Peer]\nPublicKey = %s\nAllowedIPs = %s/32\nPresharedKey = %s\n\n",
				w.PublicKey,
				w.IP,
				w.PreSharedKey,
			)

			serverPeerGz := serverPeer
			if conf.UseGzipDuringProcessing {
				// this saves RAM while processing server peers
				// but slows down processing
				serverPeerGz, err = GzipString(serverPeer)
				if err != nil {
					return fmt.Errorf("failed to gzip server peer: %w", err)
				}
			}

			mutex.Lock()

			spgz = append(spgz, serverPeerGz)
			mutex.Unlock()
		}

		mutex.Lock()
		conf.peers[i] = w
		mutex.Unlock()

		return nil
	}

	prepFn := func(wg *sync.WaitGroup, progress *int64, i uint, ip IPAddress) error {
		defer wg.Done()

		err := prepDevice(i, ip)
		if err != nil {
			return err
		}

		atomic.AddInt64(progress, 1)

		pbProcessedIncrement()

		return nil
	}

	prepFnWrapped := func(wg *sync.WaitGroup, progress *int64, i uint, ip IPAddress) {
		err := prepFn(wg, progress, i, ip)
		if err != nil {
			log.Fatalf("error generating keys and configuring peers: %v", err.Error())
		}
	}

	// generate the server first - this allows more parallel processing to be
	// done in one step
	if serverIPIndex >= 0 && allIPs[serverIPIndex].IsServerIP {
		err = prepDevice(uint(serverIPIndex)+1, allIPs[serverIPIndex])
		if err != nil {
			return fmt.Errorf("failed to write server: %w", err)
		}
	} else {
		return fmt.Errorf("index of server not valid: %v", serverIPIndex)
	}

	// now find the server we just created and assert that it's valid
	server = &WgConfig{}

	foundServer := false

	var serverIndex uint

	for k, v := range conf.peers {
		if v.IsServer {
			foundServer = true
			*server = v
			serverIndex = k

			break
		}
	}

	if !foundServer {
		return fmt.Errorf("failed to find generated server")
	}

	err = validateServer(*server)
	if err != nil {
		return err
	}

	chunkSize := 1000
	for j := 0; j < ips; j += chunkSize {
		end := j + chunkSize
		// Check if end is out of bounds
		if end > ips {
			end = ips
		}

		var wg sync.WaitGroup
		for l := j; l < end; l++ {
			i := uint(l + 1) // the primary key in the db is 1-based index, not 0
			if allIPs[l].IsServerIP {
				continue
			}

			wg.Add(1)

			go prepFnWrapped(&wg, &progress, i, allIPs[l])
		}
		wg.Wait()
	}

	if interactive {
		pbProcessed.Current = ips - 1 // trick it into updating before stopping
		pbProcessed.Increment()
		pbProcessed.Stop()
	}

	// 3. Finally, update the server config.
	// log.Println("saving final server config")

	server.Config = server.GenerateServerConfig(conf, spgz /* serverPeers.String() */, conf.network)

	conf.peers[serverIndex] = *server

	// convert the peers map to a slice
	conf.Peers = []WgConfig{}

	for i := 1; i <= len(conf.peers); i++ {
		conf.Peers = append(conf.Peers, conf.peers[uint(i)])

		pbPostProcessingIncrement()
	}

	// clear out the peers map to save memory
	conf.peers = nil

	// log.Println("done")

	// pbProcessedUpdate(100)

	return nil
}
