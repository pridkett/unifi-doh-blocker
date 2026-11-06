package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"maps"
	"net"
	"net/http"
	"os"
	"slices"
	"strings"
	"time"

	"github.com/naoina/toml"
	log "github.com/sirupsen/logrus"
)

const (
	httpTimeout = 30 * time.Second
	// maxListBytes caps how much of a remote host list is read into memory
	maxListBytes = 10 << 20
)

// listHTTPClient always verifies TLS, even when the controller is insecure
var listHTTPClient = &http.Client{Timeout: httpTimeout}

type Config struct {
	Input struct {
		Lists []string
	}
	Unifi struct {
		User     string
		Password string
		Host     string
		Site     string
		Insecure bool
	}
	Output struct {
		Groups []OutputGroups
	}
}

type OutputGroups struct {
	Name string `toml:"name"`
	Type string `toml:"type"`
}

func main() {
	configFile := flag.String("config", "config.toml", "config file")
	flag.Parse()

	log.SetLevel(log.InfoLevel)

	if err := run(*configFile); err != nil {
		log.Fatal(err)
	}
}

// run fails closed: anything that could leave a group incomplete stops the
// update, so a transient failure never removes existing firewall blocks.
func run(configFile string) error {
	config, err := loadConfig(configFile)
	if err != nil {
		return err
	}

	var ipv4GroupName string
	var ipv6GroupName string
	for _, group := range config.Output.Groups {
		if group.Type == "ipv4" {
			ipv4GroupName = group.Name
		}
		if group.Type == "ipv6" {
			ipv6GroupName = group.Name
		}
	}

	if config.Unifi.Insecure {
		log.Warn("TLS verification is disabled for the Unifi controller")
	}
	InitUnifiClient(config.Unifi.Insecure)

	// Check the controller first so that a bad login or a missing group
	// is reported before spending time on hundreds of DNS lookups
	if _, err := UnifiLogin(config.Unifi.User, config.Unifi.Password, config.Unifi.Host); err != nil {
		return fmt.Errorf("could not login to Unifi Controller: %w", err)
	}

	firewallGroupResponse, err := UnifiGetFirewallGroups(config.Unifi.Host)
	if err != nil {
		return fmt.Errorf("could not retrieve firewall groups from Unifi Controller: %w", err)
	}

	ipv4Group, err := findGroup(firewallGroupResponse.Data, ipv4GroupName)
	if err != nil {
		return err
	}
	ipv6Group, err := findGroup(firewallGroupResponse.Data, ipv6GroupName)
	if err != nil {
		return err
	}

	hostList, err := createHostList(config.Input.Lists)
	if err != nil {
		return err
	}
	ipv4, ipv6 := lookupAllHosts(hostList)
	log.Infof("IPv4 Hosts: %d", len(ipv4))
	log.Infof("IPv6 Hosts: %d", len(ipv6))

	return errors.Join(
		updateGroup(config.Unifi.Host, ipv4Group, ipv4),
		updateGroup(config.Unifi.Host, ipv6Group, ipv6),
	)
}

func loadConfig(path string) (Config, error) {
	var config Config

	f, err := os.Open(path)
	if err != nil {
		return config, fmt.Errorf("could not open config: %w", err)
	}
	defer f.Close()
	log.Infof("Reading configuration from %s", path)

	if info, err := f.Stat(); err == nil && info.Mode().Perm()&0o077 != 0 {
		log.Warnf("%s holds credentials but is readable by other users (mode %04o)", path, info.Mode().Perm())
	}

	if err := toml.NewDecoder(f).Decode(&config); err != nil {
		return config, fmt.Errorf("could not parse config %s: %w", path, err)
	}
	return config, validateConfig(config)
}

func validateConfig(config Config) error {
	if !strings.HasPrefix(config.Unifi.Host, "https://") {
		return errors.New("unifi host must start with https:// so that credentials are not sent in cleartext")
	}
	if len(config.Output.Groups) == 0 {
		return errors.New("no output groups configured")
	}
	return nil
}

// findGroup returns the named group, or nil if no name was configured for it
func findGroup(groups []UnifiFirewallGroup, name string) (*UnifiFirewallGroup, error) {
	if name == "" {
		return nil, nil
	}
	for i := range groups {
		if groups[i].Name == name {
			return &groups[i], nil
		}
	}
	return nil, fmt.Errorf("firewall group %q does not exist on the Unifi Controller, create it first", name)
}

func updateGroup(host string, group *UnifiFirewallGroup, ips []net.IP) error {
	if group == nil {
		return nil
	}
	if len(ips) == 0 {
		return fmt.Errorf("refusing to empty firewall group %q: no addresses resolved", group.Name)
	}

	group.GroupMembers = make([]string, 0, len(ips))
	for _, ip := range ips {
		group.GroupMembers = append(group.GroupMembers, ip.String())
	}
	log.Infof("Updating firewall group \"%s\" with %d hosts", group.Name, len(group.GroupMembers))
	if _, err := UnifiUpdateFirewallGroup(host, *group); err != nil {
		return fmt.Errorf("could not update firewall group %q: %w", group.Name, err)
	}
	return nil
}

func isRemoteList(list string) bool {
	return strings.HasPrefix(list, "http://") || strings.HasPrefix(list, "https://")
}

func fetchList(listUrl string) (string, error) {
	if strings.HasPrefix(listUrl, "http://") {
		log.Warnf("Fetching %s over cleartext HTTP, its contents can be tampered with", listUrl)
	}

	response, err := listHTTPClient.Get(listUrl)
	if err != nil {
		return "", err
	}
	defer response.Body.Close()

	if response.StatusCode != http.StatusOK {
		return "", fmt.Errorf("unexpected status %s", response.Status)
	}

	body, err := io.ReadAll(io.LimitReader(response.Body, maxListBytes+1))
	if err != nil {
		return "", err
	}
	if len(body) > maxListBytes {
		return "", fmt.Errorf("list is larger than %d bytes", maxListBytes)
	}
	return string(body), nil
}

// given a list of URLs, fetches those URLs and dedups the results
// returning one master list of hostnames. Any unreadable list is an error
// because a partial result would remove hosts from the firewall group.
func createHostList(lists []string) ([]string, error) {
	allHosts := make(map[string]bool)
	for _, listUrl := range lists {
		var listBody string

		if isRemoteList(listUrl) {
			body, err := fetchList(listUrl)
			if err != nil {
				return nil, fmt.Errorf("could not retrieve list at %s: %w", listUrl, err)
			}
			listBody = body
		} else {
			// read the file listUrl into the variable listBody
			fileBody, err := os.ReadFile(listUrl)
			if err != nil {
				return nil, fmt.Errorf("could not open file %s: %w", listUrl, err)
			}
			listBody = string(fileBody)
		}

		hosts := strings.Split(strings.ReplaceAll(listBody, "\r\n", "\n"), "\n")
		for _, host := range hosts {
			allHosts[strings.ToLower(host)] = true
		}
		log.Infof("Read %d hosts from %s", len(hosts), listUrl)
	}

	// see https://stackoverflow.com/a/71635953/57626
	hostList := slices.Collect(maps.Keys(allHosts))
	log.Infof("Total of %d de-depublicated hosts", len(hostList))
	return hostList, nil
}

func lookupAllHosts(hostnames []string) ([]net.IP, []net.IP) {
	var ipv4Map = make(map[string]net.IP)
	var ipv6Map = make(map[string]net.IP)

	ipv4 := make([]net.IP, 0)
	ipv6 := make([]net.IP, 0)

	for _, hostname := range hostnames {
		thisIPv4, thisIPv6 := lookupHost(hostname)
		ipv4 = append(ipv4, thisIPv4...)
		ipv6 = append(ipv6, thisIPv6...)
	}

	// use a map to de-duplicate the IP addresses
	// this is required because Unifi will throw an error otherwise
	for _, ip := range ipv4 {
		ipv4Map[ip.String()] = ip
	}
	for _, ip := range ipv6 {
		ipv6Map[ip.String()] = ip
	}

	return slices.Collect(maps.Values(ipv4Map)), slices.Collect(maps.Values(ipv6Map))
}

// isPublicIP rejects addresses that must never reach a firewall block group.
// Lists and DNS answers aren't trusted: a sinkhole resolver returns 0.0.0.0,
// and a private address could cut off the local network or the gateway.
func isPublicIP(addr net.IP) bool {
	return addr.IsGlobalUnicast() && !addr.IsPrivate()
}

// lookup a hostname and get all of the IP addreses associated with it
func lookupHost(hostname string) ([]net.IP, []net.IP) {
	var ipv4 []net.IP
	var ipv6 []net.IP

	if strings.TrimSpace(hostname) == "" {
		return ipv4, ipv6
	}

	ips, err := net.LookupIP(hostname)
	if err != nil {
		log.Warnf("Could not resolve %s: %s", hostname, err)
		return ipv4, ipv6
	}
	for _, ip := range ips {
		if !isPublicIP(ip) {
			if !ip.IsUnspecified() {
				log.Warnf("Skipping non-public address %s for %s", ip, hostname)
			}
			continue
		}
		if ip.To4() != nil {
			log.Debugf("IPv4 %s: %s\n", hostname, ip)
			ipv4 = append(ipv4, ip)
		} else {
			log.Debugf("IPv6 %s: %s\n", hostname, ip)
			ipv6 = append(ipv6, ip)
		}
	}
	return ipv4, ipv6
}
