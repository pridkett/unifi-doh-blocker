package main

import (
	"flag"
	"io/ioutil"
	"net"
	"net/http"
	"os"
	"strings"

	"github.com/naoina/toml"
	log "github.com/sirupsen/logrus"
	"golang.org/x/exp/maps"
)

type Config struct {
	Input struct {
		Lists []string
	}
	Unifi struct {
		User     string
		Password string
		Host     string
		Site     string
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
	var config Config
	var ipv4GroupName string
	var ipv6GroupName string

	configFile := flag.String("config", "config.toml", "config file")
	flag.Parse()

	log.SetLevel(log.DebugLevel)

	if *configFile != "" {
		f, err := os.Open(*configFile)
		if err != nil {
			panic(err)
		}
		log.Infof("Reading configuration from %s", *configFile)
		defer f.Close()
		if err := toml.NewDecoder(f).Decode(&config); err != nil {
			panic(err)
		}
	}

	for _, group := range config.Output.Groups {
		if group.Type == "ipv4" {
			ipv4GroupName = group.Name
		}
		if group.Type == "ipv6" {
			ipv6GroupName = group.Name
		}
	}

	hostList := createHostList(config.Input.Lists)
	ipv4, ipv6 := lookupAllHosts(hostList)
	log.Infof("IPv4 Hosts: %d", len(ipv4))
	log.Infof("IPv6 Hosts: %d", len(ipv6))

	_, err := UnifiLogin(config.Unifi.User, config.Unifi.Password, config.Unifi.Host)
	if err != nil {
		log.Errorf("Could not login to Unifi Controller: %s", err)
		os.Exit(1)
	}

	firewallGroupResponse, err := UnifiGetFirewallGroups(config.Unifi.Host)
	if err != nil {
		log.Errorf("Could not retrieve firewall groups from Unifi Controller: %s", err)
	}

	var ipv4Group UnifiFirewallGroup
	var ipv6Group UnifiFirewallGroup

	for _, group := range firewallGroupResponse.Data {
		if group.Name == ipv4GroupName {
			ipv4Group = group
		}
		if group.Name == ipv6GroupName {
			ipv6Group = group
		}
	}

	_, err = UnifiLogin(config.Unifi.User, config.Unifi.Password, config.Unifi.Host)
	if err != nil {
		log.Errorf("Could not login to Unifi Controller: %s", err)
		os.Exit(1)
	}

	if ipv4Group.Name != "" {
		ipv4Group.GroupMembers = make([]string, 0)
		for _, ip := range ipv4 {
			ipv4Group.GroupMembers = append(ipv4Group.GroupMembers, ip.String())
		}
		log.Infof("Updating firewall group \"%s\" with %d hosts", ipv4Group.Name, len(ipv4Group.GroupMembers))
		_, err := UnifiUpdateFirewallGroup(config.Unifi.Host, ipv4Group)
		if err != nil {
			log.Errorf("Error updating firewall group: %s", err)
		}
		// respString, _ := json.Marshal(resp)
		// log.Debugf("response: %s", string(respString))
	} else {
		log.Infof("no IPv4 output group found")
	}

	if ipv6Group.Name != "" {
		ipv6Group.GroupMembers = make([]string, 0)
		for _, ip := range ipv6 {
			ipv6Group.GroupMembers = append(ipv6Group.GroupMembers, ip.String())
		}
		log.Infof("Updating firewall group \"%s\" with %d hosts", ipv6Group.Name, len(ipv6Group.GroupMembers))
		_, err := UnifiUpdateFirewallGroup(config.Unifi.Host, ipv6Group)
		if err != nil {
			log.Errorf("Error updating firewall group: %s", err)
		}
	} else {
		log.Infof("no IPv6 output group found")
	}

}

// given a list of URLs, fetches those URLs and dedups the results
// returning one master list of hostnames
func createHostList(lists []string) []string {
	allHosts := make(map[string]bool)
	for _, listUrl := range lists {
		listBody := ""

		if strings.HasPrefix(listUrl, "http") {
			response, err := http.Get(listUrl) //use package "net/http"

			if err != nil {
				log.Errorf("Could not retrieve list at %s: %s\n", listUrl, err)
				break
			}

			defer response.Body.Close()

			resBody, err := ioutil.ReadAll(response.Body)
			if err != nil {
				log.Errorf("Could not read response body for list at %s: %s\n", listUrl, err)
				break
			}
			listBody = string(resBody)
		} else {
			// read the file listUrl into the variable listBody
			fileBody, err := ioutil.ReadFile(listUrl)
			if err != nil {
				log.Errorf("Could not open file %s: %s\n", listUrl, err)
				break
			}
			listBody = string(fileBody)
		}

		hosts := strings.Split(strings.ReplaceAll(string(listBody), "\r\n", "\n"), "\n")
		for _, host := range hosts {
			allHosts[strings.ToLower(host)] = true
		}
		log.Infof("Read %d hosts from %s", len(hosts), listUrl)
	}

	// see https://stackoverflow.com/a/71635953/57626
	hostList := maps.Keys(allHosts)
	log.Infof("Total of %d de-depublicated hosts", len(hostList))
	return hostList
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

	return maps.Values(ipv4Map), maps.Values(ipv6Map)
}

func checkIPv4Address(addr net.IP) bool {
	return addr.String() != "0.0.0.0"
}

func checkIPv6Address(addr net.IP) bool {
	return addr.String() != "::"
}

// lookup a hostname and get all of the IP addreses associated with it
func lookupHost(hostname string) ([]net.IP, []net.IP) {
	var ipv4 []net.IP
	var ipv6 []net.IP

	ips, err := net.LookupIP(hostname)
	if err != nil {
		log.Warnf("Could not resolve %s: %s", hostname, err)
		return ipv4, ipv6
	}
	for _, ip := range ips {
		if ip.To4() != nil {
			log.Debugf("IPv4 %s: %s\n", hostname, ip)
			if checkIPv4Address(ip) {
				ipv4 = append(ipv4, ip)
			}
		} else {
			log.Debugf("IPv6 %s: %s\n", hostname, ip)
			if checkIPv6Address(ip) {
				ipv6 = append(ipv6, ip)
			}
		}
	}
	return ipv4, ipv6
}
