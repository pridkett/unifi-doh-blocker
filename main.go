package main

import (
	"bytes"
	"flag"
	"fmt"
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

	hostList := createHostList(config.Input.Lists)
	ipv4, ipv6 := lookupAllHosts(hostList)
	log.Infof("IPv4 Hosts: %d", len(ipv4))
	log.Infof("IPv6 Hosts: %d", len(ipv6))
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
	ipv4 := make([]net.IP, 0)
	ipv6 := make([]net.IP, 0)

	for _, hostname := range hostnames {
		thisIPv4, thisIPv6 := lookupHost(hostname)
		ipv4 = append(ipv4, thisIPv4...)
		ipv6 = append(ipv6, thisIPv6...)
	}
	return ipv4, ipv6
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
			ipv4 = append(ipv4, ip)
		} else {
			log.Debugf("IPv6 %s: %s\n", hostname, ip)
			ipv6 = append(ipv6, ip)
		}
	}
	return ipv4, ipv6
}

// perform a REST request to authorize against the Unifi system
func authorizeRequest(username string, password string, hostname string) {
	body := []byte(fmt.Sprintf(`{"username":"%s","password":"%s", "remember":true}`, username, password))
	resp, err := http.Post(fmt.Sprintf("%s/api/auth/login", hostname), "application/json", bytes.NewBuffer(body))
	if err != nil {
		log.Fatalln(err)
	}
	fmt.Printf("Response: %s", resp)
}
