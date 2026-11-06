package main

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"sort"

	log "github.com/sirupsen/logrus"
)

type UnifiLoginRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
	Remember bool   `json:"remember"`
}

type UnifiLoginResponse struct {
	UniqueId           string                 `json:"unique_id"`
	FirstName          string                 `json:"first_name"`
	LastName           string                 `json:"last_name"`
	FullName           string                 `json:"full_name"`
	Email              string                 `json:"email"`
	EmailStatus        string                 `json:"email_status"`
	EmailIsNull        bool                   `json:"email_is_null"`
	Phone              string                 `json:"phone"`
	AvatarRelativePath string                 `json:"avatar_relative_path"`
	AvatarRpath2       string                 `json:"avatar_rpath2"`
	Status             string                 `json:"status"`
	EmployeeNumber     string                 `json:"employee_number"`
	CreateTime         int                    `json:"create_time"`
	Extras             map[string]interface{} `json:"extras"`
	LoginTime          int                    `json:"login_time"`
	Username           string                 `json:"username"`
	LocalAccountExist  bool                   `json:"local_account_exist"`
	PasswordRevision   int                    `json:"password_revision"`
	SsoAccount         string                 `json:"sso_account"`
	SsoUuid            string                 `json:"sso_uuid"`
	SsoUsername        string                 `json:"sso_username"`
	SsoPicture         string                 `json:"sso_picture"`
	UidSsoId           string                 `json:"uid_sso_id"`
	UidSsoAccount      string                 `json:"uid_sso_account"`
	Groups             []struct {
		UniqueId   string        `json:"unique_id"`
		Name       string        `json:"name"`
		UpId       string        `json:"up_id"`
		UpIds      []interface{} `json:"up_ids"`
		SystemName string        `json:"system_name"`
		CreateTime string        `json:"create_time"`
	} `json:"groups"`
	Roles []struct {
		UniqueId   string        `json:"unique_id"`
		Name       string        `json:"name"`
		SystemRole bool          `json:"system_role"`
		SystemKey  string        `json:"system_key"`
		Level      int           `json:"level"`
		CreateTime string        `json:"create_time"`
		UpId       string        `json:"up_id"`
		UpIds      []interface{} `json:"up_ids"`
	} `json:"roles"`
	Permissions        map[string][]string    `json:"permissions"`
	Scopes             []string               `json:"scopes"`
	CloudAccessGranted bool                   `json:"cloud_access_granted"`
	UpdateTime         int                    `json:"update_time"`
	Avatar             interface{}            `json:"avatar"`
	NfcToken           string                 `json:"nfc_token"`
	NfcDisplayId       string                 `json:"nfc_display_id"`
	NfcCardType        string                 `json:"nfc_card_type"`
	NfcCardStatus      string                 `json:"nfc_card_status"`
	Id                 string                 `json:"id"`
	IsOwner            bool                   `json:"isOwner"`
	IsSuperAdmin       bool                   `json:"isSuperAdmin"`
	IsMember           bool                   `json:"isMember"`
	DeviceToken        string                 `json:"deviceToken"`
	SSOAuth            map[string]interface{} `json:"ssoAuth"`
}

type UnifiFirewallGroup struct {
	ID           string   `json:"_id"`
	Name         string   `json:"name"`
	GroupType    string   `json:"group_type"`
	GroupMembers []string `json:"group_members"`
	SiteID       string   `json:"site_id"`
}

type UnifiFirewallGroupResponse struct {
	Meta struct {
		Rc string `json:"rc"`
	} `json:"meta"`
	Data []UnifiFirewallGroup `json:"data"`
}

type UnifiSitesResponse struct {
	Meta struct {
		Rc string `json:"rc"`
	} `json:"meta"`
	Data []struct {
		ID           string `json:"_id"`
		Name         string `json:"name"`
		Desc         string `json:"desc"`
		AttrHiddenID string `json:"attr_hidden_id"`
		AttrNoDelete bool   `json:"attr_no_delete"`
		AnonymousID  string `json:"anonymous_id"`
		Role         string `json:"role"`
		RoleHotspot  bool   `json:"role_hotspot"`
	} `json:"data"`
}

var CSRFToken string
var CookieToken string
var UnifiHTTPClient *http.Client

const UnifiSite = "default"

// maxResponseBytes caps how much of a controller response is read into memory
const maxResponseBytes = 10 << 20

// InitUnifiClient initializes the global UniFi HTTP client with TLS settings
func InitUnifiClient(insecure bool) {
	UnifiHTTPClient = createUnifiHTTPClient(insecure)
}

// createUnifiHTTPClient creates an HTTP client with optional insecure TLS.
// Redirects are refused: the API never needs them, and following one could
// send the login body or CSRF token to another host.
func createUnifiHTTPClient(insecure bool) *http.Client {
	client := &http.Client{
		Timeout: httpTimeout,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	if insecure {
		tr := http.DefaultTransport.(*http.Transport).Clone()
		tr.TLSClientConfig = &tls.Config{InsecureSkipVerify: true, MinVersion: tls.VersionTLS12}
		client.Transport = tr
	}
	return client
}

// unifiDo sends a request, rejects non-2xx responses, decodes the JSON body
// into out, and records any refreshed session tokens.
func unifiDo(req *http.Request, out any) error {
	resp, err := UnifiHTTPClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return fmt.Errorf("%s %s: unexpected status %s", req.Method, req.URL.Path, resp.Status)
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, maxResponseBytes))
	if err != nil {
		return err
	}
	if err := json.Unmarshal(body, out); err != nil {
		return err
	}

	extractCSRFToken(resp)
	return nil
}

func UnifiLogin(username string, password string, url string) (UnifiLoginResponse, error) {
	var loginResponse UnifiLoginResponse
	var loginRequest UnifiLoginRequest

	loginRequest.Username = username
	loginRequest.Password = password
	loginRequest.Remember = false

	body, _ := json.Marshal(loginRequest)
	targetUrl := fmt.Sprintf("%s/api/auth/login", url)

	req, err := http.NewRequest("POST", targetUrl, bytes.NewBuffer(body))
	if err != nil {
		log.Errorf("Error creating request: %v", err)
		return loginResponse, err
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	req.Header.Set("X-Requested-With", "XMLHttpRequest")

	if err := unifiDo(req, &loginResponse); err != nil {
		return loginResponse, err
	}
	if CookieToken == "" {
		return loginResponse, errors.New("login response did not include a session token")
	}

	return loginResponse, nil
}

func UnifiGetSites(url string) (UnifiSitesResponse, error) {
	var sitesResponse UnifiSitesResponse

	req, err := http.NewRequest("GET", fmt.Sprintf("%s/proxy/network/api/self/sites", url), nil)
	if err != nil {
		log.Errorf("Error creating request: %v", err)
		return sitesResponse, err
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	req.Header.Set("X-Requested-With", "XMLHttpRequest")
	req.Header.Set("X-CSRF-Token", CSRFToken)
	req.Header.Set("Cookie", "TOKEN="+CookieToken)

	err = unifiDo(req, &sitesResponse)
	return sitesResponse, err
}

func extractCSRFToken(resp *http.Response) (string, string) {
	token := resp.Header.Get("X-CSRF-Token")
	if token != "" {
		CSRFToken = token
	}

	for _, cookie := range resp.Cookies() {
		if cookie.Name == "TOKEN" {
			CookieToken = cookie.Value
			return CSRFToken, CookieToken
		}
	}

	log.Warn("No TOKEN cookie found in response")
	return CSRFToken, ""
}

func UnifiGetFirewallGroups(url string) (UnifiFirewallGroupResponse, error) {
	var firewallGroupResponse UnifiFirewallGroupResponse

	req, err := http.NewRequest("GET", fmt.Sprintf("%s/proxy/network/api/s/%s/rest/firewallgroup", url, UnifiSite), nil)
	if err != nil {
		log.Errorf("Error creating request: %v", err)
		return firewallGroupResponse, err
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	req.Header.Set("X-Requested-With", "XMLHttpRequest")
	req.Header.Set("X-CSRF-Token", CSRFToken)
	req.Header.Set("Cookie", "TOKEN="+CookieToken)

	err = unifiDo(req, &firewallGroupResponse)
	return firewallGroupResponse, err
}

func UnifiCreateFirewallGroup(url string, firewallGroup UnifiFirewallGroup) (UnifiFirewallGroupResponse, error) {
	var firewallGroupResponse UnifiFirewallGroupResponse

	body, _ := json.Marshal(firewallGroup)

	req, err := http.NewRequest("POST", fmt.Sprintf("%s/proxy/network/api/s/%s/rest/firewallgroup", url, UnifiSite), bytes.NewBuffer(body))
	if err != nil {
		log.Errorf("Error creating request: %v", err)
		return firewallGroupResponse, err
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	req.Header.Set("X-Requested-With", "XMLHttpRequest")
	req.Header.Set("X-CSRF-Token", CSRFToken)
	req.Header.Set("Cookie", "TOKEN="+CookieToken)

	err = unifiDo(req, &firewallGroupResponse)
	return firewallGroupResponse, err
}

func UnifiUpdateFirewallGroup(url string, firewallGroup UnifiFirewallGroup) (UnifiFirewallGroupResponse, error) {
	var firewallGroupResponse UnifiFirewallGroupResponse

	// Sort IP addresses in numerical ascending order
	sort.Slice(firewallGroup.GroupMembers, func(i, j int) bool {
		ip1 := net.ParseIP(firewallGroup.GroupMembers[i])
		ip2 := net.ParseIP(firewallGroup.GroupMembers[j])
		return bytes.Compare(ip1, ip2) < 0
	})

	body, _ := json.Marshal(firewallGroup)

	req, err := http.NewRequest("PUT", fmt.Sprintf("%s/proxy/network/api/s/%s/rest/firewallgroup/%s", url, UnifiSite, firewallGroup.ID), bytes.NewBuffer(body))
	if err != nil {
		log.Errorf("Error creating request: %v", err)
		return firewallGroupResponse, err
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	req.Header.Set("X-Requested-With", "XMLHttpRequest")
	req.Header.Set("X-CSRF-Token", CSRFToken)
	req.Header.Set("Cookie", "TOKEN="+CookieToken)

	err = unifiDo(req, &firewallGroupResponse)
	return firewallGroupResponse, err
}
