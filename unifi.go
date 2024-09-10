package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"

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

const UnifiSite = "default"

func UnifiLogin(username string, password string, url string) (UnifiLoginResponse, error) {
	var loginResponse UnifiLoginResponse
	var loginRequest UnifiLoginRequest

	loginRequest.Username = username
	loginRequest.Password = password
	loginRequest.Remember = true

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

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return loginResponse, err
	}
	defer resp.Body.Close()

	body, _ = io.ReadAll(io.Reader(resp.Body))
	// fmt.Printf("Response: %s", string(body))
	if err := json.Unmarshal(body, &loginResponse); err != nil {
		return loginResponse, err
	}

	extractCSRFToken(resp)

	return loginResponse, nil
}

func UnifiGetSites(url string) (UnifiSitesResponse, error) {
	var sitesResponse UnifiSitesResponse

	req, err := http.NewRequest("GET", fmt.Sprintf("%s/proxy/network/api/self/sites", url, UnifiSite), nil)
	if err != nil {
		log.Errorf("Error creating request: %v", err)
		return sitesResponse, err
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	req.Header.Set("X-Requested-With", "XMLHttpRequest")
	req.Header.Set("X-CSRF-Token", CSRFToken)
	req.Header.Set("Cookie", "TOKEN="+CookieToken)

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return sitesResponse, err
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(io.Reader(resp.Body))

	if err := json.Unmarshal(body, &sitesResponse); err != nil {
		return sitesResponse, err
	}

	extractCSRFToken(resp)

	return sitesResponse, nil
}

func extractCSRFToken(resp *http.Response) (string, string) {
	token := resp.Header.Get("X-CSRF-Token")
	log.Debug("X-CSRF-Token Header: ", token)

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

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return firewallGroupResponse, err
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(io.Reader(resp.Body))

	if err := json.Unmarshal(body, &firewallGroupResponse); err != nil {
		return firewallGroupResponse, err
	}

	extractCSRFToken(resp)

	return firewallGroupResponse, nil
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

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return firewallGroupResponse, err
	}
	defer resp.Body.Close()

	body, _ = io.ReadAll(io.Reader(resp.Body))

	if err := json.Unmarshal(body, &firewallGroupResponse); err != nil {
		return firewallGroupResponse, err
	}

	extractCSRFToken(resp)

	return firewallGroupResponse, nil
}

func UnifiUpdateFirewallGroup(url string, firewallGroup UnifiFirewallGroup) (UnifiFirewallGroupResponse, error) {
	var firewallGroupResponse UnifiFirewallGroupResponse

	body, _ := json.Marshal(firewallGroup)

	// fmt.Printf("body: %s", string(body))
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

	// log.Infof("Request: %s %s", req.Method, req.URL.String())
	// log.Infof("Headers: %v", req.Header)
	// log.Infof("Payload: %s", string(body))
	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return firewallGroupResponse, err
	}
	defer resp.Body.Close()

	body, _ = io.ReadAll(io.Reader(resp.Body))
	log.Debugf("Response: %v", string(body))
	if err := json.Unmarshal(body, &firewallGroupResponse); err != nil {
		return firewallGroupResponse, err
	}

	extractCSRFToken(resp)

	return firewallGroupResponse, nil
}
