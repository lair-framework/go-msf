package msf

import "encoding/xml"

// Data contains a msf report.
type Data struct {
	Hosts []Host `xml:"hosts>host"`
}

// Host will be used to contain host data
type Host struct {
	ID                  string    `xml:"id"`
	CreatedAt           string    `xml:"created-at"`
	Address             string    `xml:"address"`
	Mac                 string    `xml:"mac"`
	Comm                string    `xml:"comm"`
	Name                string    `xml:"name"`
	State               string    `xml:"state"`
	OsName              string    `xml:"os-name"`
	OsFlavor            string    `xml:"os-flavor"`
	OsSp                string    `xml:"os-sp"`
	OsLang              string    `xml:"os-lang"`
	Arch                string    `xml:"arch"`
	WorkspaceID         string    `xml:"workspace-id"`
	UpdatedAt           string    `xml:"updated-at"`
	Purpose             string    `xml:"purpose"`
	Info                string    `xml:"info"`
	Comments            string    `xml:"comments"`
	Scope               string    `xml:"scope"`
	VirtualHost         string    `xml:"virtual-host"`
	NoteCount           string    `xml:"note-count"`
	VulnCount           string    `xml:"vuln-count"`
	ServiceCount        string    `xml:"service-count"`
	HostDetailCount     string    `xml:"host-detail-count"`
	ExploitAttemptCount string    `xml:"exploit-attempt-count"`
	CredCount           string    `xml:"cred-count"`
	NexposeDataAssetID  string    `xml:"nexpose-data-asset-id"`
	HistoryCount        string    `xml:"history-count"`
	DetectedArch        string    `xml:"detected-arch"`
	HostDetails         string    `xml:"host_details"`
	ExploitAttempts     string    `xml:"exploit_attempts"`
	Services            []Service `xml:"services>service"`
	Notes               []Note    `xml:"notes>note"`
	Vulns               []Vuln    `xml:"vulns>vuln"`
}

// Service will be used to contain service data
type Service struct {
	ID        string `xml:"id"`
	HostID    string `xml:"host-id"`
	CreatedAt string `xml:"created-at"`
	Port      string `xml:"port"`
	Proto     string `xml:"proto"`
	State     string `xml:"state"`
	Name      string `xml:"name"`
	UpdatedAt string `xml:"updated-at"`
	Info      string `xml:"info"`
}

// Note will be used to contain note data
type Note struct {
	ID          string `xml:"id"`
	CreatedAt   string `xml:"created-at"`
	Ntype       string `xml:"ntype"`
	WorkspaceID string `xml:"workspace-id"`
	ServiceID   string `xml:"service-id"`
	HostID      string `xml:"host-id"`
	UpdatedAt   string `xml:"updated-at"`
	Critical    string `xml:"critical"`
	Seen        string `xml:"seen"`
	Data        string `xml:"data"`
	VulnID      string `xml:"vuln-id"`
}

// Vuln will be used to contain vuln data
type Vuln struct {
	ID                   string `xml:"id"`
	HostID               string `xml:"host-id"`
	ServiceID            string `xml:"service-id"`
	CreatedAt            string `xml:"created-at"`
	Name                 string `xml:"name"`
	UpdatedAt            string `xml:"updated-at"`
	Info                 string `xml:"info"`
	ExploitedAt          string `xml:"exploited-at"`
	VulnDetailCount      string `xml:"vuln-detail-count"`
	VulnAttemptCount     string `xml:"vuln-attempt-count"`
	NexposeDataVulnDefID string `xml:"nexpose-data-vuln-def-id"`
	OriginID             string `xml:"origin-id"`
	OriginType           string `xml:"origin-type"`
	Notes                []Note `xml:"notes"`
	Refs                 []Ref  `xml:"refs"`
	VulnDetails          string `xml:"vuln_details"`
	VulnAttempts         string `xml:"vuln_attempts"`
}

// Ref will be used to contain ref data
type Ref struct {
	Ref string `xml:"ref"`
}

// Parse takes a byte array of msf xml data and unmarshals it into an
// MsfData struct. All elements are returned as strings, it is up to the caller
// to check and cast them to the proper type.
func Parse(content []byte) (*Data, error) {
	r := &Data{}
	err := xml.Unmarshal(content, r)
	if err != nil {
		return r, err
	}
	return r, nil
}
