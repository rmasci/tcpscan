package types

type ServicePreset struct {
	Name        string
	Description string
	Ports       []string
	SSLCheck    bool
	DNSCheck    bool
	ICMPCheck   bool
}

var ServicePresets = map[string]ServicePreset{
	"web": {
		Name:        "web",
		Description: "Web services (HTTP/HTTPS)",
		Ports:       []string{"80", "443"},
		SSLCheck:    true,
		DNSCheck:    true,
		ICMPCheck:   false,
	},
	"database": {
		Name:        "database",
		Description: "Common database ports",
		Ports:       []string{"3306", "5432", "1433", "27017", "6379"},
		SSLCheck:    false,
		DNSCheck:    true,
		ICMPCheck:   true,
	},
	"ssh": {
		Name:        "ssh",
		Description: "SSH remote access",
		Ports:       []string{"22"},
		SSLCheck:    false,
		DNSCheck:    true,
		ICMPCheck:   true,
	},
	"mail": {
		Name:        "mail",
		Description: "Email services (SMTP/IMAP/POP3)",
		Ports:       []string{"25", "587", "993", "995", "465"},
		SSLCheck:    true,
		DNSCheck:    true,
		ICMPCheck:   false,
	},
	"dns": {
		Name:        "dns",
		Description: "DNS servers",
		Ports:       []string{"53"},
		SSLCheck:    false,
		DNSCheck:    false,
		ICMPCheck:   true,
	},
	"ldap": {
		Name:        "ldap",
		Description: "LDAP/Active Directory",
		Ports:       []string{"389", "636", "3268", "3269"},
		SSLCheck:    true,
		DNSCheck:    true,
		ICMPCheck:   true,
	},
	"rdp": {
		Name:        "rdp",
		Description: "Remote Desktop Protocol",
		Ports:       []string{"3389"},
		SSLCheck:    false,
		DNSCheck:    true,
		ICMPCheck:   true,
	},
	"smb": {
		Name:        "smb",
		Description: "Windows file sharing",
		Ports:       []string{"445", "139"},
		SSLCheck:    false,
		DNSCheck:    true,
		ICMPCheck:   true,
	},
}

func GetServicePreset(name string) (ServicePreset, bool) {
	preset, ok := ServicePresets[name]
	return preset, ok
}

func ListServicePresets() []string {
	presets := make([]string, 0, len(ServicePresets))
	for name := range ServicePresets {
		presets = append(presets, name)
	}
	return presets
}
