package main

const (
	TacticExecution           = "execution"
	TacticPersistence         = "persistence"
	TacticPrivilegeEscalation = "privilege-escalation"
	TacticDefenseEvasion      = "defense-evasion"
	TacticCredentialAccess    = "credential-access"
	TacticDiscovery           = "discovery"
	TacticLateralMovement     = "lateral-movement"
	TacticCommandAndControl   = "command-and-control"
	TacticCollection          = "collection"
	TacticExfiltration        = "exfiltration"
	TacticImpact              = "impact"
	TacticBenign              = "benign"

	CategoryCommand     = "command"
	CategoryFileAccess  = "file_access"
	CategoryNetwork     = "network"
	CategoryUnknown     = "unknown"
	CategoryBenign      = "benign"
	CategoryOther       = "other"
	CategorySourceRules = "rules"
	CategorySourceLaya  = "laya"

	MaxChoiceOptions = 16
)

type AttackCategory struct {
	Category      string
	Description   string
	TechniqueID   string
	TechniqueName string
	Tactic        string
}

type TacticSpec struct {
	Tactic      string
	Description string
	Options     []string
}

func attackCategory(category, description, techniqueID, techniqueName, tactic string) AttackCategory {
	return AttackCategory{
		Category:      category,
		Description:   description,
		TechniqueID:   techniqueID,
		TechniqueName: techniqueName,
		Tactic:        tactic,
	}
}

var CategoryMITREMap = map[string]AttackCategory{
	"curl_pipe":         attackCategory("curl_pipe", "curl output piped into a shell or interpreter", "T1059.004", "Command and Scripting Interpreter: Unix Shell", TacticExecution),
	"curl_redirect":     attackCategory("curl_redirect", "curl writing a download to a file on disk", "T1105", "Ingress Tool Transfer", TacticCommandAndControl),
	"curl_flag":         attackCategory("curl_flag", "curl invoked with transfer or upload flags", "T1105", "Ingress Tool Transfer", TacticCommandAndControl),
	"curl_silent":       attackCategory("curl_silent", "curl fetching a remote URL in silent mode", "T1105", "Ingress Tool Transfer", TacticCommandAndControl),
	"curl_method":       attackCategory("curl_method", "curl using an unusual HTTP method such as PUT or DELETE", "T1105", "Ingress Tool Transfer", TacticCommandAndControl),
	"curl_data":         attackCategory("curl_data", "curl posting data to a remote endpoint", "T1105", "Ingress Tool Transfer", TacticCommandAndControl),
	"curl_timeout":      attackCategory("curl_timeout", "curl download with an explicit short timeout", "T1105", "Ingress Tool Transfer", TacticCommandAndControl),
	"wget_flag":         attackCategory("wget_flag", "wget invoked with output or spider flags", "T1105", "Ingress Tool Transfer", TacticCommandAndControl),
	"wget_pipe":         attackCategory("wget_pipe", "wget output piped into a shell or interpreter", "T1059.004", "Command and Scripting Interpreter: Unix Shell", TacticExecution),
	"wget_redirect":     attackCategory("wget_redirect", "wget writing a download to a file on disk", "T1105", "Ingress Tool Transfer", TacticCommandAndControl),
	"wget_data":         attackCategory("wget_data", "wget posting data to a remote endpoint", "T1105", "Ingress Tool Transfer", TacticCommandAndControl),
	"wget_insecure":     attackCategory("wget_insecure", "wget download with certificate verification disabled", "T1557", "Adversary-in-the-Middle", TacticCommandAndControl),
	"shell_exec":        attackCategory("shell_exec", "shell invoked with an inline -c command string", "T1059.004", "Command and Scripting Interpreter: Unix Shell", TacticExecution),
	"bash_pipe":         attackCategory("bash_pipe", "command output piped into bash", "T1059.004", "Command and Scripting Interpreter: Unix Shell", TacticExecution),
	"bash_c2":           attackCategory("bash_c2", "bash opening a raw TCP or UDP socket for remote control", "T1059.004", "Command and Scripting Interpreter: Unix Shell", TacticExecution),
	"bash_decode":       attackCategory("bash_decode", "bash decoding a base64 payload inline", "T1027", "Obfuscated Files or Information", TacticDefenseEvasion),
	"bash_curl":         attackCategory("bash_curl", "bash invoking curl to fetch or post content", "T1105", "Ingress Tool Transfer", TacticCommandAndControl),
	"bash_wget":         attackCategory("bash_wget", "bash invoking wget to fetch content", "T1105", "Ingress Tool Transfer", TacticCommandAndControl),
	"interactive_shell": attackCategory("interactive_shell", "interactive shell session such as bash -i", "T1059.004", "Command and Scripting Interpreter: Unix Shell", TacticExecution),
	"netcat":            attackCategory("netcat", "netcat or ncat invoked to move data over a socket", "T1095", "Non-Application Layer Protocol", TacticCommandAndControl),
	"netcat_exec":       attackCategory("netcat_exec", "netcat with command execution such as -e or -p", "T1059.004", "Command and Scripting Interpreter: Unix Shell", TacticExecution),
	"netcat_ip":         attackCategory("netcat_ip", "netcat connecting to or from a remote host", "T1095", "Non-Application Layer Protocol", TacticCommandAndControl),
	"socat":             attackCategory("socat", "socat relaying or bridging a connection", "T1095", "Non-Application Layer Protocol", TacticCommandAndControl),
	"base64_decode":     attackCategory("base64_decode", "base64 payload decoded at runtime", "T1027", "Obfuscated Files or Information", TacticDefenseEvasion),
	"powershell":        attackCategory("powershell", "PowerShell interpreter invocation", "T1059.001", "Command and Scripting Interpreter: PowerShell", TacticExecution),
	"python_socket":     attackCategory("python_socket", "Python opening a raw network socket", "T1095", "Non-Application Layer Protocol", TacticCommandAndControl),
	"python_subprocess": attackCategory("python_subprocess", "Python spawning a child process", "T1059.006", "Command and Scripting Interpreter: Python", TacticExecution),
	"python_pty":        attackCategory("python_pty", "Python allocating a pseudo terminal for a shell", "T1059.006", "Command and Scripting Interpreter: Python", TacticExecution),
	"python_os_exec":    attackCategory("python_os_exec", "Python running a command through os.exec or os.system", "T1059.006", "Command and Scripting Interpreter: Python", TacticExecution),
	"perl_eval":         attackCategory("perl_eval", "Perl evaluating an inline script with -e", "T1059", "Command and Scripting Interpreter", TacticExecution),
	"ruby_eval":         attackCategory("ruby_eval", "Ruby evaluating an inline script with -e", "T1059", "Command and Scripting Interpreter", TacticExecution),
	"php_eval":          attackCategory("php_eval", "PHP evaluating inline code with -r", "T1059", "Command and Scripting Interpreter", TacticExecution),

	"credential_read":      attackCategory("credential_read", "reading a password database such as /etc/shadow", "T1003.008", "OS Credential Dumping: /etc/passwd and /etc/shadow", TacticCredentialAccess),
	"ssh_key":              attackCategory("ssh_key", "reading an SSH private key", "T1552.004", "Unsecured Credentials: Private Keys", TacticCredentialAccess),
	"gpg_key":              attackCategory("gpg_key", "reading a GnuPG keyring or secret key", "T1552.004", "Unsecured Credentials: Private Keys", TacticCredentialAccess),
	"privilege_escalation": attackCategory("privilege_escalation", "modifying /etc/sudoers to change privilege rules", "T1548.003", "Abuse Elevation Control Mechanism: Sudo and Sudo Caching", TacticPrivilegeEscalation),
	"cron_tampering":       attackCategory("cron_tampering", "writing or editing cron schedule files", "T1053.003", "Scheduled Task/Job: Cron", TacticPersistence),
	"ssh_tampering":        attackCategory("ssh_tampering", "modifying the sshd daemon configuration", "T1222", "File and Directory Permissions Modification", TacticPersistence),
	"pam_tampering":        attackCategory("pam_tampering", "modifying PAM authentication modules", "T1556", "Modify Authentication Process", TacticCredentialAccess),
	"selinux_tampering":    attackCategory("selinux_tampering", "modifying SELinux policy or configuration", "T1562.001", "Impair Defenses: Disable or Modify Tools", TacticDefenseEvasion),
	"apparmor_tampering":   attackCategory("apparmor_tampering", "modifying AppArmor profiles or configuration", "T1562.001", "Impair Defenses: Disable or Modify Tools", TacticDefenseEvasion),
	"security_tampering":   attackCategory("security_tampering", "writing into the /etc/security configuration tree", "T1562.001", "Impair Defenses: Disable or Modify Tools", TacticDefenseEvasion),
	"login_tampering":      attackCategory("login_tampering", "modifying login policy such as /etc/login.defs", "T1556", "Modify Authentication Process", TacticCredentialAccess),
	"ssh_authorized_keys":  attackCategory("ssh_authorized_keys", "writing an SSH authorized_keys entry", "T1098.004", "Account Manipulation: SSH Authorized Keys", TacticPersistence),
	"ssh_config":           attackCategory("ssh_config", "modifying SSH client or server configuration", "T1222", "File and Directory Permissions Modification", TacticPersistence),
	"boot_tampering":       attackCategory("boot_tampering", "modifying the bootloader configuration under /boot", "T1542.003", "Boot or Logon Autostart Execution: Boot Script", TacticPersistence),
	"ld_preload":           attackCategory("ld_preload", "adding a library to /etc/ld.so.preload", "T1574.006", "Hijack Execution Flow: Dynamic Linker Hijacking", TacticPersistence),
	"ld_config":            attackCategory("ld_config", "modifying the dynamic linker search configuration", "T1574.006", "Hijack Execution Flow: Dynamic Linker Hijacking", TacticPersistence),
	"env_tampering":        attackCategory("env_tampering", "modifying the system environment file", "T1037", "Boot or Logon Initialization Scripts", TacticPersistence),
	"profile_tampering":    attackCategory("profile_tampering", "modifying a shell profile script", "T1037.004", "Boot or Logon Initialization Scripts: RC Scripts", TacticPersistence),
	"bashrc_tampering":     attackCategory("bashrc_tampering", "modifying a shell rc file such as .bashrc", "T1037.004", "Boot or Logon Initialization Scripts: RC Scripts", TacticPersistence),

	"c2_default":            attackCategory("c2_default", "outbound connection to a port commonly used for command and control", "T1095", "Non-Application Layer Protocol", TacticCommandAndControl),
	"c2_trojan":             attackCategory("c2_trojan", "outbound connection to a known backdoor or trojan control port", "T1095", "Non-Application Layer Protocol", TacticCommandAndControl),
	"proxy":                 attackCategory("proxy", "connection to a local or remote proxy port", "T1090", "Proxy", TacticCommandAndControl),
	"anonymizer":            attackCategory("anonymizer", "connection to an anonymization network such as Tor", "T1090.003", "Proxy: Multi-hop Proxy", TacticCommandAndControl),
	"irc":                   attackCategory("irc", "IRC protocol traffic", "T1071", "Application Layer Protocol", TacticCommandAndControl),
	"write_then_execute":    attackCategory("write_then_execute", "write to a sensitive path followed by execution of a program", "T1204.002", "User Execution: Malicious File", TacticExecution),
	"download_drop_execute": attackCategory("download_drop_execute", "payload downloaded, written to a temp path, then executed", "T1105", "Ingress Tool Transfer", TacticCommandAndControl),
	"exec_then_c2":          attackCategory("exec_then_c2", "process execution followed by a connection to a suspicious port", "T1095", "Non-Application Layer Protocol", TacticCommandAndControl),
	"credential_theft":      attackCategory("credential_theft", "credential file read followed by an outbound network connection", "T1003.008", "OS Credential Dumping: /etc/passwd and /etc/shadow", TacticCredentialAccess),
	"pivot_chain":           attackCategory("pivot_chain", "network tool executed repeatedly alongside new outbound connections", "T1021", "Remote Services", TacticLateralMovement),
	"rapid_spawn":           attackCategory("rapid_spawn", "many process executions inside one correlation window", "T1059", "Command and Scripting Interpreter", TacticExecution),

	CategoryCommand:    attackCategory(CategoryCommand, "process execution with no rule match", "", "", ""),
	CategoryFileAccess: attackCategory(CategoryFileAccess, "file access with no rule match", "", "", ""),
	CategoryNetwork:    attackCategory(CategoryNetwork, "network connection with no rule match", "", "", ""),
	CategoryUnknown:    attackCategory(CategoryUnknown, "event that could not be categorised", "", "", ""),
	CategoryBenign:     attackCategory(CategoryBenign, "routine activity with no attack behaviour", "", "", TacticBenign),

	"script_execution":    attackCategory("script_execution", "a script or interpreted program being run", "T1059", "Command and Scripting Interpreter", TacticExecution),
	"reverse_shell":       attackCategory("reverse_shell", "a shell connected back to a remote host for interactive control", "T1059.004", "Command and Scripting Interpreter: Unix Shell", TacticExecution),
	"temp_execution":      attackCategory("temp_execution", "a program executed from a temp or world-writable directory", "T1204.002", "User Execution: Malicious File", TacticExecution),
	"obfuscated_payload":  attackCategory("obfuscated_payload", "an encoded or obfuscated payload prepared for execution", "T1027", "Obfuscated Files or Information", TacticDefenseEvasion),
	"log_tampering":       attackCategory("log_tampering", "writing to or truncating system log files", "T1070.002", "Indicator Removal: Clear Linux or Mac System Logs", TacticDefenseEvasion),
	"config_tampering":    attackCategory("config_tampering", "writing to a system configuration file", "T1222", "File and Directory Permissions Modification", TacticPersistence),
	"setuid_execution":    attackCategory("setuid_execution", "executing a setuid or setgid binary", "T1548.001", "Abuse Elevation Control Mechanism: Setuid and Setgid", TacticPrivilegeEscalation),
	"su_usage":            attackCategory("su_usage", "privilege change through su or sudo", "T1078.003", "Valid Accounts: Local Accounts", TacticPrivilegeEscalation),
	"discovery_command":   attackCategory("discovery_command", "host or system enumeration commands", "T1082", "System Information Discovery", TacticDiscovery),
	"file_discovery":      attackCategory("file_discovery", "searching the filesystem for files or directories", "T1083", "File and Directory Discovery", TacticDiscovery),
	"network_discovery":   attackCategory("network_discovery", "scanning or enumerating hosts, ports or services", "T1046", "Network Service Discovery", TacticDiscovery),
	"remote_service":      attackCategory("remote_service", "use of a remote access or remote execution service", "T1021", "Remote Services", TacticLateralMovement),
	"pivot_activity":      attackCategory("pivot_activity", "relayed or pivoted access to another host", "T1021", "Remote Services", TacticLateralMovement),
	"suspicious_download": attackCategory("suspicious_download", "a download or transfer of a remote payload", "T1105", "Ingress Tool Transfer", TacticCommandAndControl),
	"suspicious_outbound": attackCategory("suspicious_outbound", "an outbound connection that does not match normal service traffic", "T1071.001", "Application Layer Protocol: Web Protocols", TacticCommandAndControl),
	"data_staging":        attackCategory("data_staging", "collecting data into a staging location before transfer", "T1074", "Data Staged", TacticCollection),
	"archive_creation":    attackCategory("archive_creation", "compressing collected data into an archive", "T1560", "Archive Collected Data", TacticCollection),
	"exfiltration":        attackCategory("exfiltration", "transferring data out to a remote destination", "T1041", "Exfiltration Over C2 Channel", TacticExfiltration),
	"dns_tunneling":       attackCategory("dns_tunneling", "data smuggled out through DNS or another tunnel protocol", "T1572", "Protocol Tunneling", TacticExfiltration),
	"destructive_action":  attackCategory("destructive_action", "deleting, wiping or overwriting data", "T1485", "Data Destruction", TacticImpact),
	"cryptomining":        attackCategory("cryptomining", "a mining workload consuming host resources", "T1496", "Resource Hijacking", TacticImpact),
}

var TacticSpecs = []TacticSpec{
	{
		Tactic:      TacticExecution,
		Description: "running code, shells, scripts or dropped payloads",
		Options: []string{
			"interactive_shell", "reverse_shell", "shell_exec", "bash_pipe",
			"script_execution", "temp_execution", "bash_c2", "powershell",
		},
	},
	{
		Tactic:      TacticPersistence,
		Description: "scheduled jobs, startup files or config that survive a reboot",
		Options: []string{
			"cron_tampering", "ssh_authorized_keys", "config_tampering",
			"ld_preload", "env_tampering", "profile_tampering",
		},
	},
	{
		Tactic:      TacticPrivilegeEscalation,
		Description: "gaining higher privileges or bypassing access control",
		Options: []string{
			"privilege_escalation", "su_usage", "setuid_execution",
		},
	},
	{
		Tactic:      TacticDefenseEvasion,
		Description: "disabling security controls or hiding activity",
		Options: []string{
			"obfuscated_payload", "base64_decode", "selinux_tampering",
			"apparmor_tampering", "log_tampering", "security_tampering",
		},
	},
	{
		Tactic:      TacticCredentialAccess,
		Description: "reading passwords, keys, tokens or authentication config",
		Options: []string{
			"credential_read", "ssh_key", "gpg_key", "pam_tampering",
		},
	},
	{
		Tactic:      TacticDiscovery,
		Description: "enumerating the host, its files or its network",
		Options: []string{
			"discovery_command", "file_discovery", "network_discovery",
		},
	},
	{
		Tactic:      TacticLateralMovement,
		Description: "moving to or acting on other hosts",
		Options: []string{
			"remote_service", "pivot_activity",
		},
	},
	{
		Tactic:      TacticCommandAndControl,
		Description: "outbound control, downloads, proxies and tunnels",
		Options: []string{
			"suspicious_download", "netcat", "socat",
			"suspicious_outbound", "proxy", "anonymizer",
		},
	},
	{
		Tactic:      TacticCollection,
		Description: "gathering data for later exfiltration",
		Options: []string{
			"data_staging", "archive_creation",
		},
	},
	{
		Tactic:      TacticExfiltration,
		Description: "sending data out of the host",
		Options: []string{
			"exfiltration", "dns_tunneling",
		},
	},
	{
		Tactic:      TacticImpact,
		Description: "destroying data or hijacking host resources",
		Options: []string{
			"destructive_action", "cryptomining",
		},
	},
	{
		Tactic:      TacticBenign,
		Description: "routine activity with no attack behaviour",
		Options:     nil,
	},
}

func LookupCategory(category string) (AttackCategory, bool) {
	entry, ok := CategoryMITREMap[category]
	return entry, ok
}

func IsKnownCategory(category string) bool {
	_, ok := CategoryMITREMap[category]
	return ok
}

func LookupTactic(tactic string) (TacticSpec, bool) {
	for _, spec := range TacticSpecs {
		if spec.Tactic == tactic {
			return spec, true
		}
	}
	return TacticSpec{}, false
}

func TacticOptions() map[string]string {
	options := make(map[string]string, len(TacticSpecs))
	for _, spec := range TacticSpecs {
		options[spec.Tactic] = spec.Description
	}
	return options
}

func CategoryOptions(tactic string) map[string]string {
	spec, ok := LookupTactic(tactic)
	if !ok {
		return nil
	}
	options := make(map[string]string, len(spec.Options))
	for _, category := range spec.Options {
		if entry, ok := LookupCategory(category); ok {
			options[category] = entry.Description
		}
	}
	return options
}

func defaultCategoryForEvent(event Event) string {
	switch event.EventType {
	case EventTypeExecve, EventTypeExecveat:
		return CategoryCommand
	case EventTypeOpen, EventTypeOpenat:
		return CategoryFileAccess
	case EventTypeNetwork, EventTypeConnect:
		return CategoryNetwork
	}
	return CategoryUnknown
}

func needsClassification(event Event) bool {
	switch event.Category {
	case "", CategoryCommand, CategoryFileAccess, CategoryNetwork, CategoryUnknown:
		return true
	}
	return false
}

func applyAttackTaxonomy(event *Event, category string, confidence float64, source string) {
	if category == "" {
		category = defaultCategoryForEvent(*event)
	}

	entry, ok := LookupCategory(category)
	if !ok {
		entry, _ = LookupCategory(CategoryUnknown)
		category = CategoryUnknown
	}

	event.Category = category
	event.TechniqueID = entry.TechniqueID
	event.TechniqueName = entry.TechniqueName
	event.Tactic = entry.Tactic
	event.CategorySource = source
	event.CategoryConfidence = confidence
}
