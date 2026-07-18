package main

import (
	"regexp"
)

type CommandRule struct {
	Pattern    *regexp.Regexp
	Category   string
	Score      float32
	ActionType ActionType
}

type FileRule struct {
	Pattern    *regexp.Regexp
	Category   string
	Score      float32
	ActionType ActionType
	IsWrite    bool
}

type NetworkRule struct {
	Port       uint16
	Reason     string
	Category   string
	Score      float32
	ActionType ActionType
}

type ProcessAllowlist struct {
	Parent string
	Child  string
	Reason string
}

type DetectionRules struct {
	CommandRules    []CommandRule
	FileRules       []FileRule
	NetworkRules    []NetworkRule
	SensitiveFiles  []string
	ServerProcesses map[string]bool
	ShellImages     map[string]bool
	Allowlists      []ProcessAllowlist
}

var DefaultRules = DetectionRules{
	CommandRules: []CommandRule{
		{Pattern: regexp.MustCompile(`curl\s+[^\s]+\s*\|`), Category: "curl_pipe", Score: 0.8, ActionType: ActionKillPID},
		{Pattern: regexp.MustCompile(`curl\s+[^\s]+\s*>\s*/`), Category: "curl_redirect", Score: 0.8, ActionType: ActionKillPID},
		{Pattern: regexp.MustCompile(`curl\s+-[dTk]`), Category: "curl_flag", Score: 0.7, ActionType: ActionKillPID},
		{Pattern: regexp.MustCompile(`curl\s+-[A-Z]-[dTk]`), Category: "curl_flag", Score: 0.7, ActionType: ActionKillPID},
		{Pattern: regexp.MustCompile(`curl\s+-[sS].*http://[^\s]+`), Category: "curl_silent", Score: 0.8, ActionType: ActionKillPID},
		{Pattern: regexp.MustCompile(`curl\s+-X\s+(DELETE|PUT|PATCH)`), Category: "curl_method", Score: 0.7, ActionType: ActionKillPID},
		{Pattern: regexp.MustCompile(`curl\s+--post-data`), Category: "curl_data", Score: 0.8, ActionType: ActionKillPID},
		{Pattern: regexp.MustCompile(`curl\s+--connect-timeout\s+\d+\s+http://`), Category: "curl_timeout", Score: 0.7, ActionType: ActionKillPID},

		{Pattern: regexp.MustCompile(`wget\s+-[OQA]`), Category: "wget_flag", Score: 0.7, ActionType: ActionKillPID},
		{Pattern: regexp.MustCompile(`wget\s+[^\s]+\s+-[OQA]`), Category: "wget_flag", Score: 0.7, ActionType: ActionKillPID},
		{Pattern: regexp.MustCompile(`wget\s+[^\s]+\s*\|`), Category: "wget_pipe", Score: 0.8, ActionType: ActionKillPID},
		{Pattern: regexp.MustCompile(`wget\s+[^\s]+\s*>\s*/`), Category: "wget_redirect", Score: 0.8, ActionType: ActionKillPID},
		{Pattern: regexp.MustCompile(`wget\s+--post-data`), Category: "wget_data", Score: 0.8, ActionType: ActionKillPID},
		{Pattern: regexp.MustCompile(`wget\s+--no-check-certificate`), Category: "wget_insecure", Score: 0.6, ActionType: ActionKillPID},

		{Pattern: regexp.MustCompile(`/bin/(ba)?sh\s+-c`), Category: "shell_exec", Score: 0.7, ActionType: ActionKillPID},
		{Pattern: regexp.MustCompile(`bash\s+-c\s+\|`), Category: "bash_pipe", Score: 0.9, ActionType: ActionKillPID},
		{Pattern: regexp.MustCompile(`bash\s+-c\s+.*\|`), Category: "bash_pipe", Score: 0.9, ActionType: ActionKillPID},
		{Pattern: regexp.MustCompile(`bash\s+-c\s+.*>.*\/dev\/tcp`), Category: "bash_c2", Score: 0.95, ActionType: ActionKillPID},
		{Pattern: regexp.MustCompile(`bash\s+-c\s+.*base64`), Category: "bash_decode", Score: 0.9, ActionType: ActionKillPID},
		{Pattern: regexp.MustCompile(`bash\s+-c\s+.*nc\s+-`), Category: "bash_c2", Score: 0.95, ActionType: ActionKillPID},
		{Pattern: regexp.MustCompile(`bash\s+-c\s+.*curl`), Category: "bash_curl", Score: 0.85, ActionType: ActionKillPID},
		{Pattern: regexp.MustCompile(`bash\s+-c\s+.*wget`), Category: "bash_wget", Score: 0.85, ActionType: ActionKillPID},

		{Pattern: regexp.MustCompile(`bash\s+-i`), Category: "interactive_shell", Score: 0.95, ActionType: ActionKillPID},
		{Pattern: regexp.MustCompile(`sh\s+-i`), Category: "interactive_shell", Score: 0.95, ActionType: ActionKillPID},

		{Pattern: regexp.MustCompile(`nc\s+-[lveuzwp]`), Category: "netcat", Score: 0.8, ActionType: ActionKillPID},
		{Pattern: regexp.MustCompile(`nc\s+-[^\s]*\s+.*-[eEpP]`), Category: "netcat_exec", Score: 0.9, ActionType: ActionKillPID},
		{Pattern: regexp.MustCompile(`nc\s+\S+\s+\d+\s+-[eEpP]`), Category: "netcat_exec", Score: 0.9, ActionType: ActionKillPID},
		{Pattern: regexp.MustCompile(`nc\s+[0-9]`), Category: "netcat_ip", Score: 0.7, ActionType: ActionKillPID},
		{Pattern: regexp.MustCompile(`ncat\s+`), Category: "netcat", Score: 0.8, ActionType: ActionKillPID},
		{Pattern: regexp.MustCompile(`netcat\s+`), Category: "netcat", Score: 0.8, ActionType: ActionKillPID},
		{Pattern: regexp.MustCompile(`socat\s+`), Category: "socat", Score: 0.8, ActionType: ActionKillPID},

		{Pattern: regexp.MustCompile(`base64\s+-d`), Category: "base64_decode", Score: 0.7, ActionType: ActionKillPID},
		{Pattern: regexp.MustCompile(`/dev/tcp`), Category: "bash_c2", Score: 0.95, ActionType: ActionKillPID},
		{Pattern: regexp.MustCompile(`/dev/udp`), Category: "bash_c2", Score: 0.95, ActionType: ActionKillPID},

		{Pattern: regexp.MustCompile(`powershell`), Category: "powershell", Score: 0.7, ActionType: ActionKillPID},
		{Pattern: regexp.MustCompile(`python.*socket`), Category: "python_socket", Score: 0.7, ActionType: ActionKillPID},
		{Pattern: regexp.MustCompile(`python.*subprocess`), Category: "python_subprocess", Score: 0.7, ActionType: ActionKillPID},
		{Pattern: regexp.MustCompile(`python.*pty`), Category: "python_pty", Score: 0.7, ActionType: ActionKillPID},
		{Pattern: regexp.MustCompile(`python.*os\.(listdir|system|popen|exec|remove|unlink|rmdir|rename)`), Category: "python_os_exec", Score: 0.7, ActionType: ActionKillPID},
		{Pattern: regexp.MustCompile(`perl\s+-e\s+`), Category: "perl_eval", Score: 0.7, ActionType: ActionKillPID},
		{Pattern: regexp.MustCompile(`ruby\s+-e\s+`), Category: "ruby_eval", Score: 0.7, ActionType: ActionKillPID},
		{Pattern: regexp.MustCompile(`php\s+-r\s+`), Category: "php_eval", Score: 0.7, ActionType: ActionKillPID},
	},

	FileRules: []FileRule{
		{Pattern: regexp.MustCompile(`/etc/shadow`), Category: "credential_read", Score: 0.9, ActionType: ActionKillPID, IsWrite: false},
		{Pattern: regexp.MustCompile(`/etc/passwd`), Category: "credential_read", Score: 0.9, ActionType: ActionKillPID, IsWrite: false},
		{Pattern: regexp.MustCompile(`/etc/sudoers`), Category: "privilege_escalation", Score: 0.9, ActionType: ActionKillPID, IsWrite: true},
		{Pattern: regexp.MustCompile(`/etc/crontab`), Category: "cron_tampering", Score: 0.8, ActionType: ActionKillPID, IsWrite: true},
		{Pattern: regexp.MustCompile(`/etc/cron\.d/`), Category: "cron_tampering", Score: 0.8, ActionType: ActionKillPID, IsWrite: true},
		{Pattern: regexp.MustCompile(`/etc/ssh/sshd_config`), Category: "ssh_tampering", Score: 0.8, ActionType: ActionKillPID, IsWrite: true},
		{Pattern: regexp.MustCompile(`/etc/pam\.d/`), Category: "pam_tampering", Score: 0.9, ActionType: ActionKillPID, IsWrite: true},
		{Pattern: regexp.MustCompile(`/etc/selinux/`), Category: "selinux_tampering", Score: 0.8, ActionType: ActionKillPID, IsWrite: true},
		{Pattern: regexp.MustCompile(`/etc/apparmor/`), Category: "apparmor_tampering", Score: 0.8, ActionType: ActionKillPID, IsWrite: true},
		{Pattern: regexp.MustCompile(`/etc/security/`), Category: "security_tampering", Score: 0.8, ActionType: ActionKillPID, IsWrite: true},
		{Pattern: regexp.MustCompile(`/etc/login\.defs`), Category: "login_tampering", Score: 0.8, ActionType: ActionKillPID, IsWrite: true},
		{Pattern: regexp.MustCompile(`/var/spool/cron/`), Category: "cron_tampering", Score: 0.8, ActionType: ActionKillPID, IsWrite: true},
		{Pattern: regexp.MustCompile(`\.ssh/authorized_keys`), Category: "ssh_authorized_keys", Score: 0.9, ActionType: ActionKillPID, IsWrite: true},
		{Pattern: regexp.MustCompile(`\.ssh/id_rsa`), Category: "ssh_key", Score: 0.9, ActionType: ActionKillPID, IsWrite: false},
		{Pattern: regexp.MustCompile(`\.ssh/config`), Category: "ssh_config", Score: 0.7, ActionType: ActionKillPID, IsWrite: true},
		{Pattern: regexp.MustCompile(`\.gnupg/`), Category: "gpg_key", Score: 0.8, ActionType: ActionKillPID, IsWrite: false},
		{Pattern: regexp.MustCompile(`/boot/grub/`), Category: "boot_tampering", Score: 0.9, ActionType: ActionKillPID, IsWrite: true},
		{Pattern: regexp.MustCompile(`/etc/ld\.so\.preload`), Category: "ld_preload", Score: 0.95, ActionType: ActionKillPID, IsWrite: true},
		{Pattern: regexp.MustCompile(`/etc/ld\.so\.conf`), Category: "ld_config", Score: 0.8, ActionType: ActionKillPID, IsWrite: true},
		{Pattern: regexp.MustCompile(`/etc/environment`), Category: "env_tampering", Score: 0.8, ActionType: ActionKillPID, IsWrite: true},
		{Pattern: regexp.MustCompile(`/etc/profile`), Category: "profile_tampering", Score: 0.7, ActionType: ActionKillPID, IsWrite: true},
		{Pattern: regexp.MustCompile(`/etc/bash\.bashrc`), Category: "bashrc_tampering", Score: 0.7, ActionType: ActionKillPID, IsWrite: true},
	},

	NetworkRules: []NetworkRule{
		{Port: 4444, Reason: "netcat/metasploit default", Category: "c2_default", Score: 0.8, ActionType: ActionBlockIP},
		{Port: 5555, Reason: "android debug / common C2", Category: "c2_default", Score: 0.7, ActionType: ActionBlockIP},
		{Port: 6666, Reason: "irc backdoor / common C2", Category: "c2_default", Score: 0.8, ActionType: ActionBlockIP},
		{Port: 7777, Reason: "common backdoor", Category: "c2_default", Score: 0.7, ActionType: ActionBlockIP},
		{Port: 8888, Reason: "common proxy/C2", Category: "c2_default", Score: 0.6, ActionType: ActionBlockIP},
		{Port: 1234, Reason: "common test/backdoor port", Category: "c2_default", Score: 0.7, ActionType: ActionBlockIP},
		{Port: 31337, Reason: "Back Orifice", Category: "c2_trojan", Score: 0.9, ActionType: ActionBlockIP},
		{Port: 12345, Reason: "netbus trojan", Category: "c2_trojan", Score: 0.9, ActionType: ActionBlockIP},
		{Port: 54321, Reason: "Back Orifice 2000", Category: "c2_trojan", Score: 0.9, ActionType: ActionBlockIP},
		{Port: 9999, Reason: "common C2", Category: "c2_default", Score: 0.7, ActionType: ActionBlockIP},
		{Port: 44344, Reason: "common C2", Category: "c2_default", Score: 0.8, ActionType: ActionBlockIP},
		{Port: 1080, Reason: "SOCKS proxy", Category: "proxy", Score: 0.6, ActionType: ActionBlockIP},
		{Port: 9050, Reason: "Tor SOCKS", Category: "anonymizer", Score: 0.7, ActionType: ActionBlockIP},
		{Port: 6697, Reason: "IRC over SSL", Category: "irc", Score: 0.6, ActionType: ActionBlockIP},
	},

	SensitiveFiles: []string{
		`/etc/shadow`,
		`/etc/passwd`,
		`/etc/sudoers`,
		`/etc/crontab`,
		`/etc/cron\.d/`,
		`/etc/ssh/sshd_config`,
		`/etc/pam\.d/`,
		`/etc/selinux/`,
		`/etc/apparmor/`,
		`/etc/security/`,
		`/etc/login\.defs`,
		`/var/spool/cron/`,
		`/var/log/auth\.log`,
		`/var/log/syslog`,
		`\.ssh/authorized_keys`,
		`\.ssh/id_rsa`,
		`\.ssh/config`,
		`\.gnupg/`,
		`/boot/grub/`,
		`/etc/ld\.so\.preload`,
		`/etc/ld\.so\.conf`,
		`/etc/environment`,
		`/etc/profile`,
		`/etc/bash\.bashrc`,
	},

	ServerProcesses: map[string]bool{
		"nginx":           true,
		"apache2":         true,
		"httpd":           true,
		"sshd":            true,
		"mysqld":          true,
		"postgres":        true,
		"postgresql":      true,
		"redis-server":    true,
		"mongod":          true,
		"php-fpm":         true,
		"java":            true,
		"docker":          true,
		"containerd-shim": true,
		"kubelet":         true,
		"node_exporter":   true,
		"prometheus":      true,
		"elastic-agent":   true,
		"filebeat":        true,
		"logstash":        true,
		"cron":            true,
		"systemd-network": true,
		"dbus-daemon":     true,
	},

	ShellImages: map[string]bool{
		"bash":      true,
		"sh":        true,
		"dash":      true,
		"zsh":       true,
		"ksh":       true,
		"csh":       true,
		"tcsh":      true,
		"fish":      true,
		"/bin/bash": true,
		"/bin/sh":   true,
		"/bin/dash": true,
		"/bin/zsh":  true,
	},

	Allowlists: []ProcessAllowlist{
		{Parent: "sshd", Child: "bash", Reason: "SSH login shell"},
		{Parent: "sshd", Child: "sh", Reason: "SSH login shell"},
		{Parent: "docker", Child: "sh", Reason: "Docker container shell"},
		{Parent: "docker", Child: "bash", Reason: "Docker container shell"},
		{Parent: "containerd-shim", Child: "sh", Reason: "Container runtime shell"},
		{Parent: "containerd-shim", Child: "bash", Reason: "Container runtime shell"},
		{Parent: "cron", Child: "sh", Reason: "Cron job execution"},
		{Parent: "cron", Child: "bash", Reason: "Cron job execution"},
		{Parent: "systemd-network", Child: "sh", Reason: "Network script"},
		{Parent: "systemd-network", Child: "bash", Reason: "Network script"},
	},
}
