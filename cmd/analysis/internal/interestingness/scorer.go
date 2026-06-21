package interestingness

import (
	"path/filepath"
	"strings"
)

type NearMiss struct {
	Pattern string
	Event   EventLike
}

type EventLike interface {
	GetEventType() string
	GetCommandLine() string
	GetImagePath() string
	GetRemoteAddr() string
	GetRemotePort() uint16
	GetFilePath() string
	GetProcessID() uint32
	GetParentGUID() string
}

type BatchInfo struct {
	Events     []EventLike
	NearMisses []NearMiss
	HostName   string
}

type Scorer struct {
	miningPorts    map[uint16]bool
	suspiciousDirs []string
}

func New() *Scorer {
	return &Scorer{
		miningPorts: map[uint16]bool{
			3333:  true, // XMRig default
			4444:  true, // common reverse shell
			5555:  true,
			6666:  true,
			7777:  true,
			8332:  true, // Bitcoin
			8333:  true, // Bitcoin
			9332:  true, // Bitcoin testnet
			14444: true,
			45560: true, // Ethereum
		},
		suspiciousDirs: []string{"/tmp", "/var/tmp", "/dev/shm", "/dev/shm"},
	}
}

func (s *Scorer) Score(batch BatchInfo, knownBinaries map[string]bool) float64 {
	var score float64
	n := len(batch.Events)
	if n == 0 {
		return 0.0
	}

	hasTempDirExec := false
	hasUnknownBinary := false
	hasMiningPort := false
	nearMissCount := len(batch.NearMisses)
	networkEventCount := 0
	execEventCount := 0
	uniquePorts := make(map[uint16]bool)
	hasDownloadEvent := false
	hasNetworkTool := false

	for _, ev := range batch.Events {
		cmd := ev.GetCommandLine()
		img := ev.GetImagePath()
		etype := ev.GetEventType()

		if etype == "execve" || etype == "execveat" {
			execEventCount++
		}
		if etype == "connect" {
			networkEventCount++
			port := ev.GetRemotePort()
			uniquePorts[port] = true
			if s.miningPorts[port] {
				hasMiningPort = true
			}
		}

		imgLower := strings.ToLower(img)
		cmdLower := strings.ToLower(cmd)

		dir := filepath.Dir(imgLower)
		for _, sd := range s.suspiciousDirs {
			if strings.HasPrefix(dir, sd) {
				hasTempDirExec = true
			}
		}

		binaryName := filepath.Base(imgLower)
		if binaryName != "" && !knownBinaries[binaryName] {
			hasUnknownBinary = true
		}

		if strings.Contains(cmdLower, "curl") || strings.Contains(cmdLower, "wget") || strings.Contains(cmdLower, "fetch") {
			hasDownloadEvent = true
		}
		if strings.Contains(imgLower, "nc") || strings.Contains(imgLower, "ncat") ||
			strings.Contains(imgLower, "socat") || strings.Contains(cmdLower, "/dev/tcp") {
			hasNetworkTool = true
		}
	}

	// Cross-event: download followed by network connection
	if execEventCount > 0 && networkEventCount > 0 {
		score += 0.3
	}
	if hasDownloadEvent && networkEventCount > 0 {
		score += 0.2
	}
	if hasNetworkTool && networkEventCount > 0 {
		score += 0.2
	}
	if hasTempDirExec {
		score += 0.3
	}
	if hasMiningPort {
		score += 0.25
	}
	if nearMissCount > 0 {
		ns := float64(nearMissCount) * 0.15
		if ns > 0.45 {
			ns = 0.45
		}
		score += ns
	}
	if hasUnknownBinary && execEventCount > 0 {
		score += 0.15
	} else if hasUnknownBinary && networkEventCount > 0 {
		score += 0.1
	}
	if len(uniquePorts) >= 3 {
		score += 0.15
	}

	allBenign := true
	for _, ev := range batch.Events {
		if ev.GetEventType() != "execve" && ev.GetEventType() != "open" && ev.GetEventType() != "openat" {
			allBenign = false
			break
		}
		img := strings.ToLower(filepath.Base(ev.GetImagePath()))
		if !knownBinaries[img] {
			allBenign = false
			break
		}
	}
	if allBenign && nearMissCount == 0 && !hasTempDirExec {
		score -= 0.5
	}

	if score < 0 {
		score = 0
	}
	if score > 1.0 {
		score = 1.0
	}

	return score
}

func DefaultKnownBinaries() map[string]bool {
	return map[string]bool{
		"ls": true, "cat": true, "grep": true, "find": true,
		"git": true, "apt": true, "dpkg": true, "make": true,
		"gcc": true, "go": true, "python3": true, "node": true,
		"npm": true, "docker": true, "vim": true, "nano": true,
		"systemctl": true, "journalctl": true, "cp": true,
		"mv": true, "rm": true, "chmod": true, "chown": true,
		"tar": true, "curl": true, "wget": true, "ssh": true,
		"scp": true, "rsync": true, "ps": true, "top": true,
		"htop": true, "df": true, "du": true, "free": true,
		"uptime": true, "whoami": true, "id": true, "hostname": true,
		"uname": true, "date": true, "echo": true, "sed": true,
		"awk": true, "sort": true, "uniq": true, "wc": true,
		"head": true, "tail": true, "tee": true, "xargs": true,
		"env": true, "which": true, "less": true, "diff": true,
		"patch": true, "mkdir": true, "ln": true, "mount": true,
		"ping": true, "traceroute": true, "dig": true, "nslookup": true,
		"ip": true, "ss": true, "iptables": true, "openssl": true,
		"ruby": true, "java": true, "mvn": true, "gradle": true,
		"cargo": true, "rustc": true, "perl": true, "php": true,
		"sudo": true, "su": true, "passwd": true, "adduser": true,
		"usermod": true, "groupadd": true, "file": true, "stat": true,
		"basename": true, "dirname": true, "readlink": true,
		"realpath": true, "sleep": true, "timeout": true,
		"nproc": true, "nohup": true, "screen": true, "tmux": true,
	}
}
