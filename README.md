
# Installation de Falco avec Helm

Falco is a Cloud Native Computing Foundation project that provides runtime threat detection. Out of the box, Falco examines syscalls to alert you to any suspicious activity. And, since containers share the same kernel as their host, Falco can monitor not only activity on the host but also activity on all of the containers running on that host. Moreover, Falco pulls data from both Kubernetes and the container runtime to add additional context to its alerts.

## Ajout du repo

```
helm repo add falcosecurity https://falcosecurity.github.io/charts
helm repo update

```
## Création des custom rules

```
touch falco_custom_rules.yaml
```
## Rules
```
customRules:
  falco_custom_rules.yaml: |-
    - macro: legitimate_container_activity
      condition: >
        proc.cmdline contains "ping_liveness_" or
        proc.cmdline contains "ping_readiness_" or
        proc.cmdline contains "/health/ping_" or
        proc.cmdline contains "pg_isready" or
        proc.cmdline contains "/mnt/elastic-internal/scripts/readiness-port-script.sh" or
        proc.cmdline contains "/app/sidecar.py" or
        proc.cmdline contains "nc -z -v -w5" or
        proc.cmdline contains "nginx -c /tmp/nginx" or
        proc.cmdline contains "bash -ec" or
        proc.cmdline contains "ganesha.nfsd"

    - rule: Container Breakout Attempt Detected
      desc: Detect when a container tries to access sensitive host files
      condition: >
        container and evt.type=open and fd.name contains "/etc/passwd" and
        not legitimate_container_activity
      output: "Container Breakout Attempt Detected! (Container ID=%container.id Command=%proc.cmdline File=%fd.name)"
      priority: CRITICAL
      tags: [container, breakout, security]

    - rule: Network tool used in container
      desc: Detect common CLI tools used for upload/download inside a container
      condition: >
        spawned_process and container and
        proc.name in (curl, wget, ftp, nc, ncat, scp, rsync, aria2c, python3, python) and
        not legitimate_container_activity
      output: >
        [NETWORK TOOL] Process used for file transfer in container (tool=%proc.name user=%user.name command=%proc.cmdline container=%container.name image=%container.image.repository)
      priority: WARNING
      tags: [network, download, upload, file_transfer]

    - rule: Python HTTP server started in container
      desc: Detect usage of simple Python HTTP server (often used to exfiltrate or serve files)
      condition: >
        spawned_process and container and
        proc.cmdline contains "http.server" and
        not legitimate_container_activity
      output: >
        [SIMPLE HTTP SERVER] Python HTTP server started in container (command=%proc.cmdline user=%user.name container=%container.name image=%container.image.repository)
      priority: WARNING
      tags: [exfiltration, http, python, file_transfer]

    - rule: Suspicious use of base64 in container
      desc: Detect base64 usage which could indicate data encoding for transfer
      condition: >
        spawned_process and container and
        proc.name = "base64" and
        not legitimate_container_activity
      output: >
        [ENCODING] base64 used in container (command=%proc.cmdline user=%user.name container=%container.name image=%container.image.repository)
      priority: WARNING
      tags: [encoding, base64, file_transfer]

    - rule: File written in tmp directory
      desc: Detect file writes in /tmp which may indicate staging of download/upload
      condition: >
        evt.type in (open, creat, write) and fd.name startswith "/tmp" and
        container and
        not legitimate_container_activity
      output: >
        [TMP FILE] File operation in /tmp directory (file=%fd.name operation=%evt.type user=%user.name command=%proc.cmdline container=%container.name)
      priority: WARNING
      tags: [filesystem, tmp, staging, download]

    - rule: Netcat or similar listener started in container
      desc: Detect netcat or similar command listening for incoming data (potential data exfil point)
      condition: >
        spawned_process and container and
        proc.name in (nc, ncat) and
        proc.cmdline contains "-l" and
        not legitimate_container_activity
      output: >
        [NETCAT LISTENER] Netcat started in listening mode (command=%proc.cmdline container=%container.name)
      priority: WARNING
      tags: [network, listener, netcat, upload, exfiltration]

    - rule: Git clone inside container
      desc: Detect use of git clone which may be used to pull scripts or data
      condition: >
        spawned_process and container and
        proc.cmdline contains "git clone" and
        not legitimate_container_activity
      output: >
        [GIT CLONE] Git clone executed in container (command=%proc.cmdline user=%user.name container=%container.name image=%container.image.repository)
      priority: WARNING
      tags: [code_download, git, version_control]

    - rule: Compression utility used in container
      desc: Detect usage of compression tools (possibly for staging file exfiltration)
      condition: >
        spawned_process and container and
        proc.name in (zip, tar, gzip, bzip2) and
        not legitimate_container_activity
      output: >
        [COMPRESSION] Compression tool used (tool=%proc.name command=%proc.cmdline container=%container.name)
      priority: WARNING
      tags: [compression, exfiltration, file_staging]

    - rule: Suspicious shell command execution
      desc: Detect shell commands passed as string (used to hide or chain commands)
      condition: >
        spawned_process and container and
        proc.name in (sh, bash) and proc.args contains "-c" and
        not legitimate_container_activity
      output: >
        [SUSPICIOUS SHELL] Shell command with -c option executed (cmd=%proc.cmdline user=%user.name container=%container.name)
      priority: WARNING
      tags: [evasion, shell, execution]

    - rule: Suspicious use of eval
      desc: Detect use of eval which can execute arbitrary code dynamically
      condition: >
        spawned_process and container and
        proc.cmdline contains "eval" and
        not legitimate_container_activity
      output: >
        [EVAL USAGE] 'eval' detected in command (cmd=%proc.cmdline user=%user.name container=%container.name)
      priority: WARNING
      tags: [execution, eval, injection]

    - rule: Executable run from /tmp
      desc: Detect execution of any binary/script from /tmp
      condition: >
        spawned_process and container and
        proc.exepath startswith "/tmp" and
        not legitimate_container_activity
      output: >
        [TMP EXEC] Executable launched from /tmp (cmd=%proc.cmdline path=%proc.exepath container=%container.name)
      priority: WARNING
      tags: [tmp, execution, malware, download]

    - rule: Encryption tool used in container
      desc: Detect tools commonly used to encrypt files before exfiltration
      condition: >
        spawned_process and container and
        proc.name in (openssl, gpg) and
        not legitimate_container_activity
      output: >
        [ENCRYPTION] Tool used for file encryption (tool=%proc.name cmd=%proc.cmdline container=%container.name)
      priority: WARNING
      tags: [encryption, exfiltration, staging]

    - rule: Tunneling tool used
      desc: Detect reverse tunneling or proxy tools often used for data exfiltration
      condition: >
        spawned_process and container and
        (proc.cmdline contains "ssh -R" or
         proc.name in (socat, chisel)) and
        not legitimate_container_activity
      output: >
        [TUNNELING] Tunneling or proxy tool detected (tool=%proc.name cmd=%proc.cmdline container=%container.name)
      priority: WARNING
      tags: [network, tunnel, ssh, reverse_proxy]

    - rule: Sensitive file read
      desc: Detect processes that access sensitive system files
      condition: >
        open_read and container and
        fd.name in (/etc/shadow, /etc/passwd, /root/.ssh/id_rsa, /root/.bash_history) and
        not legitimate_container_activity
      output: >
        [SENSITIVE READ] Sensitive file accessed (file=%fd.name cmd=%proc.cmdline container=%container.name)
      priority: WARNING
      tags: [reconnaissance, secrets, file_access]

    - rule: Archive and transfer pattern
      desc: Detect creation of archive + use of transfer tool in short time window (requires correlation)
      condition: >
        spawned_process and container and
        proc.name in (tar, curl, scp) and
        not legitimate_container_activity
      output: >
        [ARCHIVE+TRANSFER] Transfer-related tool executed (tool=%proc.name cmd=%proc.cmdline container=%container.name)
      priority: WARNING
      tags: [archive, transfer, exfiltration]

    - rule: Suspicious DNS activity
      desc: Detect command-line DNS queries which may be used for exfiltration (e.g. via dig)
      condition: >
        spawned_process and container and
        proc.name in (dig, nslookup, host) and
        not legitimate_container_activity
      output: >
        [DNS TUNNEL] DNS query tool used (cmd=%proc.cmdline container=%container.name)
      priority: WARNING
      tags: [dns, exfiltration, network]

    - rule: Ping command used in container
      desc: Detect use of ping command which can indicate network scanning or reconnaissance
      condition: >
        spawned_process and container and proc.name = "ping" and
        not legitimate_container_activity
      output: >
        [PING COMMAND] Ping used in container (cmd=%proc.cmdline user=%user.name container=%container.name)
      priority: WARNING
      tags: [network, reconnaissance]
```

## Création du namespace
```
kubectl create namespace falco
```
## Déploiement avec helm 
```
helm upgrade -n falco falco falcosecurity/falco \
  -f custom_falco_rules.yaml \
  --set falcosidekick.enabled=true \
  --set falcosidekick.webui.enabled=truehelm install falco falcosecurity/falco\
  --namespace falco \
  --set falcosidekick.enabled=true \
  --set falcosidekick.webui.enabled=true \
  --set tty=true \
  --set driver.kind=ebpf \
  --set falcosidekick.config.slack.webhookurl="https://hooks.slack.com/services/xxx" \
  --set falcosidekick.config.slack.minimumpriority="warning"
```
## Test
```
kubectl exec -it <pod> -- ping 8.8.8.8
kubectl exec -it <pod> -- curl http://example.com
kubectl exec -it <pod> -- bash -c "echo 'test'"
kubectl exec -it <pod> -- curl http://example.com
```
## API Reference

#### Get all items

```http
  GET /api/items
```

| Parameter | Type     | Description                |
| :-------- | :------- | :------------------------- |
| `api_key` | `string` | **Required**. Your API key |

#### Get item

```http
  GET /api/items/${id}
```

| Parameter | Type     | Description                       |
| :-------- | :------- | :-------------------------------- |
| `id`      | `string` | **Required**. Id of item to fetch |

#### add(num1, num2)

Takes two numbers and returns the sum.

