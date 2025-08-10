# Legionnaire IRC Client - Deployment Guide

This guide covers deploying Legionnaire IRC client in various environments, from personal use to enterprise deployments.

## Table of Contents

1. [Deployment Overview](#deployment-overview)
2. [Single User Deployment](#single-user-deployment)
3. [Multi-User Deployment](#multi-user-deployment)
4. [Container Deployment](#container-deployment)
5. [Enterprise Deployment](#enterprise-deployment)
6. [Cloud Deployment](#cloud-deployment)
7. [Security Considerations](#security-considerations)
8. [Monitoring and Logging](#monitoring-and-logging)
9. [Backup and Recovery](#backup-and-recovery)
10. [Performance Tuning](#performance-tuning)

## Deployment Overview

Legionnaire supports several deployment scenarios:

- **Personal Desktop**: Single user with TUI/CLI
- **Bouncer Service**: Persistent IRC connection with multiple clients
- **Multi-User Server**: Shared bouncer for team/organization
- **Container Environment**: Docker/Kubernetes deployment
- **Enterprise Integration**: LDAP, SSO, centralized management

## Single User Deployment

### Desktop Installation

#### Linux (systemd)
```bash
# Install legionnaire
cargo install legionnaire
# or download from releases

# Create user service
mkdir -p ~/.config/systemd/user
cat > ~/.config/systemd/user/legionnaire.service << EOF
[Unit]
Description=Legionnaire IRC Client
After=network.target

[Service]
Type=simple
ExecStart=/usr/local/bin/legionnaire --config %h/.config/legionnaire/config.toml
Restart=always
RestartSec=10
Environment=RUST_LOG=info

[Install]
WantedBy=default.target
EOF

# Enable and start service
systemctl --user enable legionnaire.service
systemctl --user start legionnaire.service
```

#### macOS (launchd)
```bash
# Create launch agent
mkdir -p ~/Library/LaunchAgents
cat > ~/Library/LaunchAgents/com.legionnaire.client.plist << EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>com.legionnaire.client</string>
    <key>ProgramArguments</key>
    <array>
        <string>/usr/local/bin/legionnaire</string>
        <string>--config</string>
        <string>${HOME}/.config/legionnaire/config.toml</string>
    </array>
    <key>RunAtLoad</key>
    <true/>
    <key>KeepAlive</key>
    <true/>
    <key>StandardOutPath</key>
    <string>${HOME}/Library/Logs/legionnaire.log</string>
    <key>StandardErrorPath</key>
    <string>${HOME}/Library/Logs/legionnaire-error.log</string>
</dict>
</plist>
EOF

# Load and start service
launchctl load ~/Library/LaunchAgents/com.legionnaire.client.plist
```

#### Windows (NSSM)
```powershell
# Download and install NSSM (Non-Sucking Service Manager)
# Install legionnaire.exe to C:\Program Files\Legionnaire\

# Install service
nssm install "Legionnaire IRC Client" "C:\Program Files\Legionnaire\legionnaire.exe"
nssm set "Legionnaire IRC Client" Parameters "--config %APPDATA%\legionnaire\config.toml"
nssm set "Legionnaire IRC Client" Start SERVICE_AUTO_START

# Start service
net start "Legionnaire IRC Client"
```

### Configuration for Single User

```toml
# ~/.config/legionnaire/config.toml

[user]
nickname = "my_nick"
username = "my_user"
realname = "My Name"

[[servers]]
name = "libera"
host = "irc.libera.chat"
port = 6697
tls = true
auto_connect = true
auto_reconnect = true
channels = ["#rust", "#programming"]

[logging]
enabled = true
directory = "~/.local/share/legionnaire/logs"
level = "info"

[security]
enable_rate_limiting = false  # Not needed for single user
enable_threat_detection = true

[ui]
theme = "auto"
show_timestamps = true
```

## Multi-User Deployment

### Bouncer Server Setup

Create a dedicated bouncer configuration:

```toml
# /etc/legionnaire/bouncer.toml

[bouncer]
listen_addr = "0.0.0.0"
listen_port = 7777
password = "secure_bouncer_password"
max_clients = 50
history_size = 1000
auto_replay = true

# TLS configuration for bouncer
[bouncer.tls]
enabled = true
cert_file = "/etc/ssl/certs/legionnaire.crt"
key_file = "/etc/ssl/private/legionnaire.key"

# IRC server configuration
[[servers]]
name = "company"
host = "irc.company.com" 
port = 6697
tls = true
channels = ["#general", "#dev-team", "#announcements"]

[servers.sasl]
type = "plain"
username = "bouncer_user"

[logging]
enabled = true
directory = "/var/log/legionnaire"
level = "info"

[security]
enable_rate_limiting = true
rate_limit_messages_per_minute = 120
enable_connection_throttling = true
max_connections_per_ip = 10
```

### System Service (Linux)

```bash
# Create system service
sudo cat > /etc/systemd/system/legionnaire-bouncer.service << EOF
[Unit]
Description=Legionnaire IRC Bouncer
After=network.target
Wants=network.target

[Service]
Type=simple
User=legionnaire
Group=legionnaire
ExecStart=/usr/local/bin/legionnaire --bouncer --config /etc/legionnaire/bouncer.toml
Restart=always
RestartSec=10
PrivateTmp=yes
ProtectSystem=strict
ProtectHome=yes
ReadWritePaths=/var/log/legionnaire /var/lib/legionnaire
NoNewPrivileges=yes
Environment=RUST_LOG=info

[Install]
WantedBy=multi-user.target
EOF

# Create user and directories
sudo useradd -r -s /bin/false legionnaire
sudo mkdir -p /var/log/legionnaire /var/lib/legionnaire
sudo chown legionnaire:legionnaire /var/log/legionnaire /var/lib/legionnaire

# Enable and start service
sudo systemctl enable legionnaire-bouncer.service
sudo systemctl start legionnaire-bouncer.service
```

### User Access Configuration

```toml
# User's client configuration
[bouncer]
host = "bouncer.company.com"
port = 7777
username = "alice"
password = "user_specific_password"
tls = true

[ui]
mode = "bouncer_client"  # Connect to bouncer instead of IRC directly
```

## Container Deployment

### Docker

#### Dockerfile
```dockerfile
FROM rust:1.75-slim as builder

WORKDIR /app
COPY . .
RUN apt-get update && apt-get install -y pkg-config libssl-dev
RUN cargo build --release

FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y ca-certificates libssl3 && rm -rf /var/lib/apt/lists/*

COPY --from=builder /app/target/release/legionnaire /usr/local/bin/
COPY docker/config.toml /app/config.toml

RUN useradd -r -s /bin/false legionnaire
USER legionnaire

EXPOSE 7777
VOLUME ["/app/data", "/app/logs"]

CMD ["legionnaire", "--bouncer", "--config", "/app/config.toml"]
```

#### Docker Compose
```yaml
version: '3.8'

services:
  legionnaire:
    build: .
    container_name: legionnaire-bouncer
    ports:
      - "7777:7777"
    volumes:
      - ./config:/app/config
      - legionnaire_data:/app/data
      - legionnaire_logs:/app/logs
    environment:
      - RUST_LOG=info
      - IRC_NICK=bouncer_nick
      - IRC_SERVER=irc.libera.chat
      - IRC_PORT=6697
    restart: unless-stopped
    security_opt:
      - no-new-privileges:true
    read_only: true
    tmpfs:
      - /tmp
    networks:
      - irc_network

  # Optional: Monitoring
  prometheus:
    image: prom/prometheus:latest
    container_name: legionnaire-prometheus
    ports:
      - "9090:9090"
    volumes:
      - ./monitoring/prometheus.yml:/etc/prometheus/prometheus.yml
    command:
      - --config.file=/etc/prometheus/prometheus.yml
      - --storage.tsdb.path=/prometheus
    networks:
      - irc_network

volumes:
  legionnaire_data:
  legionnaire_logs:

networks:
  irc_network:
    driver: bridge
```

#### Environment-based Configuration
```bash
# docker-compose.override.yml for environment-specific settings
version: '3.8'

services:
  legionnaire:
    environment:
      - IRC_NICK=${IRC_NICK}
      - IRC_SERVER=${IRC_SERVER}
      - IRC_PASSWORD=${IRC_PASSWORD}
      - BOUNCER_PASSWORD=${BOUNCER_PASSWORD}
      - OPENWEATHER_API_KEY=${OPENWEATHER_API_KEY}
```

### Kubernetes

#### Deployment
```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: legionnaire-bouncer
  namespace: irc
spec:
  replicas: 1  # IRC bouncers should typically not be scaled horizontally
  selector:
    matchLabels:
      app: legionnaire-bouncer
  template:
    metadata:
      labels:
        app: legionnaire-bouncer
    spec:
      containers:
      - name: legionnaire
        image: legionnaire:latest
        ports:
        - containerPort: 7777
        env:
        - name: RUST_LOG
          value: "info"
        - name: IRC_NICK
          valueFrom:
            secretKeyRef:
              name: legionnaire-secrets
              key: irc-nick
        - name: IRC_PASSWORD
          valueFrom:
            secretKeyRef:
              name: legionnaire-secrets
              key: irc-password
        volumeMounts:
        - name: config
          mountPath: /app/config
        - name: data
          mountPath: /app/data
        - name: logs
          mountPath: /app/logs
        resources:
          limits:
            memory: "256Mi"
            cpu: "200m"
          requests:
            memory: "128Mi"
            cpu: "100m"
        livenessProbe:
          tcpSocket:
            port: 7777
          initialDelaySeconds: 30
          periodSeconds: 60
        readinessProbe:
          tcpSocket:
            port: 7777
          initialDelaySeconds: 10
          periodSeconds: 30
      volumes:
      - name: config
        configMap:
          name: legionnaire-config
      - name: data
        persistentVolumeClaim:
          claimName: legionnaire-data
      - name: logs
        persistentVolumeClaim:
          claimName: legionnaire-logs
      securityContext:
        runAsNonRoot: true
        runAsUser: 1000
        fsGroup: 1000
```

#### Service and Ingress
```yaml
---
apiVersion: v1
kind: Service
metadata:
  name: legionnaire-service
  namespace: irc
spec:
  selector:
    app: legionnaire-bouncer
  ports:
  - port: 7777
    targetPort: 7777
    protocol: TCP
  type: LoadBalancer

---
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: legionnaire-ingress
  namespace: irc
  annotations:
    nginx.ingress.kubernetes.io/tcp-services-configmap: irc/tcp-services
spec:
  rules:
  - host: irc.example.com
    http:
      paths:
      - path: /
        pathType: Prefix
        backend:
          service:
            name: legionnaire-service
            port:
              number: 7777
```

## Enterprise Deployment

### LDAP Integration

```toml
# Enterprise configuration with LDAP
[auth]
type = "ldap"
server = "ldap://ldap.company.com:389"
base_dn = "ou=users,dc=company,dc=com"
bind_dn = "cn=legionnaire,ou=services,dc=company,dc=com"
bind_password_env = "LDAP_BIND_PASSWORD"

# User mapping
[auth.ldap]
username_attr = "uid"
email_attr = "mail"
realname_attr = "cn"
group_attr = "memberOf"

# Group-based server access
[[auth.ldap.groups]]
dn = "cn=developers,ou=groups,dc=company,dc=com"
servers = ["internal", "github"]
channels = ["#dev-team", "#general"]

[[auth.ldap.groups]]
dn = "cn=managers,ou=groups,dc=company,dc=com" 
servers = ["internal"]
channels = ["#management", "#general"]
```

### SSO Integration (OIDC)

```toml
[auth]
type = "oidc"
provider = "https://auth.company.com"
client_id = "legionnaire-irc-client"
client_secret_env = "OIDC_CLIENT_SECRET"
redirect_uri = "https://irc.company.com/auth/callback"

[auth.oidc]
scopes = ["openid", "profile", "email", "groups"]
username_claim = "preferred_username"
email_claim = "email"
groups_claim = "groups"
```

### Centralized Configuration

```toml
# Central config server
[config]
type = "remote"
url = "https://config.company.com/legionnaire"
auth_token_env = "CONFIG_AUTH_TOKEN"
refresh_interval = 300  # 5 minutes
fallback_config = "/etc/legionnaire/fallback.toml"

# Certificate management
[tls]
ca_cert = "/etc/ssl/certs/company-ca.crt"
client_cert = "/etc/legionnaire/client.crt"
client_key = "/etc/legionnaire/client.key"
verify_hostname = true
```

### Policy Enforcement

```toml
[policy]
# Channel restrictions
allowed_channels = ["#general", "#dev-*", "#project-*"]
blocked_channels = ["#off-topic", "#random"]

# Message filtering
max_message_length = 512
blocked_words = ["confidential", "secret", "password"]
url_whitelist = ["*.company.com", "github.com"]

# Bot restrictions  
allowed_bots = ["github-bot", "weather-bot"]
bot_admin_groups = ["cn=bot-admins,ou=groups,dc=company,dc=com"]

# Logging requirements
audit_all_messages = true
retention_period_days = 90
compliance_export = true
```

## Cloud Deployment

### AWS

#### ECS Task Definition
```json
{
  "family": "legionnaire-bouncer",
  "taskRoleArn": "arn:aws:iam::123456789012:role/LegionnaireTaskRole",
  "executionRoleArn": "arn:aws:iam::123456789012:role/LegionnaireExecutionRole",
  "networkMode": "awsvpc",
  "requiresCompatibilities": ["FARGATE"],
  "cpu": "256",
  "memory": "512",
  "containerDefinitions": [
    {
      "name": "legionnaire",
      "image": "your-account.dkr.ecr.region.amazonaws.com/legionnaire:latest",
      "portMappings": [
        {
          "containerPort": 7777,
          "protocol": "tcp"
        }
      ],
      "environment": [
        {
          "name": "RUST_LOG",
          "value": "info"
        }
      ],
      "secrets": [
        {
          "name": "IRC_PASSWORD",
          "valueFrom": "arn:aws:secretsmanager:region:account:secret:legionnaire/irc-password"
        }
      ],
      "mountPoints": [
        {
          "sourceVolume": "config",
          "containerPath": "/app/config"
        }
      ],
      "logConfiguration": {
        "logDriver": "awslogs",
        "options": {
          "awslogs-group": "/aws/ecs/legionnaire",
          "awslogs-region": "us-west-2",
          "awslogs-stream-prefix": "ecs"
        }
      }
    }
  ],
  "volumes": [
    {
      "name": "config",
      "efsVolumeConfiguration": {
        "fileSystemId": "fs-12345678"
      }
    }
  ]
}
```

#### CloudFormation Template
```yaml
AWSTemplateFormatVersion: '2010-09-09'
Description: 'Legionnaire IRC Bouncer on ECS Fargate'

Resources:
  LegionnaireCluster:
    Type: AWS::ECS::Cluster
    Properties:
      ClusterName: legionnaire-cluster

  LegionnaireService:
    Type: AWS::ECS::Service
    Properties:
      Cluster: !Ref LegionnaireCluster
      TaskDefinition: !Ref LegionnaireTaskDefinition
      DesiredCount: 1
      LaunchType: FARGATE
      NetworkConfiguration:
        AwsvpcConfiguration:
          SecurityGroups:
            - !Ref LegionnaireSecurityGroup
          Subnets:
            - !Ref PrivateSubnet1
            - !Ref PrivateSubnet2

  LoadBalancer:
    Type: AWS::ElasticLoadBalancingV2::LoadBalancer
    Properties:
      Type: network
      Scheme: internet-facing
      Subnets:
        - !Ref PublicSubnet1
        - !Ref PublicSubnet2

  TargetGroup:
    Type: AWS::ElasticLoadBalancingV2::TargetGroup
    Properties:
      Port: 7777
      Protocol: TCP
      TargetType: ip
      VpcId: !Ref VPC
```

### Google Cloud Platform

#### Cloud Run Service
```yaml
apiVersion: serving.knative.dev/v1
kind: Service
metadata:
  name: legionnaire-bouncer
  annotations:
    run.googleapis.com/ingress: all
    run.googleapis.com/execution-environment: gen2
spec:
  template:
    metadata:
      annotations:
        autoscaling.knative.dev/maxScale: "1"  # IRC bouncer shouldn't scale
        run.googleapis.com/cpu-throttling: "false"
    spec:
      containers:
      - image: gcr.io/PROJECT_ID/legionnaire:latest
        ports:
        - containerPort: 7777
        env:
        - name: RUST_LOG
          value: "info"
        - name: IRC_PASSWORD
          valueFrom:
            secretKeyRef:
              name: legionnaire-secrets
              key: irc-password
        resources:
          limits:
            memory: 512Mi
            cpu: 500m
        volumeMounts:
        - name: config
          mountPath: /app/config
      volumes:
      - name: config
        secret:
          secretName: legionnaire-config
```

### Azure

#### Container Instance
```yaml
apiVersion: 2021-03-01
location: eastus
name: legionnaire-bouncer
properties:
  containers:
  - name: legionnaire
    properties:
      image: legionnaire:latest
      ports:
      - port: 7777
        protocol: TCP
      environmentVariables:
      - name: RUST_LOG
        value: info
      - name: IRC_PASSWORD
        secureValue: ${IRC_PASSWORD}
      resources:
        requests:
          memoryInGB: 0.5
          cpu: 0.5
      volumeMounts:
      - name: config
        mountPath: /app/config
  osType: Linux
  restartPolicy: Always
  ipAddress:
    type: Public
    ports:
    - protocol: TCP
      port: 7777
  volumes:
  - name: config
    azureFile:
      shareName: legionnaire-config
      storageAccountName: ${STORAGE_ACCOUNT}
      storageAccountKey: ${STORAGE_KEY}
```

## Security Considerations

### Network Security

```bash
# Firewall configuration (iptables)
# Allow IRC bouncer port
iptables -A INPUT -p tcp --dport 7777 -j ACCEPT

# Allow outbound IRC connections
iptables -A OUTPUT -p tcp --dport 6667 -j ACCEPT
iptables -A OUTPUT -p tcp --dport 6697 -j ACCEPT

# Block other ports
iptables -A INPUT -j DROP
iptables -A OUTPUT -j DROP
```

### TLS Configuration

```toml
[tls]
# Use strong TLS configuration
min_version = "1.3"
cipher_suites = [
    "TLS_AES_256_GCM_SHA384",
    "TLS_CHACHA20_POLY1305_SHA256",
    "TLS_AES_128_GCM_SHA256"
]

# Certificate pinning
pin_certificates = true
allowed_certificates = [
    "sha256:ABCD1234...",  # IRC server certificate fingerprint
    "sha256:EFGH5678..."   # Backup certificate fingerprint
]
```

### Access Control

```toml
[access_control]
# IP-based restrictions
allowed_ips = ["10.0.0.0/8", "192.168.0.0/16"]
blocked_ips = ["192.168.1.100"]

# Rate limiting per user
rate_limit_per_user = 60  # messages per minute
burst_limit = 10

# Connection limits
max_connections_per_user = 3
max_idle_time = 3600  # seconds
```

### Audit Logging

```toml
[audit]
enabled = true
log_file = "/var/log/legionnaire/audit.log"
log_format = "json"
log_level = "info"

# What to log
log_connections = true
log_messages = true
log_commands = true
log_auth_attempts = true
log_errors = true

# Compliance
gdpr_compliant = true
anonymize_ips = true
retention_days = 365
```

## Monitoring and Logging

### Prometheus Metrics

```toml
[monitoring]
enabled = true
prometheus_endpoint = "0.0.0.0:9090"
metrics_interval = 30  # seconds

[monitoring.metrics]
# System metrics
memory_usage = true
cpu_usage = true
connection_count = true

# Application metrics
messages_per_second = true
error_rate = true
plugin_performance = true
```

### Grafana Dashboard

```json
{
  "dashboard": {
    "title": "Legionnaire IRC Client",
    "panels": [
      {
        "title": "Active Connections",
        "type": "graph",
        "targets": [
          {
            "expr": "legionnaire_active_connections"
          }
        ]
      },
      {
        "title": "Message Rate",
        "type": "graph", 
        "targets": [
          {
            "expr": "rate(legionnaire_messages_total[1m])"
          }
        ]
      },
      {
        "title": "Error Rate",
        "type": "graph",
        "targets": [
          {
            "expr": "rate(legionnaire_errors_total[1m])"
          }
        ]
      }
    ]
  }
}
```

### Log Aggregation

#### ELK Stack Configuration
```yaml
# logstash.conf
input {
  file {
    path => "/var/log/legionnaire/*.log"
    type => "legionnaire"
    codec => "json"
  }
}

filter {
  if [type] == "legionnaire" {
    date {
      match => [ "timestamp", "ISO8601" ]
    }
    
    if [level] == "ERROR" {
      mutate {
        add_tag => ["alert"]
      }
    }
  }
}

output {
  elasticsearch {
    hosts => ["elasticsearch:9200"]
    index => "legionnaire-%{+YYYY.MM.dd}"
  }
}
```

## Backup and Recovery

### Configuration Backup

```bash
#!/bin/bash
# backup-legionnaire.sh

BACKUP_DIR="/backup/legionnaire/$(date +%Y%m%d)"
mkdir -p "$BACKUP_DIR"

# Backup configuration
cp -r /etc/legionnaire "$BACKUP_DIR/config"

# Backup data directory
cp -r /var/lib/legionnaire "$BACKUP_DIR/data"

# Backup logs (last 7 days)
find /var/log/legionnaire -name "*.log" -mtime -7 -exec cp {} "$BACKUP_DIR/logs/" \;

# Create encrypted archive
tar czf "$BACKUP_DIR.tar.gz" "$BACKUP_DIR"
gpg --cipher-algo AES256 --compress-algo 1 --symmetric --output "$BACKUP_DIR.tar.gz.gpg" "$BACKUP_DIR.tar.gz"

# Clean up
rm -rf "$BACKUP_DIR" "$BACKUP_DIR.tar.gz"

# Upload to cloud storage (optional)
aws s3 cp "$BACKUP_DIR.tar.gz.gpg" "s3://my-backup-bucket/legionnaire/"
```

### Disaster Recovery

```bash
#!/bin/bash
# restore-legionnaire.sh

BACKUP_FILE="$1"
RESTORE_DIR="/tmp/legionnaire-restore"

# Decrypt and extract backup
gpg --decrypt "$BACKUP_FILE" | tar xzf - -C "$RESTORE_DIR"

# Stop services
systemctl stop legionnaire-bouncer

# Restore configuration
cp -r "$RESTORE_DIR/config/"* /etc/legionnaire/

# Restore data
cp -r "$RESTORE_DIR/data/"* /var/lib/legionnaire/

# Fix permissions
chown -R legionnaire:legionnaire /var/lib/legionnaire
chmod 600 /etc/legionnaire/config.toml

# Start services
systemctl start legionnaire-bouncer

# Verify
systemctl status legionnaire-bouncer
```

## Performance Tuning

### System Optimization

```bash
# Increase file descriptor limits
echo "legionnaire soft nofile 65536" >> /etc/security/limits.conf
echo "legionnaire hard nofile 65536" >> /etc/security/limits.conf

# TCP tuning for IRC
echo "net.core.somaxconn = 65536" >> /etc/sysctl.conf
echo "net.core.netdev_max_backlog = 5000" >> /etc/sysctl.conf
echo "net.ipv4.tcp_max_syn_backlog = 65536" >> /etc/sysctl.conf
sysctl -p
```

### Application Configuration

```toml
[performance]
# Connection pooling
max_connections = 1000
connection_timeout = 30
keep_alive_interval = 60

# Message processing
message_buffer_size = 10000
message_batch_size = 100
processing_threads = 4

# Memory management
gc_interval = 300
max_memory_usage = "512MB"
```

### Load Testing

```bash
# Simple load test script
#!/bin/bash

BOUNCER_HOST="localhost"
BOUNCER_PORT="7777"
CONCURRENT_CLIENTS=100

for i in $(seq 1 $CONCURRENT_CLIENTS); do
  {
    echo "Connecting client $i"
    telnet $BOUNCER_HOST $BOUNCER_PORT << EOF
PASS bouncer_password
NICK testuser$i
USER test$i test$i test$i :Test User $i
JOIN #test
PRIVMSG #test :Test message from client $i
QUIT :Load test complete
EOF
  } &
done

wait
echo "Load test completed"
```

---

This deployment guide provides comprehensive coverage for deploying Legionnaire in various environments. Choose the deployment method that best fits your infrastructure and requirements.

For additional help, consult the [GitHub repository](https://github.com/exec/legionnaire) or join #legionnaire on Libera Chat.