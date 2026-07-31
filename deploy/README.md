# Deploying the backend

Oracle Cloud VM → nginx → deSEC hostname. The frontend stays on GitHub Pages;
this gets the API onto its own origin, which LLD §8.1 requires.

Substitute throughout:

| Placeholder | Example |
| --- | --- |
| `api.example.dedyn.io` | your deSEC hostname |
| `soham874.github.io` | your Pages origin (scheme + host, **no path**) |
| `<VM_IP>` | the reserved public IP of the instance |

---

## 1. Create the VM

Prefer **VM.Standard.A1.Flex** (Ampere ARM, 4 OCPU / 24 GB, Always Free) over the
AMD micro shape. Capacity in popular regions is often exhausted — retry across
availability domains. Everything below works on either; the AMD micro's 1 GB is
what makes the MySQL tuning in step 5 mandatory rather than optional.

Ubuntu 24.04 is assumed. Then:

- **Reserve the public IP.** Networking → Reserved IPs, and attach it to the
  instance's VNIC. An ephemeral IP changes when the instance stops, and your DNS
  record will silently point at someone else's box.
- **Open 80 and 443 in the Security List** for `0.0.0.0/0` (VCN → Security Lists
  → Ingress Rules). Do *not* open 8080 — nothing should reach Tomcat directly.

### The Oracle firewall trap

Oracle's Ubuntu images ship a pre-loaded iptables ruleset with a catch-all REJECT.
Opening the cloud Security List is **not** enough; the instance drops the traffic
itself. This is the single most common reason an Oracle VM appears unreachable.

```bash
sudo iptables -I INPUT 6 -m state --state NEW -p tcp --dport 80 -j ACCEPT
sudo iptables -I INPUT 6 -m state --state NEW -p tcp --dport 443 -j ACCEPT
sudo netfilter-persistent save
```

On Oracle Linux instead: `sudo firewall-cmd --permanent --add-service=http --add-service=https && sudo firewall-cmd --reload`

---

## 2. deSEC hostname

1. Register at [desec.io](https://desec.io) and confirm the email.
2. Create a domain — pick a `dedyn.io` name, e.g. `api.example.dedyn.io`.
3. Add an **A** record for the subname pointing at `<VM_IP>`, TTL 3600.
   Add **AAAA** too if the instance has IPv6.
4. Add a **CAA** record so only Let's Encrypt may issue for the name. This is the
   control DuckDNS could not offer, and it is why the migration was worth doing:

   ```
   0 issue "letsencrypt.org"
   ```

DNSSEC is on automatically — deSEC signs every zone and there is no switch to
forget.

Confirm before continuing, or certbot will fail in a confusing way:

```bash
dig +short api.example.dedyn.io
```

---

## 3. Base packages

```bash
sudo apt update && sudo apt upgrade -y
sudo apt install -y nginx mysql-server certbot python3-certbot-nginx wget gpg
```

Java 25 is newer than Ubuntu's archive. Use Adoptium (ships both x86_64 and
aarch64, so this is identical on Ampere):

```bash
sudo mkdir -p /etc/apt/keyrings
wget -qO - https://packages.adoptium.net/artifactory/api/gpg/key/public \
  | sudo gpg --dearmor -o /etc/apt/keyrings/adoptium.gpg
echo "deb [signed-by=/etc/apt/keyrings/adoptium.gpg] https://packages.adoptium.net/artifactory/deb $(awk -F= '/^VERSION_CODENAME/{print$2}' /etc/os-release) main" \
  | sudo tee /etc/apt/sources.list.d/adoptium.list
sudo apt update && sudo apt install -y temurin-25-jre
java -version   # expect 25.x
```

### Swap (do this on the 1 GB shape)

Oracle micro instances have no swap. A JVM plus MySQL plus nginx in 1 GB will get
something OOM-killed without it.

```bash
sudo fallocate -l 2G /swapfile && sudo chmod 600 /swapfile
sudo mkswap /swapfile && sudo swapon /swapfile
echo '/swapfile none swap sw 0 0' | sudo tee -a /etc/fstab
```

---

## 4. Database

```bash
sudo mysql_secure_installation
sudo mysql
```

```sql
CREATE DATABASE ccshareapp CHARACTER SET utf8mb4 COLLATE utf8mb4_bin;
CREATE USER 'ccshare'@'127.0.0.1' IDENTIFIED BY 'CHOOSE_A_LONG_RANDOM_PASSWORD';
-- Flyway needs DDL rights: it creates flyway_schema_history and V3 drops a column.
GRANT SELECT, INSERT, UPDATE, DELETE, CREATE, ALTER, DROP, INDEX, REFERENCES
  ON ccshareapp.* TO 'ccshare'@'127.0.0.1';
FLUSH PRIVILEGES;
```

Note the collation: the migrations specify `utf8mb4_bin`, which is
case-**sensitive**. Card identifiers are hex and must not collide case-insensitively.

Then apply the memory tuning and restart:

```bash
sudo cp deploy/mysql/ccshareapp.cnf /etc/mysql/mysql.conf.d/99-ccshareapp.cnf
sudo systemctl restart mysql
```

---

## 5. Build and ship the jar

**Build on your laptop, not on the VM.** Maven plus javac wants several hundred
MB; on the 1 GB shape it will thrash or get OOM-killed. The jar is architecture
independent, so an x86 laptop builds fine for an Ampere VM.

```bash
cd ccshareapp && ./mvnw clean package -DskipTests
scp target/ccshareapp-0.0.1-SNAPSHOT.jar ubuntu@<VM_IP>:/tmp/ccshareapp.jar
scp -r deploy ubuntu@<VM_IP>:/tmp/deploy
```

(On an Ampere A1 with 24 GB you can `git clone` and build on the VM instead —
`sudo apt install -y temurin-25-jdk git` and run `./mvnw` there.)

---

## 6. Install the service

```bash
sudo useradd --system --no-create-home --shell /usr/sbin/nologin ccshare
sudo mkdir -p /opt/ccshareapp /var/log/ccshareapp /etc/ccshareapp
sudo mv /tmp/ccshareapp.jar /opt/ccshareapp/ccshareapp.jar
sudo chown -R ccshare:ccshare /opt/ccshareapp /var/log/ccshareapp
```

Secrets go in an environment file, never in the repo:

```bash
sudo tee /etc/ccshareapp/env >/dev/null <<'EOF'
SPRING_PROFILES_ACTIVE=prod
DB_USER=ccshare
DB_PASSWORD=CHOOSE_A_LONG_RANDOM_PASSWORD
CORS_ALLOWED_ORIGIN=https://soham874.github.io
EOF
sudo chmod 600 /etc/ccshareapp/env
sudo chown root:root /etc/ccshareapp/env
```

`CORS_ALLOWED_ORIGIN` is scheme + host **only**. The Pages site lives under
`/credit-card-details-sharer/`, but a path is not part of an origin and adding one
matches nothing.

```bash
sudo cp /tmp/deploy/systemd/ccshareapp.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now ccshareapp
sudo systemctl status ccshareapp
```

Check it came up on loopback only — Flyway should report three migrations applied:

```bash
curl -si -X POST http://127.0.0.1:8080/fetch \
  -H 'Content-Type: application/json' -d '{"card_identifier":"x"}' | head -1
sudo tail -n 40 /var/log/ccshareapp/spring.log
```

A `400` there is success: the service is up and rejecting a malformed identifier.

---

## 7. nginx and TLS

```bash
sudo cp /tmp/deploy/nginx/ccshareapp.conf /etc/nginx/sites-available/ccshareapp
sudo sed -i 's/api\.example\.dedyn\.io/YOUR.NAME.dedyn.io/g' /etc/nginx/sites-available/ccshareapp
sudo ln -sf /etc/nginx/sites-available/ccshareapp /etc/nginx/sites-enabled/
sudo rm -f /etc/nginx/sites-enabled/default
```

The config references certificates that do not exist yet, so get them first with
the standalone-ish nginx plugin, then enable the site:

```bash
sudo certbot --nginx -d api.example.dedyn.io
sudo nginx -t && sudo systemctl reload nginx
```

Certbot installs a renewal timer automatically; confirm with
`systemctl list-timers | grep certbot` and dry-run it once:

```bash
sudo certbot renew --dry-run
```

Renewal uses HTTP-01 through the `/.well-known/acme-challenge/` location in the
port-80 server block — leave that in place.

---

## 8. Point the frontend at it

In the GitHub repo: Settings → Secrets and variables → Actions → Variables, set

```
VITE_API_BASE_URL = https://api.example.dedyn.io
```

Then re-run the **Deploy frontend to GitHub Pages** workflow. This value is baked
into the bundle *and* into the CSP's `connect-src` at build time, so changing the
hostname later always means a rebuild.

---

## 9. Verify end to end

Preflight — the response must name your origin exactly:

```bash
curl -si -X OPTIONS https://api.example.dedyn.io/fetch \
  -H 'Origin: https://soham874.github.io' \
  -H 'Access-Control-Request-Method: POST' \
  -H 'Access-Control-Request-Headers: content-type' | grep -i access-control
```

Docs must be gone:

```bash
curl -so /dev/null -w '%{http_code}\n' https://api.example.dedyn.io/v3/api-docs   # 404
curl -so /dev/null -w '%{http_code}\n' https://api.example.dedyn.io/swagger-ui/   # 404
```

Rate limiting must engage (expect 200/400s then 429s):

```bash
for i in $(seq 1 25); do
  curl -so /dev/null -w '%{http_code} ' -X POST https://api.example.dedyn.io/fetch \
    -H 'Content-Type: application/json' -d '{"card_identifier":"x"}'
done; echo
```

Then create and unlock a card in the browser.

---

## Backups

Client-side encryption means nobody can read the vault for you — it also means
nobody can recover it for you. If the VM dies, the cards are gone.

```bash
sudo tee /usr/local/bin/ccshare-backup >/dev/null <<'EOF'
#!/bin/sh
set -eu
umask 077
mysqldump --defaults-file=/etc/ccshareapp/backup.cnf --single-transaction ccshareapp \
  | gzip > /var/backups/ccshareapp-$(date +%F).sql.gz
find /var/backups -name 'ccshareapp-*.sql.gz' -mtime +30 -delete
EOF
sudo chmod 700 /usr/local/bin/ccshare-backup
```

Put the DB credentials in `/etc/ccshareapp/backup.cnf` (`chmod 600`), run it from
a systemd timer or cron, and copy the dumps off the box. The dump holds ciphertext
and SRP verifiers — not card numbers — but a verifier is offline-guessable, so
treat the backups as secret.

---

## Still outstanding

`CardFetchService.challenges` is an unbounded map that only sheds entries when a
matching `/fetch` prove arrives. Abandoned challenges accumulate forever, and each
holds a 2048-bit SRP session. The nginx rate limit caps how fast that grows but
not that it grows. Against `-Xmx200m` this is a slow remote OOM; `MemoryMax` in
the unit file keeps it from taking the box down with it, and the service restarts,
but the fix is a scheduled sweep of expired entries.
