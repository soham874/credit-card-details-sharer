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
availability domains. Everything below works on either — and with the database
living in a managed HeatWave DB System rather than on the instance, even the
1 GB shape only has to carry a 200 MB heap plus nginx.

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
# mysql-CLIENT, not mysql-server — the database is a managed HeatWave DB System.
sudo apt install -y nginx mysql-client certbot python3-certbot-nginx wget gpg
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

Oracle micro instances have no swap at all. With the database off-box this is no
longer critical, but it is cheap insurance against a JVM heap spike taking the
instance down — skip it on the 24 GB Ampere shape.

```bash
sudo fallocate -l 2G /swapfile && sudo chmod 600 /swapfile
sudo mkswap /swapfile && sudo swapon /swapfile
echo '/swapfile none swap sw 0 0' | sudo tee -a /etc/fstab
```

---

## 4. Database (managed HeatWave DB System)

The database is not on the VM. It is a separate managed instance in the VCN, so
the connection is VM private IP → DB private endpoint, and **nothing here
involves loopback**.

Collect three things first:

```bash
# DB endpoint: OCI console → Databases → DB Systems → your system → "Private IP"
# or, if the OCI CLI is configured:
oci mysql db-system list --compartment-id <OCID> \
  --query 'data[].{name:"display-name",ip:endpoints[0]."ip-address"}' --output table

# The VM's own private address — this decides the grant's host part
hostname -I
```

**Open the path.** The DB System's subnet needs an ingress rule permitting TCP
3306 from the VM's subnet CIDR (VCN → Security Lists, or an NSG on the DB
system). Without it you get a connect timeout rather than an auth error. Verify
before going further:

```bash
nc -vz <DB_PRIVATE_IP> 3306
```

Then create the schema and the application account, as the admin user you chose
when provisioning the DB System:

```bash
# edit the subnet CIDR and password in the file first
mysql -h <DB_PRIVATE_IP> -u <admin> -p --ssl-mode=REQUIRED < /tmp/deploy/mysql/heatwave-setup.sql
```

See [mysql/heatwave-setup.sql](mysql/heatwave-setup.sql). Two details in there
matter:

- **The host part of the account is not cosmetic.** `'ccshare'@'127.0.0.1'` and
  `'ccshare'@'10.0.0.%'` are different accounts. The VM connects from its VCN
  private address, so the grant must cover that — a loopback grant can never
  match and produces "Access denied" for an account that visibly exists.
- The collation is `utf8mb4_bin`, i.e. case-**sensitive**. Card identifiers are
  hex and must not collide case-insensitively.

Confirm the app account works from the VM before starting the service:

```bash
mysql -h <DB_PRIVATE_IP> -u ccshare -p ccshareapp --ssl-mode=REQUIRED -e 'SELECT 1;'
```

### If you followed an earlier version of this guide

A local `mysql-server` may be installed and running, eating ~400MB for nothing —
and it is what answers on 127.0.0.1, which is how you get an "Access denied"
that looks like a credentials problem when the real database was never contacted:

```bash
systemctl is-active mysql && sudo systemctl disable --now mysql && sudo apt purge -y mysql-server
```

---

## 5. Build and ship the jar

**Build on your laptop, not on the VM.** Maven plus javac wants several hundred
MB; on the 1 GB shape it will thrash or get OOM-killed. The jar is architecture
independent, so an x86 laptop builds fine for an Ampere VM.

```bash
cd ccshareapp
./mvnw clean package -DskipTests
scp target/ccshareapp-0.0.1-SNAPSHOT.jar ubuntu@<VM_IP>:/tmp/ccshareapp.jar
# deploy/ is at the repository root, one level up from here
scp -r ../deploy ubuntu@<VM_IP>:/tmp/deploy
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
DB_HOST=10.0.0.123
DB_PORT=3306
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

## Operations

### Service control

```bash
sudo systemctl status ccshareapp        # state, PID, memory against the 450M cap
sudo systemctl restart ccshareapp
sudo systemctl stop ccshareapp
sudo systemctl start ccshareapp
sudo systemctl disable ccshareapp       # stop starting at boot
```

Two things about restarts:

- **Startup takes 60–90 seconds** on this hardware — around 67s of that is Spring
  context initialisation before Tomcat binds. It is not hung. Do not conclude
  anything from a probe until `Started CcshareappApplication` appears.
- **There is no `reload`.** The unit defines no `ExecReload`, so config changes —
  including anything edited in `/etc/ccshareapp/env` — need a full `restart`.
  Changes to `application-prod.yaml` need more than that: it is packaged inside
  the jar, so it needs a rebuild and redeploy.

### Logs live in two places

The logback config writes to **both** the console (captured by journald) and a
rotating file. They carry the same content; the file survives a journal vacuum
and rotates itself (10MB per file, 30 days, 1GB cap — logback handles this, so
there is deliberately no logrotate entry).

```bash
# journald — best for "what happened around this restart"
sudo journalctl -u ccshareapp -f                    # follow
sudo journalctl -u ccshareapp --since "10 min ago"
sudo journalctl -u ccshareapp -p err -b             # errors this boot
sudo journalctl -u ccshareapp | grep -iE 'exception|caused by' | tail -20

# the file appender
sudo tail -f /var/log/ccshareapp/spring.log
sudo ls -la /var/log/ccshareapp/                    # rotated .gz archives
```

The box runs **UTC** (`Etc/UTC`). Timestamps will not match your local clock.

### Changing log verbosity

Levels come from two places and the precedence matters. `logback-spring.xml` is
read first; then Spring Boot applies `logging.level.*` from
`application-prod.yaml` on top, so the yaml wins. Within logback itself an
explicit `<logger>` beats `<root>`, which is why a logger pinned outside the
`<springProfile name="prod">` block stays at its declared level no matter what
root says.

To quieten or raise something, edit `logging.level` in `application-prod.yaml` —
then rebuild and redeploy, because that file is packaged inside the jar.

Never raise `org.hibernate.type.descriptor.sql.BasicBinder` to TRACE here. It
logs every bound parameter, which on this schema means the identifier, the SRP
verifier, the salt and the ciphertext — all written to disk in the clear
(LLD §6.7). The comment above that logger in `logback-spring.xml` says the same.

### The stale-log trap

`Restart=on-failure` means a failing service leaves a trail of old failures that
look current. Reading them cost real time during the initial deployment: the
JDBC errors on screen were from a previous run against a hostname that had
already been corrected.

Always scope to the process that is actually running:

```bash
sudo journalctl -u ccshareapp \
  --since "$(systemctl show ccshareapp -p ExecMainStartTimestamp --value | cut -d' ' -f2-3)"
```

And check whether it is looping rather than serving — `active (running)` for a
few seconds tells you nothing on its own:

```bash
systemctl show ccshareapp -p NRestarts --value       # climbing = crash loop
systemctl show ccshareapp -p ExecMainStartTimestamp --value
```

### Health checks

There is no actuator endpoint (springdoc is disabled and actuator is not a
dependency), so health is the API itself. Behind nginx, substitute your hostname.

```bash
# malformed identifier -> 400, valid UUIDv4 -> 200
curl -so /dev/null -w '%{http_code}\n' -X POST http://127.0.0.1:8080/fetch \
  -H 'Content-Type: application/json' -d '{"card_identifier":"x"}'

curl -so /dev/null -w '%{http_code}\n' -X POST http://127.0.0.1:8080/fetch \
  -H 'Content-Type: application/json' \
  -d "{\"card_identifier\":\"$(python3 -c 'import uuid;print(uuid.uuid4())')\"}"

# database reachability (HeatWave endpoint)
nc -z -w3 10.0.1.161 3306 && echo reachable || echo UNREACHABLE
```

A `403` from the first probe means the ERROR-dispatch rule in
`SecurityConfiguration` has regressed — every error status gets masked as an
empty 403 when that breaks.

### Resources

```bash
systemctl status ccshareapp | grep Memory     # against MemoryMax=450M
free -m; swapon --show
systemd-cgtop -n1
```

Note the VM has a **JRE, not a JDK** — `jcmd`, `jstat`, `jmap` and `jstack` are
not installed. For heap or thread inspection either install `temurin-25-jdk` or
reproduce locally; do not expect to introspect a live JVM here as things stand.

This instance is shared with several other applications, so memory pressure is
not necessarily caused by this service.

### nginx and rate limiting

```bash
sudo nginx -t                                  # validate before reloading
sudo systemctl reload nginx                    # graceful, unlike the app
sudo tail -f /var/log/nginx/access.log
sudo grep 'limiting requests' /var/log/nginx/error.log | tail -20
```

That last one is a security signal, not just noise. The `limit_req` zones are the
only bound on online passkey guessing (see the note at the top of
`nginx/ccshareapp.conf`), so repeated entries against `/fetch` from one address
mean someone is working through guesses.

```bash
sudo certbot certificates                      # expiry dates
systemctl list-timers | grep certbot           # renewal timer is armed
```

### Shipping a new build

```bash
# laptop
cd ccshareapp && ./mvnw clean package
scp target/ccshareapp-0.0.1-SNAPSHOT.jar ubuntu@<VM_IP>:/tmp/ccshareapp.jar

# VM — keep the outgoing jar so a rollback is one command
sudo cp /opt/ccshareapp/ccshareapp.jar /opt/ccshareapp/ccshareapp.jar.prev
sudo install -o ccshare -g ccshare -m 644 /tmp/ccshareapp.jar /opt/ccshareapp/ccshareapp.jar
sudo systemctl restart ccshareapp
```

Rollback: copy `.prev` back over `ccshareapp.jar` and restart.

To confirm which config is actually inside a jar — worth doing when a setting
appears to be ignored, since the yaml is packaged rather than read from disk:

```bash
python3 -c "
import zipfile
z = zipfile.ZipFile('/opt/ccshareapp/ccshareapp.jar')
print(z.read('BOOT-INF/classes/application-prod.yaml').decode())
"
```

### Failures seen so far, and what they meant

| Symptom | Cause |
| --- | --- |
| `Access denied for user 'ccshare'@'localhost'` | Grant host mismatch. MySQL accounts are user **and** host; the VM connects from `10.0.0.x`, so a `127.0.0.1` or `localhost` grant can never match. |
| `Communications link failure` / `Connection refused` | Wrong or missing `DB_HOST`, or the app fell back to loopback. Confirm with `tr '\0' '\n' < /proc/$(systemctl show ccshareapp -p MainPID --value)/environ \| grep DB_`. |
| `ERROR 1819 ... password does not satisfy policy` | `validate_password` wants mixed case, a digit and a special character. |
| Every response is an empty `403` | The `/error` forward is being denied — `dispatcherTypeMatchers(ERROR).permitAll()` missing. |
| Errors that reference a fixed problem | Stale journal entries from an earlier crash-loop run. Scope to `ExecMainStartTimestamp`. |

## Backups

Client-side encryption means nobody can read the vault for you — it also means
nobody can recover it for you.

Using HeatWave rather than a database on the VM genuinely helps here: the DB
System takes automatic backups on a retention policy you set (Databases → your DB
System → Backups), and the data survives the VM being destroyed and rebuilt.
Check the retention window is what you actually want; the default may be shorter
than you would choose for something irreplaceable.

For a copy outside OCI entirely:

```bash
mysqldump -h "$DB_HOST" -u ccshare -p --ssl-mode=REQUIRED \
  --single-transaction ccshareapp | gzip > ccshareapp-$(date +%F).sql.gz
```

The dump holds ciphertext and SRP verifiers — not card numbers — but a verifier
is offline-guessable, so treat these as secret.

---

## Still outstanding

`CardFetchService.challenges` is an unbounded map that only sheds entries when a
matching `/fetch` prove arrives. Abandoned challenges accumulate forever, and each
holds a 2048-bit SRP session. The nginx rate limit caps how fast that grows but
not that it grows. Against `-Xmx200m` this is a slow remote OOM; `MemoryMax` in
the unit file keeps it from taking the box down with it, and the service restarts,
but the fix is a scheduled sweep of expired entries.
