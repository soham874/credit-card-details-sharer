# CC Share Application

## Prerequisites

- JDK 25
- Maven 3.9 or newer, or the repository Maven Wrapper
- MySQL Server 8.0 or newer
- Git

Run commands from the `ccshareapp` directory. The application requires JDK 25. Verify the installed runtime:

```bash
java -version
```

## Clone and Enter the Project

```bash
git clone <repository-url>
cd credit-card-details-sharer/ccshareapp
```

## Install MySQL

### macOS

```bash
brew install mysql
brew services start mysql
```

Verify MySQL is listening:

```bash
lsof -nP -iTCP:3306 -sTCP:LISTEN
```

### Windows

1. Download and install MySQL Community Server.
2. Install MySQL Shell or MySQL Client.
3. Set and retain the root password during installation.
4. Start the `MySQL80` service in Windows Services.
5. Verify connectivity in PowerShell:

```powershell
mysql -h 127.0.0.1 -P 3306 -u roomysql -h 127.0.0.1 -P 3306 -u roomysql -h 127.0.0.1 -P 3306 -u roomysq MySQL `bin` directory to the Windows `PATH`, then open a new PowerShell window.

## Create the Database

Create a dedicated database once. Do not use an existing application database because Flyway manages the schema.

### macOS

```bash
mysql -h 127.0.0.1 -P 3306 -u root -e 'CREATE DATABASE ccshareapp CHARACTER SET utf8mb4 COLLATE utf8mb4_bin;'
```

### Windows PowerShell

```powershell
mysql -h 127.0.0.1 -P 3306 -u root -p -e "CREATE DATABASE ccshareapp CHARACTER SET utf8mb4 COLLATE utf8mb4_bin;"
```

## Configure MySQL

Set database credentials in `src/main/resources/application-mysql.yaml`:

```yaml
spring:
  datasource:
    url: jdbc:mysql://127.0.0.1:3306/ccshareapp
    username: root
    password: <your-mysql-root-password>
```

For a local root account with no password, leave `password` blank. Do not commit real credentials. Use environment-specific configuration or a secret manager outside local development.

## Build

### macOS and Linux

```bash
./mvnw clean package
```

### Windows PowerShell

```powershell
.\mvnw.cmd clean package
```

The built application is `target/ccshareapp-0.0.1-SNAPSHOT.jar`.

## Test

Tests use an in-memory H2 database and do not require local MySQL.

### macOS and Linux

```bash
./mvnw clean install
```

### Windows PowerShell

```powershell
.\mvnw.cmd clean install
```

## Flyway Migrations

The `mysql` profile enables Flyway. At startup it creates `flyway_schema_history`, validates migrations in `src/main/resources/db/migration`, applies pending migrations, and then Hibernate validates the schema.

The initial migration creates:

- `cards`
- `card_auth_events`
- `flyway_schema_history`

Verify the database state:

### macOS

```bash
mysql -h 127.0.0.1 -P 3306 -u root -D ccshareapp -e 'SHOW TABLES;'
```

### Windows PowerShell

```powershell
mysql -h 127.0.0.1 -P 3306 -u root -p -D ccshareapp -e "SHOW TABLES;"
```

## Run the Application

The runtime requires the `mysql` Spring profile.

### macOS

```bash
 mvn clean package && java -Xmx200m -Xms100m -Xss256k -XX:MaxMetaspaceSize=100m -XX:+UseSerialGC -jar target/ccshareapp-0.0.1-SNAPSHOT.jar --spring.profiles.active=mysql
```

### Windows PowerShell

Ensure `java` resolves to JDK 25, then run:

```powershell
.\mvnw.cmd clean package

java `
  -Xmx200m `
  -Xms100m `
  -Xss256k `
  -XX:MaxMetaspaceSize=100m `
  -XX:+UseSerialGC `
  -jar target\ccshareapp-0.0.1-SNAPSHOT.jar `
  --spring.profiles.active=mysql
```

The application runs at `http://localhost:8080`.

## Port 8080 Already in Use

Only one process can use port `8080`.

### macOS

```bash
lsof -nP -iTCP:8080 -sTCP:LISTEN
kill <PID>
```

### Windows PowerShell

```powershell
Get-NetTCPConnection -LocalPort 8080 | Select-Object OwningProcess
Stop-Process -Id <PID>
```

To start another instance, append `--server.port=8081` to the application command.

## Swagger UI

When the application is running:

- Swagger UI: `http://localhost:8080/swagger-ui/index.html`
- OpenAPI JSON: `http://localhost:8080/v3/api-docs`

## Create Card Record API

`POST /create` stores encrypted data and SRP verifier material. It never accepts plaintext card data or a passkey.

Required request fields:

- `card_identifier`: UUIDv4. Derived in the browser from the card name, its last four digits, and the passkey (LLD §4.3) — the server cannot compute or verify it beyond checking the shape, since it never sees the passkey.
- `encrypted_cc_blob`: Base64-encoded encrypted bytes. Includes the card's nickname; there is no plaintext label column (dropped in `V3__drop_card_label.sql`).
- `srp_verifier`: hexadecimal SRP verifier
- `srp_salt`: hexadecimal SRP salt

Example:

```bash
curl --request POST http://localhost:8080/create \
  --header 'Content-Type: application/json' \
  --data '{
    "card_identifier": "550e8400-e29b-41d4-a716-446655440000",
    "encrypted_cc_blob": "AAECAwQFBgcICQ==",
    "srp_verifier": "a1b2c3d4",
    "srp_salt": "e5f6a7b8"
  }'
```

A successful request returns `200 OK` with no body. Invalid input returns `400 Bad Request`; duplicate card identifiers return `409 Conflict`.

Because identifiers are derived, storing the same card name, last four digits, and passkey twice produces the same identifier and therefore a `409`. That is the intended signal for "you already stored this card" — it must not silently overwrite or no-op.

## Logging

Logging is configured via `logback-spring.xml` with both INFO and DEBUG levels:

### Log Levels

- **INFO:** Business-critical events (card created, fetch initiated, proof verified, lockout triggered)
- **DEBUG:** Detailed flow information (validation steps, challenge generation, state transitions)

### Log Output

- **Console:** Real-time log output during development
- **File:** Rotating log file at `spring.log` (10MB per file, 30-day history)

### Security Note (LLD §6.7)

The logging system intentionally **never logs:**
- Passphrases or passkeys
- SRP proofs (M1, M2, session key S)
- Encrypted CC blob contents
- Decrypted plaintext card data
- **Raw card identifiers**

Card identifiers are derived from the passkey (LLD §4.3), so a log line carrying one lets anyone with the log file grind passkey guesses offline — no server, no rate limit, no lockout. Application code routes every identifier through `LogSafe.identifier(...)`, which emits a truncated SHA-256: still stable enough to correlate requests for attack detection, useless for grinding.

Two framework loggers used to defeat this by logging around the application code, and are pinned in `logback-spring.xml` because of it:

- `org.springframework...RequestResponseBodyMethodProcessor` at `DEBUG` prints the whole deserialized request body — identifier *and* ciphertext. Pinned to `INFO`.
- `org.hibernate.type.descriptor.sql.BasicBinder` at `TRACE` prints every bound SQL parameter — identifier, verifier, salt, ciphertext. Removed.

Do not re-enable either. `org.hibernate.SQL` at `DEBUG` is fine: statement text, no parameter values.

Safe to log:
- Hashed card identifiers (via `LogSafe`) and challenge IDs
- Failed attempt counts and lockout state
- Validation results and error types
- Request/response metadata (size, timing)

### Configure Log Level

Set the `LOG_LEVEL` environment variable or edit `logback-spring.xml`:

```yaml
# In application.yaml or application-mysql.yaml
logging:
  level:
    com.soham.ccshareapp: DEBUG
    org.springframework.web: DEBUG
```

### View Logs

```bash
# Console output during runtime (already in use)
# File-based logs
tail -f spring.log

# Filter by logger
grep "CardFetchService" spring.log
```