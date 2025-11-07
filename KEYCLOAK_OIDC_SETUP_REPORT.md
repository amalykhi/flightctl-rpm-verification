# Keycloak OIDC Setup and Verification Report

**Date:** November 7, 2025
**VM:** eurolinux9 (192.168.122.219)
**FlightCtl Version:** 1.0.0-1.20251107095201063929.main.234.g15702321

---

## ✅ Completed Tasks

### 1. Keycloak Deployment and Configuration

#### Keycloak Container Deployed
- **Status:** ✅ Running
- **Container:** `keycloak` (Quay.io/keycloak/keycloak:latest)
- **Port:** 8080
- **Admin User:** admin
- **Admin Password:** admin
- **Access URL:** http://192.168.122.219:8080/admin

#### Realm Configuration
- **Realm Name:** `myrealm`
- **SSL Required:** None (HTTP allowed for development)
- **Status:** ✅ Created successfully
- **OIDC Discovery:** http://192.168.122.219:8080/realms/myrealm/.well-known/openid-configuration

#### Client Configuration
- **Client ID:** `my_client`
- **Type:** Public Client
- **Redirect URIs:**
  - `https://192.168.122.219:3443/*`
  - `https://192.168.122.219:443/*`
  - `http://localhost:*`
  - `urn:ietf:wg:oauth:2.0:oob`
- **Direct Access Grants:** Enabled
- **Standard Flow:** Enabled
- **Status:** ✅ Created successfully

#### Test Users Created
1. **Username:** `testuser`
   - **Password:** `password`
   - **Email:** testuser@example.com
   - **Email Verified:** Yes
   - **Status:** ✅ Authentication tested successfully

2. **Username:** `admin`
   - **Password:** `admin123`
   - **Email:** admin@example.com
   - **Email Verified:** Yes
   - **Status:** ✅ Created successfully

### 2. FlightCtl RPM Installation

#### RPMs Installed
- **Source:** LATEST build from Copr (Build ID: 9776837)
- **Version:** 1.0.0-1.20251107095201063929.main.234.g15702321
- **Packages:**
  - `flightctl-services`
  - `flightctl-cli`
- **Status:** ✅ Installed successfully

### 3. FlightCtl Services

#### Running Services
- ✅ `flightctl-db.service` - PostgreSQL Database
- ✅ `flightctl-kv.service` - Redis Key-Value Store
- ✅ `flightctl-alertmanager.service` - Alertmanager
- ✅ `flightctl-api.service` - API Server (running on port 3443)

#### Container Images
All container images retagged to version `1.0.0`:
- ✅ `flightctl-api:1.0.0`
- ✅ `flightctl-db-setup:1.0.0`
- ✅ `flightctl-periodic:1.0.0`
- ✅ `flightctl-ui:1.0.0`
- ✅ `flightctl-worker:1.0.0`
- ✅ `flightctl-alert-exporter:1.0.0`
- ✅ `flightctl-alertmanager-proxy:1.0.0`
- ✅ `flightctl-cli-artifacts:1.0.0`

### 4. OIDC Configuration Files

#### /etc/flightctl/service-config.yaml
```yaml
global:
  baseDomain: 192.168.122.219
  auth:
    type: oidc
    insecureSkipTlsVerify: true
    oidc:
      oidcAuthority: "http://192.168.122.219:8080/realms/myrealm"
      externalOidcAuthority: "http://192.168.122.219:8080/realms/myrealm"
      oidcClientId: "my_client"
```

#### /etc/flightctl/flightctl-api/config.yaml
```yaml
auth:
  type: oidc
  insecureSkipTlsVerify: true
  oidc:
    oidcAuthority: http://192.168.122.219:8080/realms/myrealm
    externalOidcAuthority: http://192.168.122.219:8080/realms/myrealm
    oidcClientId: my_client
```

### 5. Automation Scripts Created

#### setup_keycloak_oidc.sh
- **Location:** `/home/amalykhi/RPMs and OIDC/setup_keycloak_oidc.sh`
- **Purpose:** Automates Keycloak deployment and OIDC configuration
- **Features:**
  - Deploys Keycloak container
  - Creates realm, client, and users via REST API
  - Tests authentication
  - No UI interaction required

**Usage:**
```bash
./setup_keycloak_oidc.sh 192.168.122.219
```

#### verify_flightctl_oidc.sh (Enhanced)
- **Location:** `/home/amalykhi/RPMs and OIDC/verify_flightctl_oidc.sh`
- **New Feature:** `LATEST` option
- **Purpose:** Automates FlightCtl installation and OIDC verification

**Usage:**
```bash
./verify_flightctl_oidc.sh eurolinux9 LATEST
```

---

## ⚠️ Current Issues

### Issue #1: FlightCtl API Auth Disabled

**Problem:**
- The FlightCtl API is running but authentication is disabled
- API endpoint `/api/v1/auth/config` returns: "Auth not configured"
- Root cause: `flightctl-api-init.service` is failing

**Evidence:**
```bash
$ curl -k https://192.168.122.219:3443/api/v1/auth/config
{
  "code": 418,
  "message": "Auth not configured",
  "reason": "Auth not configured"
}
```

**Service Status:**
```bash
$ systemctl status flightctl-api-init.service
● flightctl-api-init.service
   Active: activating (auto-restart) (Result: exit-code)
```

**Impact:**
- Cannot test OIDC login flow with FlightCtl CLI
- Cannot test OIDC login flow with FlightCtl UI
- API currently accepts unauthenticated requests

**Next Steps to Debug:**
1. Check init script logs in detail: `journalctl -u flightctl-api-init.service -n 200`
2. Verify the init script template file: `/usr/share/flightctl/flightctl-api/config.yaml.template`
3. Check if there are missing dependencies or environment variables
4. Consider filing a bug report with FlightCtl team if this is a regression

### Issue #2: Multiple Services in Auto-Restart Loop

**Affected Services:**
- `flightctl-alert-exporter.service`
- `flightctl-alertmanager-proxy.service`
- `flightctl-cli-artifacts.service`
- `flightctl-db-migrate.service`
- `flightctl-db-users-init.service`
- `flightctl-pam-issuer.service`
- `flightctl-periodic.service`
- `flightctl-ui.service`
- `flightctl-worker.service`

**Likely Cause:**
- These services depend on `flightctl-api-init.service` completing successfully
- Since init is failing, dependent services cannot start properly

---

## ✅ Keycloak OIDC Verification (Independent)

Even though FlightCtl integration is blocked, **Keycloak OIDC is fully functional** and can be verified independently:

### Test 1: OIDC Discovery Endpoint
```bash
$ curl http://192.168.122.219:8080/realms/myrealm/.well-known/openid-configuration
```
**Result:** ✅ Returns full OIDC configuration

### Test 2: User Authentication (Password Grant)
```bash
$ curl -X POST 'http://192.168.122.219:8080/realms/myrealm/protocol/openid-connect/token' \
  -H 'Content-Type: application/x-www-form-urlencoded' \
  -d 'username=testuser' \
  -d 'password=password' \
  -d 'grant_type=password' \
  -d 'client_id=my_client'
```
**Result:** ✅ Returns valid access token

### Test 3: Token Validation
```bash
# Decode the JWT token to verify claims
$ echo "<access_token>" | cut -d. -f2 | base64 -d | jq
```
**Result:** ✅ Token contains correct issuer, client, and user information

---

## 📋 Summary

### What Works
1. ✅ **Keycloak OIDC Provider:** Fully deployed and configured
2. ✅ **OIDC Authentication:** Users can authenticate via Keycloak
3. ✅ **FlightCtl RPM Installation:** Latest build installed automatically
4. ✅ **FlightCtl Core Services:** Database, KV store, and API are running
5. ✅ **Automation Scripts:** Created and tested for repeatable deployment

### What Needs Fixing
1. ⚠️ **FlightCtl API Init Service:** Failing to configure authentication
2. ⚠️ **FlightCtl OIDC Integration:** Cannot test end-to-end login flow
3. ⚠️ **Dependent Services:** Multiple services stuck in restart loop

### Recommended Next Actions
1. **Debug Init Service:** Examine why `flightctl-api-init.service` is failing
2. **Check RPM Version Compatibility:** Verify if this is a known issue with build #9776837
3. **Try Previous Build:** Test with an earlier FlightCtl build to isolate the issue
4. **Manual Configuration:** Attempt to manually configure the API without the init service
5. **Contact FlightCtl Team:** Report the init service failure if it's a regression

---

## 🎯 OIDC Flow Verification Checklist

### Keycloak Setup
- [x] Keycloak container deployed
- [x] Realm "myrealm" created
- [x] Client "my_client" created
- [x] Test users created
- [x] OIDC discovery endpoint accessible
- [x] User authentication tested

### FlightCtl Setup
- [x] Latest RPMs installed
- [x] Container images available
- [x] Core services running
- [x] OIDC configuration files updated
- [ ] **API authentication enabled** ⚠️ BLOCKED
- [ ] **CLI login tested** ⚠️ BLOCKED
- [ ] **UI login tested** ⚠️ BLOCKED

---

## 📚 Reference Commands

### Keycloak Management
```bash
# Access Keycloak Admin Console
http://192.168.122.219:8080/admin

# Check Keycloak logs
sudo podman logs keycloak

# Restart Keycloak
sudo podman restart keycloak
```

### FlightCtl Management
```bash
# Check all FlightCtl services
systemctl list-units 'flightctl*' --all

# Restart FlightCtl
sudo systemctl restart flightctl.target

# Check API logs
sudo journalctl -u flightctl-api.service -f

# Check init service logs
sudo journalctl -u flightctl-api-init.service -n 100
```

### OIDC Testing
```bash
# Get access token
TOKEN=$(curl -s -X POST \
  'http://192.168.122.219:8080/realms/myrealm/protocol/openid-connect/token' \
  -H 'Content-Type: application/x-www-form-urlencoded' \
  -d 'username=testuser' \
  -d 'password=password' \
  -d 'grant_type=password' \
  -d 'client_id=my_client' | jq -r '.access_token')

# Use token with FlightCtl API (when auth is enabled)
curl -k -H "Authorization: Bearer $TOKEN" \
  https://192.168.122.219:3443/api/v1/devices
```

---

## 📞 Support Information

- **FlightCtl GitHub:** https://github.com/flightctl/flightctl
- **Copr Repository:** https://copr.fedorainfracloud.org/coprs/g/redhat-et/flightctl-dev/
- **Keycloak Docs:** https://www.keycloak.org/documentation

---

**Report Generated:** November 7, 2025  
**Author:** AI Assistant  
**VM:** eurolinux9 (192.168.122.219)

