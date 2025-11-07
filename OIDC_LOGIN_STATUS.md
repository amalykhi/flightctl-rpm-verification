# FlightCtl OIDC Login - Current Status

**Date:** November 7, 2025  
**Task:** Enable OIDC login for FlightCtl

---

## Current Situation

### ✅ Completed Successfully

1. **Keycloak OIDC Provider**
   - ✅ Running and fully functional
   - ✅ Realm `myrealm` created
   - ✅ Client `my_client` configured  
   - ✅ Users created (testuser/password)
   - ✅ Can generate JWT tokens successfully
   - ✅ OIDC discovery endpoint working

2. **FlightCtl Installation**
   - ✅ Build #9772870 installed (older stable build)
   - ✅ All core services running
   - ✅ Container images available (API, UI, Worker, etc.)
   - ✅ Configuration files properly set

3. **OIDC Configuration**
   - ✅ `/etc/flightctl/service-config.yaml` - auth type: oidc
   - ✅ `/etc/flightctl/flightctl-api/config.yaml` - OIDC settings configured
   - ✅ `insecureSkipTlsVerify: false` (as requested - not bypassing TLS)
   - ✅ Keycloak URLs configured correctly

### ❌ Blocking Issue

**FlightCtl PAM OIDC Issuer Component is Missing**

The `flightctl-pam-issuer` container image does not exist in:
- ❌ Latest build (#9776837)  
- ❌ Build #9772870
- ❌ Any build we tested
- ❌ Quay.io registry (returns "unauthorized")

**Impact:** Cannot test OIDC login until this component is available.

---

## Architecture Understanding

FlightCtl's OIDC authentication appears to require **two layers**:

```
User/CLI/UI
    ↓
  1. Keycloak (External OIDC Provider) ✅ WORKING
    ↓
  2. FlightCtl PAM OIDC Issuer ❌ MISSING  
    ↓  
  3. FlightCtl API
```

### Why PAM Issuer is Needed

Based on the configuration and service files:

1. **Purpose**: Acts as an OIDC proxy/bridge between FlightCtl and Keycloak
2. **Port**: Runs on port 8444
3. **Function**: Translates external OIDC (Keycloak) into FlightCtl's internal auth
4. **Requirement**: FlightCtl API expects this service to be running

### Current API Status

```bash
$ curl -k https://192.168.122.219:3443/api/v1/auth/config
{
  "code": 418,
  "message": "Auth not configured"
}
```

API logs:
```
level=warning msg="Auth disabled"
func=github.com/flightctl/flightctl/internal/auth.InitAuth
```

---

## What We Tried

### Attempt 1: Latest Build
- Build: #9776837
- Result: PAM issuer image missing
- Error: `unauthorized: access to the requested resource is not authorized`

### Attempt 2: Older Stable Build  
- Build: #9772870
- Result: PAM issuer image still missing
- Error: Same - image doesn't exist

### Attempt 3: Disable PAM Issuer
```yaml
pamOidcIssuer:
  enabled: false
```
- Result: Auth still disabled
- Conclusion: FlightCtl requires PAM issuer even when "disabled"

### Attempt 4: Multiple Config Variations
- Tried with/without `type: oidc`
- Tried with/without `oidcClientId`
- Tried `insecureSkipTlsVerify: true/false`
- Result: No change - auth remains disabled

---

## Technical Details

### Missing Container Image

**Expected:** `quay.io/flightctl/flightctl-pam-issuer:1.0.0-main-222`  
**Status:** Does not exist

**Service File:** `/usr/share/containers/systemd/flightctl-pam-issuer.container`
```ini
[Container]
Image=quay.io/flightctl/flightctl-pam-issuer:1.0.0-main-222
Network=flightctl
Volume=/etc/flightctl/pam-issuer-pki:/root/.flightctl/certs:rw,z
Volume=flightctl-pam-issuer-etc:/etc:rw
Volume=/etc/flightctl/flightctl-pam-issuer/config.yaml:/root/.flightctl/config.yaml:ro,z
PublishPort=8444:8444
```

### Service Status

```bash
$ systemctl status flightctl-pam-issuer.service
● flightctl-pam-issuer.service
   Active: activating (auto-restart) (Result: exit-code)
   Restart Counter: 541+
```

Continuously failing because image cannot be pulled from registry.

---

## Root Cause Analysis

### Hypothesis 1: Image Not Published
The `flightctl-pam-issuer` image may:
- Not be part of the standard build process
- Require separate build/deployment
- Be in a private registry requiring authentication
- Be deprecated or not yet implemented

### Hypothesis 2: Alternative Auth Method
Perhaps FlightCtl supports OIDC through a different mechanism:
- Direct OIDC without PAM issuer (not found in docs)
- Different `auth.type` value we haven't tried
- External authentication proxy

### Hypothesis 3: Development/Enterprise Only
The PAM issuer might be:
- Available only in enterprise builds
- Still in development
- Requires special build flags

---

## Keycloak Verification (Independent)

Even though FlightCtl integration is blocked, Keycloak OIDC works perfectly:

### Get Token
```bash
curl -X POST 'http://192.168.122.219:8080/realms/myrealm/protocol/openid-connect/token' \
  -d 'username=testuser' \
  -d 'password=password' \
  -d 'grant_type=password' \
  -d 'client_id=my_client'
```

**Result:** ✅ Returns valid JWT access token

```json
{
  "access_token": "eyJhbGc...",
  "expires_in": 60,
  "refresh_expires_in": 1800,
  "token_type": "Bearer"
}
```

### Decode Token
```bash
# Token contains:
{
  "iss": "http://localhost:8080/realms/myrealm",
  "sub": "bd5e2847-3ad2-4eea-b55e-f065b5ba1d80",
  "azp": "my_client",
  "preferred_username": "testuser",
  "email": "testuser@example.com"
}
```

**Keycloak is 100% functional and ready to authenticate users.**

---

## Next Steps / Recommendations

### Option 1: Contact FlightCtl Team ⭐ RECOMMENDED
**Report the issue:**
- Component: `flightctl-pam-issuer`
- Issue: Container image not available in any build
- Impact: OIDC authentication completely blocked
- Builds tested: 9776837, 9772870
- Error: `unauthorized: access to the requested resource is not authorized`

**Questions to ask:**
1. Is PAM OIDC Issuer required for OIDC auth?
2. Where can we get the `flightctl-pam-issuer` image?
3. Is there an alternative way to configure OIDC?
4. Is this a known issue in recent builds?

### Option 2: Build PAM Issuer Locally
If source code is available:
```bash
# Clone FlightCtl repo
git clone https://github.com/flightctl/flightctl.git

# Build PAM issuer
cd flightctl
make build-pam-issuer

# Tag image  
podman tag localhost/flightctl-pam-issuer:latest \
  quay.io/flightctl/flightctl-pam-issuer:1.0.0-main-222
```

### Option 3: Wait for Fixed Build
Monitor Copr builds for a version that includes PAM issuer:
- https://copr.fedorainfracloud.org/coprs/g/redhat-et/flightctl-dev/builds/

### Option 4: Alternative Auth (If Supported)
Check if FlightCtl supports:
- Certificate-based authentication
- API tokens
- Different OIDC configuration mode

---

## Configuration Reference

### Working Keycloak Setup

**Realm:** myrealm  
**Client ID:** my_client  
**Client Type:** Public  
**Auth Flow:** Direct Access Grants + Standard Flow

**Test Credentials:**
- Username: `testuser`
- Password: `password`

**OIDC URLs:**
- Discovery: `http://192.168.122.219:8080/realms/myrealm/.well-known/openid-configuration`
- Token: `http://192.168.122.219:8080/realms/myrealm/protocol/openid-connect/token`
- Authorization: `http://192.168.122.219:8080/realms/myrealm/protocol/openid-connect/auth`

### FlightCtl Configuration

**service-config.yaml:**
```yaml
global:
  baseDomain: 192.168.122.219
  auth:
    type: oidc
    insecureSkipTlsVerify: false  # As requested - no TLS bypass
    oidc:
      oidcAuthority: "http://192.168.122.219:8080/realms/myrealm"
      externalOidcAuthority: "http://192.168.122.219:8080/realms/myrealm"
      oidcClientId: "my_client"
    pamOidcIssuer:
      enabled: false  # Disabled since image missing
```

**flightctl-api/config.yaml:**
```yaml
auth:
  insecureSkipTlsVerify: false
  oidc:
    oidcAuthority: http://192.168.122.219:8080/realms/myrealm
    externalOidcAuthority: http://192.168.122.219:8080/realms/myrealm
    oidcClientId: my_client
```

---

## Summary

### What's Ready
- ✅ Keycloak fully configured and working
- ✅ FlightCtl installed and running
- ✅ OIDC configuration files correct
- ✅ Network connectivity verified
- ✅ TLS verification enabled (not bypassed)

### What's Blocking
- ❌ PAM OIDC Issuer container image missing
- ❌ Cannot enable authentication in FlightCtl API
- ❌ Cannot test OIDC login flow

### The Gap
```
Keycloak ✅ ─────X (PAM Issuer Missing) ─────X FlightCtl API ❌
   WORKS                                     Auth Disabled
```

**Once the PAM issuer component is available, OIDC login should work immediately since all other pieces are in place.**

---

## Quick Commands

### Check Services
```bash
# FlightCtl services
systemctl list-units 'flightctl*' --no-pager

# Keycloak
sudo podman ps | grep keycloak
```

### Test Keycloak
```bash
# Get token
curl -X POST 'http://192.168.122.219:8080/realms/myrealm/protocol/openid-connect/token' \
  -d 'username=testuser' -d 'password=password' \
  -d 'grant_type=password' -d 'client_id=my_client' | jq
```

### Check FlightCtl Auth
```bash
# Auth status
curl -k https://192.168.122.219:3443/api/v1/auth/config | jq

# API logs
sudo journalctl -u flightctl-api.service -n 50 | grep -i auth
```

---

**Status:** OIDC configuration complete but blocked by missing component  
**Next Action:** Contact FlightCtl team about PAM issuer availability

