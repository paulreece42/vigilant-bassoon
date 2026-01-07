# TrueNAS API Authentication Troubleshooting

## Current Issue

The scripts are encountering this error when attempting to authenticate with an API key:

```
AUTH: unexpected authenticator run state. Expected: START
```

## What We've Tested

✓ Connection to TrueNAS succeeds (both ws:// and wss://)
✗ API key authentication fails with state error
✗ Error occurs with both secure (wss://) and insecure (ws://) connections

## What This Error Means

This error indicates that TrueNAS's internal authentication state machine is not in the expected "START" state when attempting authentication. This is an unusual error that suggests:

1. **The API key may have been revoked** - TrueNAS automatically revokes API keys used over insecure connections
2. **Two-factor authentication (2FA) is enabled** - This may interfere with API key auth
3. **The middleware service is in an error state** - A previous authentication attempt may not have cleaned up properly
4. **API version incompatibility** - The client library may not match your TrueNAS version

## Diagnostic Steps

### 1. Check TrueNAS Version

SSH to your TrueNAS system and run:
```bash
cat /etc/version
```

The scripts are designed for **TrueNAS v25.04 (Fangtooth)**. If you're running a different version, there may be API incompatibilities.

### 2. Check Middleware Logs

```bash
tail -100 /var/log/middlewared.log
```

Look for authentication-related errors or warnings around the time you ran the test script.

### 3. Generate a Fresh API Key

1. Log into the TrueNAS web interface
2. Go to **System → API Keys**
3. Delete the old API key if it exists
4. Click **Add** to create a new one
5. Update your runtest.sh script with the new key

### 4. Check for Two-Factor Authentication

If 2FA is enabled on the account associated with the API key:
1. Try using a different account without 2FA
2. Or use username/password authentication instead (see below)

### 5. Restart Middleware Service

If the authentication state is corrupted:

```bash
systemctl restart middlewared
```

Then wait 30 seconds and try authentication again.

### 6. Try Username/Password Authentication

Run the alternative test script:

```bash
./runtest_userpass.sh
```

Or manually update your command to use:
```bash
python3 bulk_add_nfs_shares.py \
    --host 192.168.18.42 \
    --username root \
    --password YOUR_PASSWORD \
    --file testpath.txt \
    # ... other options
```

If username/password works but API key doesn't, this confirms the issue is specific to API key authentication.

## Updated Scripts

The scripts have been updated with:

✓ Better error handling and messages
✓ SSL verification disabled (for self-signed certificates)
✓ Detailed diagnostics for authentication failures
✓ Cleanup of connection on auth failure

## Running the Diagnostic Tool

Run the comprehensive diagnostic:

```bash
python3 debug_auth.py
```

This will test multiple authentication methods and provide specific guidance based on the results.

## Alternative: Use Username/Password

If API key authentication continues to fail, you can use username/password authentication as a workaround:

### For bulk_add_nfs_shares.py:
```bash
python3 bulk_add_nfs_shares.py \
    --host 192.168.18.42 \
    --username root \
    --password YOUR_PASSWORD \
    --file shares.txt \
    --network "192.168.18.0/24" \
    # ... other options
```

### For bulk_modify_nfs_shares.py:
```bash
python3 bulk_modify_nfs_shares.py \
    --host 192.168.18.42 \
    --username root \
    --password YOUR_PASSWORD \
    --pattern "/mnt/pool/*" \
    --add-network "192.168.1.0/24"
```

## Check API Endpoint

Verify the API endpoint is accessible:

```bash
curl -k https://192.168.18.42/api/docs/
```

This should return the API documentation page. If it returns 404 or an error, the API may not be properly configured.

## Known Issues

### API Keys and Insecure Transport

According to TrueNAS documentation, **API keys are automatically revoked when used over insecure (HTTP/WS) connections**. However, our tests show the error occurs even with secure (WSS) connections, suggesting the issue may be deeper than transport security.

### Client Library Version

The installed `truenas_api_client` reports version `0.0.0`, indicating it's a development version. Consider checking if a newer version is available:

```bash
pip3 install --upgrade git+https://github.com/truenas/api_client.git
```

## Getting Help

If these steps don't resolve the issue:

1. **TrueNAS Community Forums**: https://www.truenas.com/community/
2. **GitHub Issues**: https://github.com/truenas/api_client/issues
3. **Include in your report:**
   - TrueNAS version (`cat /etc/version`)
   - Output from `python3 debug_auth.py`
   - Relevant lines from `/var/log/middlewared.log`
   - Whether username/password authentication works

## Quick Reference

### Test Scripts

| Script | Purpose |
|--------|---------|
| `runtest.sh` | Original test with API key (currently failing) |
| `runtest_userpass.sh` | Alternative test with username/password |
| `debug_auth.py` | Comprehensive authentication diagnostics |

### Main Scripts

| Script | Purpose |
|--------|---------|
| `bulk_add_nfs_shares.py` | Create multiple NFS shares from file |
| `bulk_modify_nfs_shares.py` | Modify existing NFS shares by pattern |

Both scripts support:
- `--api-key` for API key authentication
- `--username` and `--password` for credential authentication
