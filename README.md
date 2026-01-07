# TrueNAS NFS Bulk Management Scripts

Python scripts for bulk management of NFS shares on TrueNAS using the v25.04 (Fangtooth) API.

## Requirements

```bash
pip install git+https://github.com/truenas/api_client.git
```

## Scripts

### 1. bulk_add_nfs_shares.py

Creates multiple NFS shares from a file containing paths, applying the same options to all shares.

#### Input File Format

Create a text file with one filesystem path per line:

```
/mnt/pool/share1
/mnt/pool/share2
/mnt/pool/media/movies
```

Lines starting with `#` are comments. Empty lines are ignored.

#### Usage Examples

**Basic creation with network access:**
```bash
python bulk_add_nfs_shares.py \
    --host 192.168.1.100 \
    --api-key YOUR_API_KEY \
    --file shares.txt \
    --network "192.168.1.0/24"
```

**Read-only shares with multiple networks and hosts:**
```bash
python bulk_add_nfs_shares.py \
    --host 192.168.1.100 \
    --username admin --password secretpass \
    --file shares.txt \
    --network "192.168.1.0/24" \
    --network "10.0.0.0/8" \
    --allowed-host "192.168.1.50" \
    --allowed-host "server.example.com" \
    --ro \
    --comment "Read-only media shares"
```

**Kerberos security with root mapping:**
```bash
python bulk_add_nfs_shares.py \
    --host 192.168.1.100 \
    --api-key YOUR_API_KEY \
    --file shares.txt \
    --network "192.168.1.0/24" \
    --security KRB5I \
    --security KRB5P \
    --maproot-user nobody \
    --maproot-group nogroup
```

**Preview without creating (dry run):**
```bash
python bulk_add_nfs_shares.py \
    --host 192.168.1.100 \
    --api-key YOUR_API_KEY \
    --file shares.txt \
    --network "172.16.0.0/12" \
    --dry-run
```

**Create disabled shares (enable manually later):**
```bash
python bulk_add_nfs_shares.py \
    --host 192.168.1.100 \
    --api-key YOUR_API_KEY \
    --file shares.txt \
    --network "192.168.1.0/24" \
    --no-enabled
```

**Skip paths that already have shares:**
```bash
python bulk_add_nfs_shares.py \
    --host 192.168.1.100 \
    --api-key YOUR_API_KEY \
    --file shares.txt \
    --network "192.168.1.0/24" \
    --skip-existing
```

**Using SSL connection:**
```bash
python bulk_add_nfs_shares.py \
    --host truenas.example.com \
    --ssl \
    --api-key YOUR_API_KEY \
    --file shares.txt \
    --network "192.168.1.0/24"
```

#### Available Options

| Option | Description |
|--------|-------------|
| `--file`, `-f` | Input file with share paths (required) |
| `--comment` | Description for all shares |
| `--network` | Allowed network in CIDR notation (max 42, repeatable) |
| `--allowed-host` | Allowed IP/hostname (max 42, repeatable) |
| `--ro` | Create shares as read-only |
| `--maproot-user` | Map root client user to this user |
| `--maproot-group` | Map root client group to this group |
| `--mapall-user` | Map all client users to this user |
| `--mapall-group` | Map all client groups to this group |
| `--security` | Security schema: SYS, KRB5, KRB5I, KRB5P (repeatable) |
| `--no-enabled` | Create shares in disabled state |
| `--expose-snapshots` | Enable ZFS snapshot directory access |
| `--skip-existing` | Skip paths that already have shares |
| `--dry-run` | Preview without creating |

---

### 2. bulk_modify_nfs_shares.py

Modifies existing NFS shares matching a path pattern. Can modify networks, hosts, security, permissions, user/group mappings, and other settings.

#### Usage Examples

**Remove a CIDR range from matching shares:**
```bash
python bulk_modify_nfs_shares.py \
    --host 192.168.1.100 \
    --api-key YOUR_API_KEY \
    --pattern "/mnt/pool/media*" \
    --remove-network "10.0.0.0/8"
```

**Add multiple hosts to backup shares:**
```bash
python bulk_modify_nfs_shares.py \
    --host 192.168.1.100 \
    --username admin --password secretpass \
    --pattern "/mnt/pool/backups*" \
    --add-host "192.168.1.50" \
    --add-host "192.168.1.51"
```

**Make all media shares read-only:**
```bash
python bulk_modify_nfs_shares.py \
    --host 192.168.1.100 \
    --api-key YOUR_API_KEY \
    --pattern "/mnt/pool/media*" \
    --set-ro
```

**Enable snapshot exposure on shares:**
```bash
python bulk_modify_nfs_shares.py \
    --host 192.168.1.100 \
    --api-key YOUR_API_KEY \
    --pattern "/mnt/pool/*" \
    --set-expose-snapshots
```

**Add Kerberos security and configure maproot:**
```bash
python bulk_modify_nfs_shares.py \
    --host 192.168.1.100 \
    --api-key YOUR_API_KEY \
    --pattern "/mnt/secure/*" \
    --add-security KRB5I \
    --add-security KRB5P \
    --set-maproot-user nobody \
    --set-maproot-group nogroup
```

**Disable old shares:**
```bash
python bulk_modify_nfs_shares.py \
    --host 192.168.1.100 \
    --api-key YOUR_API_KEY \
    --pattern "/mnt/pool/old*" \
    --disable
```

**Update comments on all shares:**
```bash
python bulk_modify_nfs_shares.py \
    --host 192.168.1.100 \
    --api-key YOUR_API_KEY \
    --pattern "*" \
    --set-comment "Managed by automation"
```

**Multiple modifications at once:**
```bash
python bulk_modify_nfs_shares.py \
    --host 192.168.1.100 \
    --api-key YOUR_API_KEY \
    --pattern "/mnt/pool/public*" \
    --add-network "172.16.0.0/12" \
    --remove-host "192.168.1.99" \
    --set-rw \
    --enable \
    --set-comment "Public shares"
```

**Preview changes without applying:**
```bash
python bulk_modify_nfs_shares.py \
    --host 192.168.1.100 \
    --api-key YOUR_API_KEY \
    --pattern "*" \
    --remove-network "192.0.2.0/24" \
    --dry-run
```

#### Available Options

**Filter Options:**
| Option | Description |
|--------|-------------|
| `--pattern` | Glob pattern to match share paths (default: "*") |

**Network and Host Options:**
| Option | Description |
|--------|-------------|
| `--add-network` | Add CIDR range (repeatable) |
| `--remove-network` | Remove CIDR range (repeatable) |
| `--add-host` | Add host/IP (repeatable) |
| `--remove-host` | Remove host/IP (repeatable) |

**Security Options:**
| Option | Description |
|--------|-------------|
| `--add-security` | Add security schema: SYS, KRB5, KRB5I, KRB5P (repeatable) |
| `--remove-security` | Remove security schema (repeatable) |

**Permission Options:**
| Option | Description |
|--------|-------------|
| `--set-ro` | Set shares as read-only |
| `--set-rw` | Set shares as read-write |
| `--enable` | Enable all matched shares |
| `--disable` | Disable all matched shares |
| `--set-expose-snapshots` | Enable ZFS snapshot directory access |
| `--unset-expose-snapshots` | Disable ZFS snapshot directory access |

**User/Group Mapping Options:**
| Option | Description |
|--------|-------------|
| `--set-maproot-user` | Map root client user to specified user |
| `--set-maproot-group` | Map root client group to specified group |
| `--clear-maproot` | Clear maproot user and group settings |
| `--set-mapall-user` | Map all client users to specified user |
| `--set-mapall-group` | Map all client groups to specified group |
| `--clear-mapall` | Clear mapall user and group settings |

**Other Options:**
| Option | Description |
|--------|-------------|
| `--set-comment` | Set comment/description for all matched shares |
| `--dry-run` | Preview changes without applying |

---

## Authentication

Both scripts support two authentication methods:

### API Key (Recommended)
```bash
--api-key YOUR_API_KEY
```

To create an API key in TrueNAS:
1. Go to System → API Keys
2. Click "Add"
3. Name it and save the key securely

### Username/Password
```bash
--username admin --password secretpass
```

## Connection Options

| Option | Description |
|--------|-------------|
| `--host` | TrueNAS hostname or IP (required) |
| `--port` | Custom port (optional) |
| `--ssl` | Use secure WebSocket (wss://) |

## Pattern Matching

The modify script uses glob patterns to match share paths:

- `*` - Matches any characters
- `?` - Matches single character
- `[abc]` - Matches a, b, or c
- `[!abc]` - Matches any character except a, b, or c

Examples:
- `/mnt/pool/*` - All immediate children of /mnt/pool/
- `/mnt/pool/media*` - Paths starting with /mnt/pool/media
- `/mnt/*/backups` - Any backups directory under /mnt/
- `*` - All shares

## API Rate Limiting

TrueNAS limits connections to **20 auth attempts or unauthenticated requests per 60 seconds**, with a 10-minute cooldown when exceeded.

Both scripts authenticate **once per execution** and reuse the connection for all operations, avoiding rate limits.

## API Version

These scripts use the **TrueNAS v25.04 (Fangtooth)** API documented at:
https://api.truenas.com/v25.04/

## Error Handling

- Both scripts validate TrueNAS limits (max 42 networks, max 42 hosts)
- Failed operations are reported with details
- Exit codes: 0 = success, 1 = errors occurred, 130 = cancelled by user
- Use `--dry-run` to preview changes before applying

## Examples

### Scenario 1: Create 10 media shares with restricted access

**shares.txt:**
```
/mnt/pool/media/movies
/mnt/pool/media/tv
/mnt/pool/media/music
# ... etc
```

**Command:**
```bash
python bulk_add_nfs_shares.py \
    --host 192.168.1.100 \
    --api-key YOUR_KEY \
    --file shares.txt \
    --network "192.168.1.0/24" \
    --network "192.168.2.0/24" \
    --ro \
    --comment "Media shares - read-only"
```

### Scenario 2: Remove old network from all shares

```bash
# Preview first
python bulk_modify_nfs_shares.py \
    --host 192.168.1.100 \
    --api-key YOUR_KEY \
    --pattern "*" \
    --remove-network "10.0.0.0/8" \
    --dry-run

# Apply if looks good
python bulk_modify_nfs_shares.py \
    --host 192.168.1.100 \
    --api-key YOUR_KEY \
    --pattern "*" \
    --remove-network "10.0.0.0/8"
```

### Scenario 3: Add backup server access to backup shares

```bash
python bulk_modify_nfs_shares.py \
    --host 192.168.1.100 \
    --api-key YOUR_KEY \
    --pattern "/mnt/*/backup*" \
    --add-host "backup.example.com" \
    --add-host "192.168.1.100"
```

### Scenario 4: Convert shares to read-only with snapshot access

```bash
python bulk_modify_nfs_shares.py \
    --host 192.168.1.100 \
    --api-key YOUR_KEY \
    --pattern "/mnt/pool/archive/*" \
    --set-ro \
    --set-expose-snapshots \
    --set-comment "Read-only archive with snapshot access"
```

### Scenario 5: Secure shares with Kerberos and maproot

```bash
python bulk_modify_nfs_shares.py \
    --host 192.168.1.100 \
    --api-key YOUR_KEY \
    --pattern "/mnt/secure/*" \
    --add-security KRB5I \
    --add-security KRB5P \
    --remove-security SYS \
    --set-maproot-user nobody \
    --set-maproot-group nogroup
```

### Scenario 6: Temporarily disable shares for maintenance

```bash
# Disable shares
python bulk_modify_nfs_shares.py \
    --host 192.168.1.100 \
    --api-key YOUR_KEY \
    --pattern "/mnt/pool/maintenance/*" \
    --disable \
    --set-comment "Disabled for maintenance"

# Re-enable later
python bulk_modify_nfs_shares.py \
    --host 192.168.1.100 \
    --api-key YOUR_KEY \
    --pattern "/mnt/pool/maintenance/*" \
    --enable \
    --set-comment "Back online"
```

## Troubleshooting

**"Rate limit exceeded"**
- Wait 10 minutes for the cooldown
- Use a single script execution rather than multiple rapid calls

**"Maximum 42 networks/hosts allowed"**
- TrueNAS enforces a limit of 42 entries for networks and hosts
- Review and consolidate your CIDR ranges
- Consider using broader network ranges

**"Share already exists"**
- Use `--skip-existing` flag when creating shares
- Or use the modify script instead to update existing shares

**"Authentication failed"**
- Verify API key or username/password
- Check that the user has SHARING_NFS_READ and SHARING_NFS_WRITE roles

**Connection timeout**
- Verify TrueNAS is accessible at the specified host
- Check firewall rules
- Try adding `--port` if using non-standard port
- Add `--ssl` if HTTPS is enforced

## Security Notes

- Store API keys securely (use environment variables or credential managers)
- Avoid passing passwords on command line (they appear in process lists)
- Use API keys instead of username/password for automation
- Consider using `--ssl` for production environments
- Review network/host access lists carefully before applying

## License

These scripts interact with TrueNAS using the official API client.
Refer to TrueNAS documentation for API usage terms.
