# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

Python CLI toolkit for bulk management of NFS shares on TrueNAS via the v25.04 (Fangtooth) WebSocket API. Two scripts handle creation and modification of shares.

## Dependencies

```bash
pip install git+https://github.com/truenas/api_client.git
```

## Running the Scripts

**Create shares from a file:**
```bash
python bulk_add_nfs_shares.py --host <IP> --api-key <KEY> --file shares.txt --network "192.168.1.0/24"
```

**Modify existing shares by pattern:**
```bash
python bulk_modify_nfs_shares.py --host <IP> --api-key <KEY> --pattern "/mnt/pool/*" --add-network "10.0.0.0/8"
```

Both scripts support `--dry-run` to preview changes without applying them.

## Architecture

Both scripts follow the same pattern:
- Main class (`NFSShareCreator` / `NFSShareModifier`) implements context manager for WebSocket connection lifecycle
- Single authentication at connection start, reused for all operations (avoids TrueNAS rate limit of 20 auth/60s)
- `bulk_create()` / `bulk_modify()` orchestrates operations and tracks statistics
- Exit codes: 0 = success, 1 = errors, 130 = user cancelled

**Key TrueNAS API calls:**
- `auth.login_with_api_key` / `auth.login` - authentication
- `sharing.nfs.query` - list shares
- `sharing.nfs.create` - create share
- `sharing.nfs.update` - modify share

## Constraints

- Maximum 42 networks per share
- Maximum 42 hosts per share
- API rate limit: 20 requests/60 seconds with 10-minute cooldown
- Paths must start with `/`
- Glob patterns use `fnmatch` syntax (*, ?, [abc])

## Authentication

API key (recommended) or username/password. API keys created in TrueNAS UI at System -> API Keys.
