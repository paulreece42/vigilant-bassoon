#!/usr/bin/env python3
"""
TrueNAS NFS Share Bulk Creation Tool

This script uses the TrueNAS API (v25.04 Fangtooth) to bulk-create NFS shares
from a file containing share paths. All shares are created with the same options.

Requirements:
    pip install git+https://github.com/truenas/api_client.git

Input File Format:
    The input file should contain one filesystem path per line:

    /mnt/pool/share1
    /mnt/pool/share2
    /mnt/pool/media/movies
    /mnt/pool/media/tv

    Empty lines and lines starting with # are ignored.

Usage Examples:
    # Create shares with basic settings
    python bulk_add_nfs_shares.py --host 192.168.1.100 --api-key YOUR_KEY \
        --file shares.txt --network "192.168.1.0/24"

    # Create read-only shares with multiple networks and hosts
    python bulk_add_nfs_shares.py --host 192.168.1.100 --username admin --password pass \
        --file shares.txt \
        --network "192.168.1.0/24" --network "10.0.0.0/8" \
        --allowed-host "192.168.1.50" --allowed-host "server.example.com" \
        --ro --comment "Read-only media shares"

    # Preview what would be created (dry run)
    python bulk_add_nfs_shares.py --host 192.168.1.100 --api-key YOUR_KEY \
        --file shares.txt --network "172.16.0.0/12" --dry-run

    # Create shares with Kerberos security and root mapping
    python bulk_add_nfs_shares.py --host 192.168.1.100 --api-key YOUR_KEY \
        --file shares.txt \
        --security KRB5I --security KRB5P \
        --maproot-user nobody --maproot-group nogroup

    # Create disabled shares (can be enabled later)
    python bulk_add_nfs_shares.py --host 192.168.1.100 --api-key YOUR_KEY \
        --file shares.txt --network "192.168.1.0/24" --no-enabled
"""

import argparse
import sys
from pathlib import Path
from typing import List, Dict, Any, Optional
from truenas_api_client import Client


class NFSShareCreator:
    """Handles bulk creation of TrueNAS NFS shares."""

    def __init__(self, uri: str, api_key: Optional[str] = None,
                 username: Optional[str] = None, password: Optional[str] = None):
        """
        Initialize the NFS share creator.

        Args:
            uri: WebSocket URI for TrueNAS (e.g., ws://192.168.1.100/api/current)
            api_key: API key for authentication
            username: Username for authentication (alternative to API key)
            password: Password for authentication (required if username provided)
        """
        self.uri = uri
        self.api_key = api_key
        self.username = username
        self.password = password
        self.client = None

    def __enter__(self):
        """Context manager entry - establish connection and authenticate."""
        try:
            self.client = Client(uri=self.uri, verify_ssl=False).__enter__()
        except Exception as e:
            raise ConnectionError(f"Failed to connect to {self.uri}: {e}")

        # Authenticate once and reuse the connection
        try:
            if self.api_key:
                print(f"Authenticating with API key...")
                result = self.client.call("auth.login_with_api_key", self.api_key)
                if not result:
                    raise ValueError("API key authentication returned False - key may be invalid or revoked")
            elif self.username and self.password:
                print(f"Authenticating as user '{self.username}'...")
                result = self.client.call("auth.login", self.username, self.password)
                if not result:
                    raise ValueError("Username/password authentication failed")
            else:
                raise ValueError("Must provide either api_key or username/password")

            print("✓ Connected and authenticated\n")
            return self

        except Exception as e:
            # Clean up the client connection on auth failure
            if self.client:
                try:
                    self.client.__exit__(None, None, None)
                except:
                    pass

            # Provide helpful error messages
            error_msg = str(e)
            if "unexpected authenticator run state" in error_msg.lower():
                raise RuntimeError(
                    f"Authentication state error: {e}\n\n"
                    "This error may indicate:\n"
                    "1. The API key has been revoked or is invalid\n"
                    "2. Two-factor authentication (2FA) is enabled on the account\n"
                    "3. The TrueNAS authentication service is in an unexpected state\n"
                    "4. A previous authentication attempt is still active\n\n"
                    "Suggestions:\n"
                    "- Try generating a new API key in TrueNAS (System → API Keys)\n"
                    "- Try using --username and --password instead of --api-key\n"
                    "- Check TrueNAS logs: /var/log/middlewared.log\n"
                    "- Restart the TrueNAS middleware service if you have console access"
                )
            else:
                raise

    def __exit__(self, exc_type, exc_val, exc_tb):
        """Context manager exit - close connection."""
        if self.client:
            self.client.__exit__(exc_type, exc_val, exc_tb)

    def create_share(self, share_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Create an NFS share using sharing.nfs.create.

        Args:
            share_data: Dictionary of share configuration

        Returns:
            Created share object with ID
        """
        return self.client.call("sharing.nfs.create", share_data)

    def check_existing_shares(self, paths: List[str]) -> Dict[str, int]:
        """
        Check if any of the paths already have NFS shares.

        Args:
            paths: List of filesystem paths to check

        Returns:
            Dictionary mapping existing paths to their share IDs
        """
        print("Checking for existing shares...")
        all_shares = self.client.call("sharing.nfs.query")
        existing = {}

        for share in all_shares:
            if share['path'] in paths:
                existing[share['path']] = share['id']

        if existing:
            print(f"⚠ Found {len(existing)} existing share(s)")
        else:
            print("✓ No conflicts found")

        return existing

    def bulk_create(self, paths: List[str], share_options: Dict[str, Any],
                   skip_existing: bool = False, dry_run: bool = False) -> Dict[str, Any]:
        """
        Bulk create NFS shares for the given paths.

        Args:
            paths: List of filesystem paths to create shares for
            share_options: Common options to apply to all shares
            skip_existing: If True, skip paths that already have shares
            dry_run: If True, show what would be created without creating

        Returns:
            Dictionary with statistics about the operation
        """
        if not paths:
            print("No paths provided.")
            return {'total': 0, 'created': 0, 'skipped': 0, 'errors': 0}

        # Check for existing shares
        existing = self.check_existing_shares(paths)

        stats = {
            'total': len(paths),
            'created': 0,
            'skipped': 0,
            'errors': 0
        }

        print(f"\n{'=' * 80}")
        print(f"{'DRY RUN - No shares will be created' if dry_run else 'Creating NFS shares'}")
        print(f"{'=' * 80}\n")

        for path in paths:
            try:
                # Check if share already exists
                if path in existing:
                    print(f"Path: {path}")
                    print(f"  ⚠ Share already exists (ID: {existing[path]})")
                    if skip_existing:
                        print(f"  → Skipping")
                        stats['skipped'] += 1
                    else:
                        print(f"  ✗ Error: Cannot create duplicate share")
                        stats['errors'] += 1
                    print()
                    continue

                # Build share data
                share_data = {'path': path, **share_options}

                print(f"Path: {path}")
                print(f"  Options:")
                for key, value in share_options.items():
                    if value not in [None, [], '']:  # Only show non-empty options
                        print(f"    {key}: {value}")

                if dry_run:
                    print(f"  [DRY RUN] Would create share")
                    stats['created'] += 1
                else:
                    # Create the share
                    result = self.create_share(share_data)
                    print(f"  ✓ Share created successfully (ID: {result['id']})")
                    stats['created'] += 1

                print()

            except Exception as e:
                print(f"Path: {path}")
                print(f"  ✗ Error creating share: {e}")
                stats['errors'] += 1
                print()

        return stats


def read_paths_from_file(file_path: str) -> List[str]:
    """
    Read filesystem paths from a file, one per line.

    Args:
        file_path: Path to the input file

    Returns:
        List of filesystem paths

    Raises:
        FileNotFoundError: If the file doesn't exist
        ValueError: If the file is empty or contains no valid paths
    """
    path_obj = Path(file_path)

    if not path_obj.exists():
        raise FileNotFoundError(f"Input file not found: {file_path}")

    if not path_obj.is_file():
        raise ValueError(f"Not a file: {file_path}")

    paths = []
    with open(file_path, 'r') as f:
        for line_num, line in enumerate(f, 1):
            line = line.strip()

            # Skip empty lines and comments
            if not line or line.startswith('#'):
                continue

            # Basic validation
            if not line.startswith('/'):
                print(f"⚠ Warning: Line {line_num} doesn't start with '/': {line}")
                continue

            paths.append(line)

    if not paths:
        raise ValueError(f"No valid paths found in {file_path}")

    return paths


def main():
    parser = argparse.ArgumentParser(
        description='Bulk create TrueNAS NFS shares from a file',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__
    )

    # Connection arguments
    parser.add_argument('--host', required=True,
                       help='TrueNAS host IP or hostname')
    parser.add_argument('--port', default=None,
                       help='TrueNAS port (default: 80 for ws://, 443 for wss://)')
    parser.add_argument('--ssl', action='store_true',
                       help='Use secure WebSocket (wss://)')

    # Authentication arguments
    auth_group = parser.add_mutually_exclusive_group(required=True)
    auth_group.add_argument('--api-key', help='API key for authentication')
    auth_group.add_argument('--username', help='Username for authentication')
    parser.add_argument('--password', help='Password (required if using --username)')

    # Input file
    parser.add_argument('--file', '-f', required=True,
                       help='File containing share paths (one per line)')

    # NFS share options
    parser.add_argument('--comment', default='',
                       help='Description for all shares')

    parser.add_argument('--network', action='append', dest='networks',
                       help='Allowed network in CIDR notation (max 42, can specify multiple times)')
    parser.add_argument('--allowed-host', action='append', dest='hosts',
                       help='Allowed IP/hostname (max 42, can specify multiple times)')

    parser.add_argument('--ro', action='store_true',
                       help='Create shares as read-only')

    parser.add_argument('--maproot-user',
                       help='Map root client user to this user')
    parser.add_argument('--maproot-group',
                       help='Map root client group to this group')
    parser.add_argument('--mapall-user',
                       help='Map all client users to this user')
    parser.add_argument('--mapall-group',
                       help='Map all client groups to this group')

    parser.add_argument('--security', action='append', dest='security',
                       choices=['SYS', 'KRB5', 'KRB5I', 'KRB5P'],
                       help='Security schema (can specify multiple times)')

    parser.add_argument('--no-enabled', action='store_true',
                       help='Create shares in disabled state (default: enabled)')

    parser.add_argument('--expose-snapshots', action='store_true',
                       help='Enable access to ZFS snapshot directory (Enterprise feature)')

    # Behavior options
    parser.add_argument('--skip-existing', action='store_true',
                       help='Skip paths that already have NFS shares')
    parser.add_argument('--dry-run', action='store_true',
                       help='Preview what would be created without creating')

    args = parser.parse_args()

    # Validate authentication
    if args.username and not args.password:
        parser.error("--password is required when using --username")

    # Validate limits
    if args.networks and len(args.networks) > 42:
        parser.error("Maximum 42 networks allowed")
    if args.hosts and len(args.hosts) > 42:
        parser.error("Maximum 42 hosts allowed")

    # Read paths from file
    try:
        paths = read_paths_from_file(args.file)
        print(f"Read {len(paths)} path(s) from {args.file}\n")
    except (FileNotFoundError, ValueError) as e:
        print(f"✗ Error reading input file: {e}", file=sys.stderr)
        sys.exit(1)

    # Build share options
    share_options = {
        'comment': args.comment,
        'networks': args.networks or [],
        'hosts': args.hosts or [],
        'ro': args.ro,
        'enabled': not args.no_enabled,
        'expose_snapshots': args.expose_snapshots,
    }

    # Add optional mapping parameters (only if specified)
    if args.maproot_user:
        share_options['maproot_user'] = args.maproot_user
    if args.maproot_group:
        share_options['maproot_group'] = args.maproot_group
    if args.mapall_user:
        share_options['mapall_user'] = args.mapall_user
    if args.mapall_group:
        share_options['mapall_group'] = args.mapall_group

    # Add security if specified
    if args.security:
        share_options['security'] = args.security

    # Build WebSocket URI
    protocol = 'wss' if args.ssl else 'ws'
    uri = f"{protocol}://{args.host}"
    if args.port:
        uri += f":{args.port}"
    uri += "/api/current"

    print(f"TrueNAS NFS Share Bulk Creator")
    print(f"{'=' * 80}\n")
    print(f"Connecting to: {uri}")

    try:
        with NFSShareCreator(uri, args.api_key, args.username, args.password) as creator:
            stats = creator.bulk_create(
                paths=paths,
                share_options=share_options,
                skip_existing=args.skip_existing,
                dry_run=args.dry_run
            )

            # Print summary
            print(f"{'=' * 80}")
            print(f"Summary:")
            print(f"  Total paths: {stats['total']}")
            print(f"  Shares created: {stats['created']}")
            print(f"  Shares skipped: {stats['skipped']}")
            print(f"  Errors: {stats['errors']}")
            print(f"{'=' * 80}")

            if stats['errors'] > 0:
                sys.exit(1)

    except KeyboardInterrupt:
        print("\n\nOperation cancelled by user.")
        sys.exit(130)
    except Exception as e:
        print(f"\n✗ Fatal error: {e}", file=sys.stderr)
        import traceback
        traceback.print_exc()
        sys.exit(1)


if __name__ == '__main__':
    main()
