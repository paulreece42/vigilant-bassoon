#!/usr/bin/env python3
"""
TrueNAS NFS Share Bulk Modification Tool

This script uses the TrueNAS API (v25.04 Fangtooth) to bulk-modify NFS shares.
It can modify networks, hosts, security, permissions, and other settings on shares
matching a path pattern.

Requirements:
    pip install git+https://github.com/truenas/api_client.git

Usage Examples:
    # Remove a CIDR range from all shares matching pattern
    python bulk_modify_nfs_shares.py --host 192.168.1.100 --api-key YOUR_KEY \
        --pattern "/mnt/pool/media*" --remove-network "10.0.0.0/8"

    # Add a host to specific shares
    python bulk_modify_nfs_shares.py --host 192.168.1.100 --username admin --password pass \
        --pattern "/mnt/pool/backups*" --add-host "192.168.1.50"

    # Make all shares read-only
    python bulk_modify_nfs_shares.py --host 192.168.1.100 --api-key YOUR_KEY \
        --pattern "*" --set-ro

    # Enable snapshot exposure on media shares
    python bulk_modify_nfs_shares.py --host 192.168.1.100 --api-key YOUR_KEY \
        --pattern "/mnt/pool/media*" --set-expose-snapshots

    # Add Kerberos security and set maproot
    python bulk_modify_nfs_shares.py --host 192.168.1.100 --api-key YOUR_KEY \
        --pattern "/mnt/secure/*" \
        --add-security KRB5I --add-security KRB5P \
        --set-maproot-user nobody --set-maproot-group nogroup

    # Disable specific shares
    python bulk_modify_nfs_shares.py --host 192.168.1.100 --api-key YOUR_KEY \
        --pattern "/mnt/pool/old*" --disable

    # Preview changes without applying
    python bulk_modify_nfs_shares.py --host 192.168.1.100 --api-key YOUR_KEY \
        --pattern "*" --remove-network "192.0.2.0/24" --dry-run
"""

import argparse
import fnmatch
import sys
from typing import List, Dict, Any, Optional
from truenas_api_client import Client


class NFSShareModifier:
    """Handles bulk modification of TrueNAS NFS shares."""

    def __init__(self, uri: str, api_key: Optional[str] = None,
                 username: Optional[str] = None, password: Optional[str] = None):
        """
        Initialize the NFS share modifier.

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

    def query_shares(self, path_pattern: Optional[str] = None,
                     filter_comment: Optional[str] = None,
                     filter_ro: bool = False,
                     filter_rw: bool = False,
                     filter_enabled: bool = False,
                     filter_disabled: bool = False,
                     filter_networks: Optional[List[str]] = None,
                     filter_hosts: Optional[List[str]] = None,
                     filter_security: Optional[List[str]] = None) -> List[Dict[str, Any]]:
        """
        Query NFS shares, optionally filtering by path pattern and other attributes.

        Args:
            path_pattern: Glob pattern to match share paths (e.g., "/mnt/pool/*")
            filter_comment: Glob pattern to match share comments
            filter_ro: Only match read-only shares
            filter_rw: Only match read-write shares
            filter_enabled: Only match enabled shares
            filter_disabled: Only match disabled shares
            filter_networks: Only match shares containing all these networks
            filter_hosts: Only match shares containing all these hosts
            filter_security: Only match shares with all these security types

        Returns:
            List of NFS share objects
        """
        print("Querying NFS shares...")
        shares = self.client.call("sharing.nfs.query")
        total_shares = len(shares)

        if path_pattern:
            shares = [s for s in shares if fnmatch.fnmatch(s['path'], path_pattern)]

        if filter_comment:
            shares = [s for s in shares if fnmatch.fnmatch(s.get('comment', ''), filter_comment)]

        if filter_ro:
            shares = [s for s in shares if s.get('ro', False)]

        if filter_rw:
            shares = [s for s in shares if not s.get('ro', False)]

        if filter_enabled:
            shares = [s for s in shares if s.get('enabled', True)]

        if filter_disabled:
            shares = [s for s in shares if not s.get('enabled', True)]

        if filter_networks:
            for network in filter_networks:
                shares = [s for s in shares if network in s.get('networks', [])]

        if filter_hosts:
            for host in filter_hosts:
                shares = [s for s in shares if host in s.get('hosts', [])]

        if filter_security:
            for sec in filter_security:
                shares = [s for s in shares if sec in s.get('security', [])]

        print(f"Found {len(shares)} share(s) matching filters (out of {total_shares} total)")

        return shares

    def modify_share_networks(self, share: Dict[str, Any],
                             add_networks: List[str] = None,
                             remove_networks: List[str] = None) -> Dict[str, Any]:
        """
        Modify the networks list for a share.

        Args:
            share: NFS share object
            add_networks: List of CIDR ranges to add
            remove_networks: List of CIDR ranges to remove

        Returns:
            Updated configuration data for the share
        """
        current_networks = set(share.get('networks', []))

        if remove_networks:
            for network in remove_networks:
                current_networks.discard(network)

        if add_networks:
            for network in add_networks:
                current_networks.add(network)

        # TrueNAS limits networks to 42 entries
        if len(current_networks) > 42:
            raise ValueError(f"Share '{share['path']}' would exceed 42 network limit")

        return list(current_networks)

    def modify_share_hosts(self, share: Dict[str, Any],
                          add_hosts: List[str] = None,
                          remove_hosts: List[str] = None) -> Dict[str, Any]:
        """
        Modify the hosts list for a share.

        Args:
            share: NFS share object
            add_hosts: List of hosts/IPs to add
            remove_hosts: List of hosts/IPs to remove

        Returns:
            Updated configuration data for the share
        """
        current_hosts = set(share.get('hosts', []))

        if remove_hosts:
            for host in remove_hosts:
                current_hosts.discard(host)

        if add_hosts:
            for host in add_hosts:
                current_hosts.add(host)

        # TrueNAS limits hosts to 42 entries
        if len(current_hosts) > 42:
            raise ValueError(f"Share '{share['path']}' would exceed 42 host limit")

        return list(current_hosts)

    def update_share(self, share_id: int, update_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Update an NFS share using sharing.nfs.update.

        Args:
            share_id: ID of the share to update
            update_data: Dictionary of fields to update

        Returns:
            Updated share object
        """
        return self.client.call("sharing.nfs.update", share_id, update_data)

    def bulk_modify(self, path_pattern: str = "*",
                   add_networks: List[str] = None,
                   remove_networks: List[str] = None,
                   add_hosts: List[str] = None,
                   remove_hosts: List[str] = None,
                   add_security: List[str] = None,
                   remove_security: List[str] = None,
                   set_comment: str = None,
                   set_ro: bool = None,
                   set_enabled: bool = None,
                   set_expose_snapshots: bool = None,
                   set_maproot_user: str = None,
                   set_maproot_group: str = None,
                   set_mapall_user: str = None,
                   set_mapall_group: str = None,
                   clear_maproot: bool = False,
                   clear_mapall: bool = False,
                   dry_run: bool = False,
                   filter_comment: str = None,
                   filter_ro: bool = False,
                   filter_rw: bool = False,
                   filter_enabled: bool = False,
                   filter_disabled: bool = False,
                   filter_networks: List[str] = None,
                   filter_hosts: List[str] = None,
                   filter_security: List[str] = None) -> Dict[str, Any]:
        """
        Bulk modify NFS shares matching the pattern.

        Args:
            path_pattern: Glob pattern to match share paths
            add_networks: List of CIDR ranges to add
            remove_networks: List of CIDR ranges to remove
            add_hosts: List of hosts/IPs to add
            remove_hosts: List of hosts/IPs to remove
            add_security: List of security schemas to add
            remove_security: List of security schemas to remove
            set_comment: Set comment/description
            set_ro: Set read-only flag
            set_enabled: Set enabled flag
            set_expose_snapshots: Set expose snapshots flag
            set_maproot_user: Set maproot user
            set_maproot_group: Set maproot group
            set_mapall_user: Set mapall user
            set_mapall_group: Set mapall group
            clear_maproot: Clear maproot user and group
            clear_mapall: Clear mapall user and group
            dry_run: If True, show changes without applying them
            filter_comment: Glob pattern to match share comments
            filter_ro: Only match read-only shares
            filter_rw: Only match read-write shares
            filter_enabled: Only match enabled shares
            filter_disabled: Only match disabled shares
            filter_networks: Only match shares containing all these networks
            filter_hosts: Only match shares containing all these hosts
            filter_security: Only match shares with all these security types

        Returns:
            Dictionary with statistics about the operation
        """
        shares = self.query_shares(
            path_pattern=path_pattern,
            filter_comment=filter_comment,
            filter_ro=filter_ro,
            filter_rw=filter_rw,
            filter_enabled=filter_enabled,
            filter_disabled=filter_disabled,
            filter_networks=filter_networks,
            filter_hosts=filter_hosts,
            filter_security=filter_security
        )

        if not shares:
            print("No shares found matching the pattern.")
            return {'matched': 0, 'modified': 0, 'errors': 0}

        stats = {'matched': len(shares), 'modified': 0, 'errors': 0, 'skipped': 0}

        print(f"\n{'=' * 80}")
        print(f"{'DRY RUN - No changes will be made' if dry_run else 'Modifying shares'}")
        print(f"{'=' * 80}\n")

        for share in shares:
            try:
                print(f"Share: {share['path']} (ID: {share['id']})")
                print(f"  Current networks: {share.get('networks', [])}")
                print(f"  Current hosts: {share.get('hosts', [])}")

                update_data = {}
                changes_made = False

                # Modify networks if requested
                if add_networks or remove_networks:
                    new_networks = self.modify_share_networks(
                        share, add_networks, remove_networks
                    )
                    if new_networks != share.get('networks', []):
                        update_data['networks'] = new_networks
                        changes_made = True
                        print(f"  → New networks: {new_networks}")

                # Modify hosts if requested
                if add_hosts or remove_hosts:
                    new_hosts = self.modify_share_hosts(
                        share, add_hosts, remove_hosts
                    )
                    if new_hosts != share.get('hosts', []):
                        update_data['hosts'] = new_hosts
                        changes_made = True
                        print(f"  → New hosts: {new_hosts}")

                # Modify security if requested
                if add_security or remove_security:
                    current_security = set(share.get('security', []))
                    if remove_security:
                        for sec in remove_security:
                            current_security.discard(sec)
                    if add_security:
                        for sec in add_security:
                            current_security.add(sec)
                    new_security = list(current_security)
                    if new_security != share.get('security', []):
                        update_data['security'] = new_security
                        changes_made = True
                        print(f"  → New security: {new_security}")

                # Set comment if requested
                if set_comment is not None:
                    if set_comment != share.get('comment', ''):
                        update_data['comment'] = set_comment
                        changes_made = True
                        print(f"  → New comment: {set_comment}")

                # Set read-only if requested
                if set_ro is not None:
                    if set_ro != share.get('ro', False):
                        update_data['ro'] = set_ro
                        changes_made = True
                        print(f"  → Read-only: {set_ro}")

                # Set enabled if requested
                if set_enabled is not None:
                    if set_enabled != share.get('enabled', True):
                        update_data['enabled'] = set_enabled
                        changes_made = True
                        print(f"  → Enabled: {set_enabled}")

                # Set expose_snapshots if requested
                if set_expose_snapshots is not None:
                    if set_expose_snapshots != share.get('expose_snapshots', False):
                        update_data['expose_snapshots'] = set_expose_snapshots
                        changes_made = True
                        print(f"  → Expose snapshots: {set_expose_snapshots}")

                # Handle maproot clearing or setting
                if clear_maproot:
                    if share.get('maproot_user') or share.get('maproot_group'):
                        update_data['maproot_user'] = None
                        update_data['maproot_group'] = None
                        changes_made = True
                        print(f"  → Cleared maproot user and group")
                else:
                    if set_maproot_user is not None:
                        if set_maproot_user != share.get('maproot_user'):
                            update_data['maproot_user'] = set_maproot_user
                            changes_made = True
                            print(f"  → Maproot user: {set_maproot_user}")
                    if set_maproot_group is not None:
                        if set_maproot_group != share.get('maproot_group'):
                            update_data['maproot_group'] = set_maproot_group
                            changes_made = True
                            print(f"  → Maproot group: {set_maproot_group}")

                # Handle mapall clearing or setting
                if clear_mapall:
                    if share.get('mapall_user') or share.get('mapall_group'):
                        update_data['mapall_user'] = None
                        update_data['mapall_group'] = None
                        changes_made = True
                        print(f"  → Cleared mapall user and group")
                else:
                    if set_mapall_user is not None:
                        if set_mapall_user != share.get('mapall_user'):
                            update_data['mapall_user'] = set_mapall_user
                            changes_made = True
                            print(f"  → Mapall user: {set_mapall_user}")
                    if set_mapall_group is not None:
                        if set_mapall_group != share.get('mapall_group'):
                            update_data['mapall_group'] = set_mapall_group
                            changes_made = True
                            print(f"  → Mapall group: {set_mapall_group}")

                if not changes_made:
                    print(f"  ✓ No changes needed")
                    stats['skipped'] += 1
                elif dry_run:
                    print(f"  [DRY RUN] Would update share")
                    stats['modified'] += 1
                else:
                    # Apply the update
                    updated_share = self.update_share(share['id'], update_data)
                    print(f"  ✓ Share updated successfully")
                    stats['modified'] += 1

                print()

            except Exception as e:
                print(f"  ✗ Error modifying share: {e}")
                stats['errors'] += 1
                print()

        return stats


def main():
    parser = argparse.ArgumentParser(
        description='Bulk modify TrueNAS NFS shares',
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

    # Authentication arguments (mutually exclusive groups)
    auth_group = parser.add_mutually_exclusive_group(required=True)
    auth_group.add_argument('--api-key', help='API key for authentication')
    auth_group.add_argument('--username', help='Username for authentication')
    parser.add_argument('--password', help='Password (required if using --username)')

    # Filter arguments
    parser.add_argument('--pattern', default='*',
                       help='Glob pattern to match share paths (default: "*")')
    parser.add_argument('--filter-comment',
                       help='Glob pattern to match share comments')
    parser.add_argument('--filter-ro', action='store_true',
                       help='Only match read-only shares')
    parser.add_argument('--filter-rw', action='store_true',
                       help='Only match read-write shares')
    parser.add_argument('--filter-enabled', action='store_true',
                       help='Only match enabled shares')
    parser.add_argument('--filter-disabled', action='store_true',
                       help='Only match disabled shares')
    parser.add_argument('--filter-has-network', action='append', dest='filter_networks',
                       help='Only match shares containing this network (repeatable)')
    parser.add_argument('--filter-has-host', action='append', dest='filter_hosts',
                       help='Only match shares containing this host (repeatable)')
    parser.add_argument('--filter-has-security', action='append', dest='filter_security',
                       choices=['SYS', 'KRB5', 'KRB5I', 'KRB5P'],
                       help='Only match shares with this security type (repeatable)')

    # Modification arguments - Networks and Hosts
    parser.add_argument('--add-network', action='append', dest='add_networks',
                       help='Add CIDR range (can be specified multiple times)')
    parser.add_argument('--remove-network', action='append', dest='remove_networks',
                       help='Remove CIDR range (can be specified multiple times)')
    parser.add_argument('--add-host', action='append', dest='add_hosts',
                       help='Add host/IP (can be specified multiple times)')
    parser.add_argument('--remove-host', action='append', dest='remove_hosts',
                       help='Remove host/IP (can be specified multiple times)')

    # Modification arguments - Security
    parser.add_argument('--add-security', action='append', dest='add_security',
                       choices=['SYS', 'KRB5', 'KRB5I', 'KRB5P'],
                       help='Add security schema (can be specified multiple times)')
    parser.add_argument('--remove-security', action='append', dest='remove_security',
                       choices=['SYS', 'KRB5', 'KRB5I', 'KRB5P'],
                       help='Remove security schema (can be specified multiple times)')

    # Modification arguments - String/Boolean fields
    parser.add_argument('--set-comment',
                       help='Set comment/description for all matched shares')
    parser.add_argument('--set-ro', action='store_true', dest='set_ro_true',
                       help='Set shares as read-only')
    parser.add_argument('--set-rw', action='store_true', dest='set_ro_false',
                       help='Set shares as read-write')
    parser.add_argument('--enable', action='store_true', dest='set_enabled_true',
                       help='Enable all matched shares')
    parser.add_argument('--disable', action='store_true', dest='set_enabled_false',
                       help='Disable all matched shares')
    parser.add_argument('--set-expose-snapshots', action='store_true', dest='set_expose_snapshots_true',
                       help='Enable ZFS snapshot directory access')
    parser.add_argument('--unset-expose-snapshots', action='store_true', dest='set_expose_snapshots_false',
                       help='Disable ZFS snapshot directory access')

    # Modification arguments - Maproot
    parser.add_argument('--set-maproot-user',
                       help='Set maproot user (map root client user to this user)')
    parser.add_argument('--set-maproot-group',
                       help='Set maproot group (map root client group to this group)')
    parser.add_argument('--clear-maproot', action='store_true',
                       help='Clear maproot user and group settings')

    # Modification arguments - Mapall
    parser.add_argument('--set-mapall-user',
                       help='Set mapall user (map all client users to this user)')
    parser.add_argument('--set-mapall-group',
                       help='Set mapall group (map all client groups to this group)')
    parser.add_argument('--clear-mapall', action='store_true',
                       help='Clear mapall user and group settings')

    # Options
    parser.add_argument('--dry-run', action='store_true',
                       help='Preview changes without applying them')

    args = parser.parse_args()

    # Validate authentication
    if args.username and not args.password:
        parser.error("--password is required when using --username")

    # Validate mutually exclusive boolean flags
    if args.set_ro_true and args.set_ro_false:
        parser.error("Cannot use both --set-ro and --set-rw")
    if args.set_enabled_true and args.set_enabled_false:
        parser.error("Cannot use both --enable and --disable")
    if args.set_expose_snapshots_true and args.set_expose_snapshots_false:
        parser.error("Cannot use both --set-expose-snapshots and --unset-expose-snapshots")
    if args.filter_ro and args.filter_rw:
        parser.error("Cannot use both --filter-ro and --filter-rw")
    if args.filter_enabled and args.filter_disabled:
        parser.error("Cannot use both --filter-enabled and --filter-disabled")

    # Process boolean flags into actual values
    set_ro = True if args.set_ro_true else (False if args.set_ro_false else None)
    set_enabled = True if args.set_enabled_true else (False if args.set_enabled_false else None)
    set_expose_snapshots = True if args.set_expose_snapshots_true else (False if args.set_expose_snapshots_false else None)

    # Validate that at least one modification was requested
    if not any([
        args.add_networks, args.remove_networks,
        args.add_hosts, args.remove_hosts,
        args.add_security, args.remove_security,
        args.set_comment,
        set_ro is not None,
        set_enabled is not None,
        set_expose_snapshots is not None,
        args.set_maproot_user, args.set_maproot_group, args.clear_maproot,
        args.set_mapall_user, args.set_mapall_group, args.clear_mapall
    ]):
        parser.error("At least one modification action must be specified")

    # Build WebSocket URI
    protocol = 'wss' if args.ssl else 'ws'
    uri = f"{protocol}://{args.host}"
    if args.port:
        uri += f":{args.port}"
    uri += "/api/current"

    print(f"TrueNAS NFS Share Bulk Modifier")
    print(f"{'=' * 80}\n")
    print(f"Connecting to: {uri}")

    try:
        with NFSShareModifier(uri, args.api_key, args.username, args.password) as modifier:
            stats = modifier.bulk_modify(
                path_pattern=args.pattern,
                add_networks=args.add_networks,
                remove_networks=args.remove_networks,
                add_hosts=args.add_hosts,
                remove_hosts=args.remove_hosts,
                add_security=args.add_security,
                remove_security=args.remove_security,
                set_comment=args.set_comment,
                set_ro=set_ro,
                set_enabled=set_enabled,
                set_expose_snapshots=set_expose_snapshots,
                set_maproot_user=args.set_maproot_user,
                set_maproot_group=args.set_maproot_group,
                set_mapall_user=args.set_mapall_user,
                set_mapall_group=args.set_mapall_group,
                clear_maproot=args.clear_maproot,
                clear_mapall=args.clear_mapall,
                dry_run=args.dry_run,
                filter_comment=args.filter_comment,
                filter_ro=args.filter_ro,
                filter_rw=args.filter_rw,
                filter_enabled=args.filter_enabled,
                filter_disabled=args.filter_disabled,
                filter_networks=args.filter_networks,
                filter_hosts=args.filter_hosts,
                filter_security=args.filter_security
            )

            # Print summary
            print(f"{'=' * 80}")
            print(f"Summary:")
            print(f"  Shares matched: {stats['matched']}")
            print(f"  Shares modified: {stats['modified']}")
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
        sys.exit(1)


if __name__ == '__main__':
    main()
