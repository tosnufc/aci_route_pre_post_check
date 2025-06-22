#!/usr/bin/env python3
"""
Cisco ACI Routes Comparison Tool

This script compares pre-change and post-change Cisco ACI route files,
using destination subnets from the pre-change file as the base for comparison.
Work best with the following artifacts collector commands:
Leaf-xx-xx# show vrf all
show lldp neighbor
show ip route vrf all
show vpc extended
show port-channel summary
show interface
show interface status
show interface brief
show system internal epm vpc
show system internal epm endpoint all
show system internal epm endpoint all summary
"""

import re
import json
import csv
import argparse
import ipaddress
from typing import Dict, List, Set, Tuple, Optional
from pathlib import Path
from dataclasses import dataclass, asdict
import sys


@dataclass
class Route:
    """Represents a network route with all relevant information"""
    destination: str
    prefix_length: int
    next_hop: Optional[str] = None
    interface: Optional[str] = None
    protocol: Optional[str] = None
    metric: Optional[int] = None
    admin_distance: Optional[int] = None
    raw_line: Optional[str] = None
    
    def __post_init__(self):
        """Normalize the destination subnet and protocol"""
        try:
            # Ensure destination is in CIDR format
            network = ipaddress.ip_network(f"{self.destination}/{self.prefix_length}", strict=False)
            self.destination = str(network.network_address)
        except (ipaddress.AddressValueError, ValueError):
            # Keep original if parsing fails
            pass
        
        # Normalize protocol field by removing trailing punctuation
        if self.protocol:
            self.protocol = self.protocol.rstrip(',]')
        
        # Normalize VLAN interfaces for comparison purposes
        if self.interface and self.interface.lower().startswith('vlan'):
            self.interface = 'vlan'
    
    @property
    def subnet(self) -> str:
        """Return the subnet in CIDR notation"""
        return f"{self.destination}/{self.prefix_length}"
    
    def __str__(self) -> str:
        return f"{self.subnet} via {self.next_hop} [{self.protocol}]"


class RouteParser:
    """Parser for different Cisco ACI route file formats"""
    
    @staticmethod
    def parse_file(file_path: str) -> List[Route]:
        """
        Parse a route file and return a list of Route objects.
        Auto-detects file format based on content.
        """
        file_path = Path(file_path)
        
        if not file_path.exists():
            raise FileNotFoundError(f"Route file not found: {file_path}")
        
        with open(file_path, 'r', encoding='utf-8') as f:
            content = f.read()
        
        # Try different parsing methods
        if content.strip().startswith('{') or content.strip().startswith('['):
            return RouteParser._parse_json(content)
        elif ',' in content and ('Destination' in content or 'Network' in content):
            return RouteParser._parse_csv(file_path)
        else:
            return RouteParser._parse_text(content)
    
    @staticmethod
    def _parse_json(content: str) -> List[Route]:
        """Parse JSON format route files"""
        routes = []
        try:
            data = json.loads(content)
            
            # Handle different JSON structures
            route_data = data
            if isinstance(data, dict):
                # Look for common keys that might contain route information
                for key in ['routes', 'entries', 'data', 'routing_table']:
                    if key in data:
                        route_data = data[key]
                        break
            
            if isinstance(route_data, list):
                for item in route_data:
                    if isinstance(item, dict):
                        route = RouteParser._parse_route_dict(item)
                        if route:
                            # Skip ISIS infrastructure routes
                            if route.protocol and 'isis-isis_infra' in route.protocol:
                                continue
                            routes.append(route)
        except json.JSONDecodeError:
            pass
        
        return routes
    
    @staticmethod
    def _parse_csv(file_path: Path) -> List[Route]:
        """Parse CSV format route files"""
        routes = []
        
        with open(file_path, 'r', encoding='utf-8') as f:
            # Try to detect delimiter
            sample = f.read(1024)
            f.seek(0)
            
            delimiter = ',' if ',' in sample else '\t'
            reader = csv.DictReader(f, delimiter=delimiter)
            
            for row in reader:
                route = RouteParser._parse_route_dict(row)
                if route:
                    # Skip ISIS infrastructure routes
                    if route.protocol and 'isis-isis_infra' in route.protocol:
                        continue
                    routes.append(route)
        
        return routes
    
    @staticmethod
    def _parse_text(content: str) -> List[Route]:
        """Parse text format route files (show ip route output)"""
        routes = []
        lines = content.split('\n')
        current_destination = None
        current_prefix = None
        
        for i, line in enumerate(lines):
            line = line.strip()
            if not line or line.startswith('#') or line.startswith('!'):
                continue
            
            # Skip header lines and VRF separators
            if ('IP Route Table for VRF' in line or 
                "'*' denotes best ucast next-hop" in line or
                "'**' denotes best mcast next-hop" in line or
                "'[x/y]' denotes [preference/metric]" in line or
                "'%<string>' in via output denotes VRF" in line or
                line.startswith('Leaf-') or
                line.startswith('show ') or
                'Total entries displayed:' in line or
                'Capability codes:' in line):
                continue
            
            # Try different text parsing patterns
            route = (RouteParser._parse_cisco_route_line(line) or
                    RouteParser._parse_generic_route_line(line))
            
            if route:
                # Skip ISIS infrastructure routes
                if route.protocol and 'isis-isis_infra' in route.protocol:
                    continue
                # Check if this is a Nexus route header (destination only)
                if route.destination and route.prefix_length and not route.next_hop:
                    current_destination = route.destination
                    current_prefix = route.prefix_length
                    continue
                
                # Check if this is a via line without destination (Nexus format)
                elif route.next_hop and not route.destination and current_destination:
                    route.destination = current_destination
                    route.prefix_length = current_prefix
                    routes.append(route)
                
                # Regular complete route entry
                elif route.destination and route.prefix_length:
                    routes.append(route)
                    current_destination = None
                    current_prefix = None
        
        return routes
    
    @staticmethod
    def _parse_route_dict(data: dict) -> Optional[Route]:
        """Parse a dictionary containing route information"""
        # Common field mappings
        dest_fields = ['destination', 'network', 'dest', 'subnet', 'prefix']
        mask_fields = ['mask', 'prefix_length', 'prefixlen', 'netmask']
        nh_fields = ['next_hop', 'nexthop', 'gateway', 'via']
        int_fields = ['interface', 'intf', 'egress_intf', 'outgoing_interface']
        proto_fields = ['protocol', 'proto', 'source']
        
        destination = None
        prefix_length = None
        
        # Find destination
        for field in dest_fields:
            if field in data and data[field]:
                destination = str(data[field]).strip()
                break
        
        if not destination:
            return None
        
        # Handle CIDR notation
        if '/' in destination:
            try:
                network = ipaddress.ip_network(destination, strict=False)
                destination = str(network.network_address)
                prefix_length = network.prefixlen
            except:
                parts = destination.split('/')
                destination = parts[0]
                try:
                    prefix_length = int(parts[1])
                except:
                    prefix_length = 32
        else:
            # Look for separate mask field
            for field in mask_fields:
                if field in data and data[field] is not None:
                    try:
                        mask_val = str(data[field])
                        if '.' in mask_val:  # Subnet mask format
                            prefix_length = sum(bin(int(x)).count('1') for x in mask_val.split('.'))
                        else:  # Prefix length format
                            prefix_length = int(mask_val)
                        break
                    except:
                        continue
            
            if prefix_length is None:
                prefix_length = 32  # Default for host routes
        
        # Find other fields
        next_hop = None
        for field in nh_fields:
            if field in data and data[field]:
                next_hop = str(data[field]).strip()
                break
        
        interface = None
        for field in int_fields:
            if field in data and data[field]:
                interface = str(data[field]).strip()
                break
        
        protocol = None
        for field in proto_fields:
            if field in data and data[field]:
                protocol = str(data[field]).strip()
                break
        
        # Extract metric and admin distance if available
        metric = data.get('metric') or data.get('cost')
        admin_distance = data.get('admin_distance') or data.get('ad')
        
        return Route(
            destination=destination,
            prefix_length=prefix_length,
            next_hop=next_hop,
            interface=interface,
            protocol=protocol,
            metric=int(metric) if metric and str(metric).isdigit() else None,
            admin_distance=int(admin_distance) if admin_distance and str(admin_distance).isdigit() else None
        )
    
    @staticmethod
    def _parse_cisco_route_line(line: str) -> Optional[Route]:
        """Parse Cisco-style route output line including Nexus format"""
        # Match patterns like:
        # 10.1.1.0/24 via 192.168.1.1, Ethernet1/1
        # O 172.16.0.0/16 [110/20] via 10.0.0.1, 00:30:17, FastEthernet0/0
        # 10.7.248.0/30, ubest/mbest: 2/0
        #     *via 10.249.16.64, eth1/54.12, [115/64], 04w00d, isis-isis_infra, isis-l1-ext
        
        # First check if this is a Nexus route header (destination line)
        nexus_route_header = r'^(?P<dest>\d+\.\d+\.\d+\.\d+)/(?P<prefix>\d+),\s+ubest/mbest:\s*\d+/\d+'
        match = re.match(nexus_route_header, line.strip())
        if match:
            groups = match.groupdict()
            return Route(
                destination=groups['dest'],
                prefix_length=int(groups['prefix']),
                raw_line=line
            )
        
        # Then check for Nexus via lines (next-hop details)
        nexus_via_patterns = [
            # *via 10.249.16.64, eth1/54.12, [115/64], 04w00d, isis-isis_infra, isis-l1-ext
            r'^\s*\*via\s+(?P<nh>\d+\.\d+\.\d+\.\d+)(?:%(?P<vrf>\S+))?,\s*(?P<intf>\S+),\s*\[(?P<ad>\d+)/(?P<metric>\d+)\],\s*(?P<age>\S+),\s*(?P<protocol>\S+)',
            # *via 10.249.248.0%overlay-1, [1/0], 28w06d, bgp-64512, internal, tag 64512
            r'^\s*\*via\s+(?P<nh>\d+\.\d+\.\d+\.\d+)(?:%(?P<vrf>\S+))?,\s*\[(?P<ad>\d+)/(?P<metric>\d+)\],\s*(?P<age>\S+),\s*(?P<protocol>\S+)',
            # *via 192.168.63.253, vlan27, [0/0], 3y34w, local, local
            r'^\s*\*via\s+(?P<nh>\d+\.\d+\.\d+\.\d+),\s*(?P<intf>\S+),\s*\[(?P<ad>\d+)/(?P<metric>\d+)\],\s*(?P<age>\S+),\s*(?P<protocol>\S+)',
        ]
        
        for pattern in nexus_via_patterns:
            match = re.search(pattern, line)
            if match:
                groups = match.groupdict()
                return Route(
                    destination='',  # Will be filled by parent parsing logic
                    prefix_length=0,  # Will be filled by parent parsing logic
                    next_hop=groups.get('nh'),
                    interface=groups.get('intf'),
                    protocol=groups.get('protocol'),
                    metric=int(groups['metric']) if groups.get('metric') else None,
                    admin_distance=int(groups['ad']) if groups.get('ad') else None,
                    raw_line=line
                )
        
        # Legacy patterns for other Cisco formats
        patterns = [
            # Standard format: network/prefix via next_hop, interface
            r'(?P<protocol>[A-Z*+]?\s*)?(?P<dest>\d+\.\d+\.\d+\.\d+)/(?P<prefix>\d+)\s+via\s+(?P<nh>\d+\.\d+\.\d+\.\d+)(?:,\s*(?P<intf>\S+))?',
            # Alternative format with brackets: network/prefix [AD/metric] via next_hop, interface
            r'(?P<protocol>[A-Z*+]?\s*)?(?P<dest>\d+\.\d+\.\d+\.\d+)/(?P<prefix>\d+)\s+\[(?P<ad>\d+)/(?P<metric>\d+)\]\s+via\s+(?P<nh>\d+\.\d+\.\d+\.\d+)(?:,\s*\d+:\d+:\d+,\s*(?P<intf>\S+))?',
            # Simple format: network/prefix next_hop
            r'(?P<dest>\d+\.\d+\.\d+\.\d+)/(?P<prefix>\d+)\s+(?P<nh>\d+\.\d+\.\d+\.\d+)',
        ]
        
        for pattern in patterns:
            match = re.search(pattern, line)
            if match:
                groups = match.groupdict()
                return Route(
                    destination=groups['dest'],
                    prefix_length=int(groups['prefix']),
                    next_hop=groups.get('nh'),
                    interface=groups.get('intf'),
                    protocol=groups.get('protocol', '').strip() or None,
                    metric=int(groups['metric']) if groups.get('metric') else None,
                    admin_distance=int(groups['ad']) if groups.get('ad') else None,
                    raw_line=line
                )
        
        return None
    
    @staticmethod
    def _parse_generic_route_line(line: str) -> Optional[Route]:
        """Parse generic route line formats"""
        # Try to extract IP addresses and infer structure
        ip_pattern = r'\b(?:\d{1,3}\.){3}\d{1,3}(?:/\d{1,2})?\b'
        ips = re.findall(ip_pattern, line)
        
        if len(ips) >= 1:
            dest_ip = ips[0]
            if '/' in dest_ip:
                destination, prefix = dest_ip.split('/')
                prefix_length = int(prefix)
            else:
                destination = dest_ip
                prefix_length = 32
            
            next_hop = ips[1] if len(ips) > 1 else None
            
            return Route(
                destination=destination,
                prefix_length=prefix_length,
                next_hop=next_hop,
                raw_line=line
            )
        
        return None


class RouteComparator:
    """Compare pre-change and post-change route files"""
    
    def __init__(self, pre_routes: List[Route], post_routes: List[Route]):
        # Handle multiple routes to same destination by keeping all routes
        # but create a mapping for comparison purposes
        self.all_pre_routes = pre_routes
        self.all_post_routes = post_routes
        
        # Create dictionaries with subnet as key, but keep track of all routes
        # In case of multiple routes to same destination, keep the first one for comparison
        # but store all routes for detailed analysis
        self.pre_routes = {}
        self.pre_route_details = {}
        for route in pre_routes:
            if route.subnet not in self.pre_routes:
                self.pre_routes[route.subnet] = route
                self.pre_route_details[route.subnet] = [route]
            else:
                self.pre_route_details[route.subnet].append(route)
        
        self.post_routes = {}
        self.post_route_details = {}
        for route in post_routes:
            if route.subnet not in self.post_routes:
                self.post_routes[route.subnet] = route
                self.post_route_details[route.subnet] = [route]
            else:
                self.post_route_details[route.subnet].append(route)
        
        self.pre_subnets = set(self.pre_routes.keys())
        self.post_subnets = set(self.post_routes.keys())
    
    def compare(self) -> Dict:
        """Perform comprehensive comparison"""
        # Use pre-change subnets as the base
        base_subnets = self.pre_subnets
        
        # Categorize changes
        missing_routes = []  # Routes in pre but not in post
        added_routes = []    # Routes in post but not in pre
        changed_routes = []  # Routes that exist in both but with differences
        unchanged_routes = [] # Routes that are identical
        
        # Check each subnet from pre-change file
        for subnet in base_subnets:
            pre_route = self.pre_routes[subnet]
            
            if subnet not in self.post_routes:
                missing_routes.append(pre_route)
            else:
                post_route = self.post_routes[subnet]
                if self._routes_equal(pre_route, post_route):
                    unchanged_routes.append(pre_route)
                else:
                    changed_routes.append({
                        'subnet': subnet,
                        'pre': pre_route,
                        'post': post_route,
                        'changes': self._get_route_differences(pre_route, post_route)
                    })
        
        # Find routes that were added (in post but not in pre)
        for subnet in self.post_subnets - self.pre_subnets:
            added_routes.append(self.post_routes[subnet])
        
        return {
            'summary': {
                'total_pre_routes': len(self.pre_routes),
                'total_post_routes': len(self.post_routes),
                'missing_routes': len(missing_routes),
                'added_routes': len(added_routes),
                'changed_routes': len(changed_routes),
                'unchanged_routes': len(unchanged_routes)
            },
            'missing_routes': missing_routes,
            'added_routes': added_routes,
            'changed_routes': changed_routes,
            'unchanged_routes': unchanged_routes
        }
    
    def _routes_equal(self, route1: Route, route2: Route) -> bool:
        """Check if two routes are functionally equal"""
        # For routes with same destination, we need to compare all next-hops
        subnet = route1.subnet
        if subnet in self.pre_route_details and subnet in self.post_route_details:
            pre_routes = self.pre_route_details[subnet]
            post_routes = self.post_route_details[subnet]
            
            # Compare the number of routes to the same destination
            if len(pre_routes) != len(post_routes):
                return False
            
            # Create sets of next-hops for comparison
            pre_nexthops = set()
            post_nexthops = set()
            
            for route in pre_routes:
                nh_key = (route.next_hop, route.interface, route.protocol)
                pre_nexthops.add(nh_key)
            
            for route in post_routes:
                nh_key = (route.next_hop, route.interface, route.protocol)
                post_nexthops.add(nh_key)
            
            return pre_nexthops == post_nexthops
        
        # Fallback to simple comparison
        return (route1.destination == route2.destination and
                route1.prefix_length == route2.prefix_length and
                route1.next_hop == route2.next_hop and
                route1.interface == route2.interface and
                route1.protocol == route2.protocol)
    
    def _get_route_differences(self, pre_route: Route, post_route: Route) -> List[str]:
        """Get list of differences between two routes"""
        differences = []
        subnet = pre_route.subnet
        
        # For routes with multiple next-hops, show detailed differences
        if subnet in self.pre_route_details and subnet in self.post_route_details:
            pre_routes = self.pre_route_details[subnet]
            post_routes = self.post_route_details[subnet]
            
            if len(pre_routes) != len(post_routes):
                differences.append(f"Number of paths: {len(pre_routes)} -> {len(post_routes)}")
            
            # Create sets for comparison
            pre_nexthops = set()
            post_nexthops = set()
            
            for route in pre_routes:
                nh_key = (route.next_hop, route.interface, route.protocol)
                pre_nexthops.add(nh_key)
            
            for route in post_routes:
                nh_key = (route.next_hop, route.interface, route.protocol)
                post_nexthops.add(nh_key)
            
            # Find removed and added next-hops
            removed_nexthops = pre_nexthops - post_nexthops
            added_nexthops = post_nexthops - pre_nexthops
            
            if removed_nexthops:
                for nh, intf, proto in removed_nexthops:
                    intf_str = f" on {intf}" if intf else ""
                    differences.append(f"Removed path: via {nh} [{proto}]{intf_str}")
            
            if added_nexthops:
                for nh, intf, proto in added_nexthops:
                    intf_str = f" on {intf}" if intf else ""
                    differences.append(f"Added path: via {nh} [{proto}]{intf_str}")
            
            return differences
        
        # Fallback to simple comparison
        if pre_route.next_hop != post_route.next_hop:
            differences.append(f"Next hop: {pre_route.next_hop} -> {post_route.next_hop}")
        
        if pre_route.interface != post_route.interface:
            differences.append(f"Interface: {pre_route.interface} -> {post_route.interface}")
        
        if pre_route.protocol != post_route.protocol:
            differences.append(f"Protocol: {pre_route.protocol} -> {post_route.protocol}")
        
        if pre_route.metric != post_route.metric:
            differences.append(f"Metric: {pre_route.metric} -> {post_route.metric}")
        
        if pre_route.admin_distance != post_route.admin_distance:
            differences.append(f"Admin distance: {pre_route.admin_distance} -> {post_route.admin_distance}")
        
        return differences


def print_comparison_report(comparison: Dict):
    """Print a detailed comparison report"""
    print("=" * 80)
    print("CISCO ACI ROUTES COMPARISON REPORT")
    print("=" * 80)
    
    summary = comparison['summary']
    print(f"\nSUMMARY:")
    print(f"  Pre-change routes:  {summary['total_pre_routes']}")
    print(f"  Post-change routes: {summary['total_post_routes']}")
    print(f"  Missing routes:     {summary['missing_routes']}")
    print(f"  Added routes:       {summary['added_routes']}")
    print(f"  Changed routes:     {summary['changed_routes']}")
    print(f"  Unchanged routes:   {summary['unchanged_routes']}")
    
    # Missing routes
    if comparison['missing_routes']:
        print(f"\nMISSING ROUTES ({len(comparison['missing_routes'])}):")
        print("-" * 60)
        for route in comparison['missing_routes']:
            print(f"  {route.subnet:<20} via {route.next_hop or 'N/A':<15} [{route.protocol or 'N/A'}]")
    
    # Added routes
    if comparison['added_routes']:
        print(f"\nADDED ROUTES ({len(comparison['added_routes'])}):")
        print("-" * 60)
        for route in comparison['added_routes']:
            print(f"  {route.subnet:<20} via {route.next_hop or 'N/A':<15} [{route.protocol or 'N/A'}]")
    
    # Changed routes
    if comparison['changed_routes']:
        print(f"\nCHANGED ROUTES ({len(comparison['changed_routes'])}):")
        print("-" * 60)
        for change in comparison['changed_routes']:
            print(f"  {change['subnet']}:")
            for diff in change['changes']:
                print(f"    - {diff}")
            print()


def save_comparison_report(comparison: Dict, output_file: str):
    """Save comparison report to JSON file"""
    # Convert Route objects to dictionaries for JSON serialization
    def route_to_dict(route):
        return {k: v for k, v in asdict(route).items() if k != 'raw_line'}
    
    json_data = {
        'summary': comparison['summary'],
        'missing_routes': [route_to_dict(route) for route in comparison['missing_routes']],
        'added_routes': [route_to_dict(route) for route in comparison['added_routes']],
        'changed_routes': [
            {
                'subnet': change['subnet'],
                'pre': route_to_dict(change['pre']),
                'post': route_to_dict(change['post']),
                'changes': change['changes']
            }
            for change in comparison['changed_routes']
        ],
        'unchanged_routes': [route_to_dict(route) for route in comparison['unchanged_routes']]
    }
    
    with open(output_file, 'w') as f:
        json.dump(json_data, f, indent=2)
    
    print(f"\nDetailed report saved to: {output_file}")


def main():
    parser = argparse.ArgumentParser(
        description="Compare pre-change and post-change Cisco ACI route files"
    )
    parser.add_argument('pre_file', help='Pre-change routes file')
    parser.add_argument('post_file', help='Post-change routes file')
    parser.add_argument('-o', '--output', help='Output JSON report file')
    parser.add_argument('-q', '--quiet', action='store_true', help='Only show summary')
    parser.add_argument('-d', '--debug', action='store_true', help='Show debug information')
    
    args = parser.parse_args()
    
    try:
        # Parse route files
        print(f"Parsing pre-change routes from: {args.pre_file}")
        pre_routes = RouteParser.parse_file(args.pre_file)
        print(f"Found {len(pre_routes)} pre-change routes")
        
        print(f"Parsing post-change routes from: {args.post_file}")
        post_routes = RouteParser.parse_file(args.post_file)
        print(f"Found {len(post_routes)} post-change routes")
        
        if not pre_routes:
            print("WARNING: No routes found in pre-change file")
        if not post_routes:
            print("WARNING: No routes found in post-change file")
        
        # Debug information
        if args.debug:
            print(f"\nDEBUG: First 5 pre-change routes:")
            for i, route in enumerate(pre_routes[:5]):
                print(f"  {i+1}: {route.subnet} -> {route.next_hop} [{route.protocol}]")
            print(f"\nDEBUG: First 5 post-change routes:")
            for i, route in enumerate(post_routes[:5]):
                print(f"  {i+1}: {route.subnet} -> {route.next_hop} [{route.protocol}]")
        
        # Perform comparison
        comparator = RouteComparator(pre_routes, post_routes)
        comparison = comparator.compare()
        
        # Debug comparison details
        if args.debug:
            print(f"\nDEBUG: Unique pre-change subnets: {len(comparator.pre_subnets)}")
            print(f"DEBUG: Unique post-change subnets: {len(comparator.post_subnets)}")
            print(f"DEBUG: Total pre-change routes parsed: {len(pre_routes)}")
            print(f"DEBUG: Total post-change routes parsed: {len(post_routes)}")
            
            # Show some examples of missing routes if any
            missing_subnets = comparator.pre_subnets - comparator.post_subnets
            if missing_subnets:
                print(f"DEBUG: Examples of missing subnets:")
                for subnet in list(missing_subnets)[:5]:
                    route = comparator.pre_routes[subnet]
                    print(f"  {subnet} -> {route.next_hop} [{route.protocol}]")
        
        # Print report
        if not args.quiet:
            print_comparison_report(comparison)
        else:
            summary = comparison['summary']
            print(f"Missing: {summary['missing_routes']}, "
                  f"Added: {summary['added_routes']}, "
                  f"Changed: {summary['changed_routes']}")
        
        # Save detailed report if requested
        if args.output:
            save_comparison_report(comparison, args.output)
    
    except FileNotFoundError as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)
    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
