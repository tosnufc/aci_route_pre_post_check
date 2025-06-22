# Cisco ACI Route Comparison Tool

A Python script to compare pre-change and post-change Cisco ACI route files, helping network engineers identify routing differences during maintenance windows or upgrades.



## Prerequisites

- Python 3.6 or higher
- Standard Python libraries (no external dependencies required)

## Installation

1. Clone the repository:
```bash
git clone https://github.com/tosnufc/aci_route_pre_post_check.git
cd aci_route_pre_post_check
```

2. Make the script executable:
```bash
chmod +x route_compare.py
```

## Data Collection 

Before using the script, collect routing information from your ACI fabric using these commands
(routes are just part of these artifact collecting commands):

```bash
# Essential ACI data collection commands:
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
```



## Usage

### Basic Usage

```bash
python route_compare.py pre_change_routes.txt post_change_routes.txt
```

### Command Line Options

```bash
python route_compare.py [OPTIONS] PRE_FILE POST_FILE

Options:
  -h, --help            Show help message and exit
  -o OUTPUT, --output OUTPUT
                        Save detailed report to JSON file
  -q, --quiet           Show only summary (no detailed route listings)
  -d, --debug           Show debug information and parsing details
```

### Examples

1. **Basic comparison with full output**:
```bash
python route_compare.py before_routes.txt after_routes.txt
```

2. **Quiet mode (summary only)**:
```bash
python route_compare.py before_routes.txt after_routes.txt -q
```

3. **Save detailed report to JSON**:
```bash
python route_compare.py before_routes.txt after_routes.txt -o comparison_report.json
```

4. **Debug mode to see parsing details**:
```bash
python route_compare.py before_routes.txt after_routes.txt -d
```
