import subprocess
import json
import time
import re

def get_switches():
    try:
        # Using subprocess to execute the ovs-vsctl command to get a list of all bridges (switches)
        result = subprocess.run(['sudo', 'ovs-vsctl', 'list-br'], capture_output=True, text=True)
        if result.returncode == 0:
            switches = result.stdout.splitlines()
            return [switch.strip() for switch in switches]
        else:
            print("Error: Unable to get list of switches")
            return []
    except Exception as e:
        print(f"Error occurred while getting switches: {str(e)}")
        return []

def get_flows():
    flows_by_switch = {}
    switches = get_switches()  # Get switches dynamically
    try:
        for switch in switches:
            # Using subprocess to execute the ovs-ofctl command to get flow information for each switch with OpenFlow 1.3
            result = subprocess.run(['sudo', 'ovs-ofctl', '-O', 'OpenFlow13', 'dump-flows', switch], capture_output=True, text=True)
            if result.returncode == 0:
                flows = parse_flows(result.stdout)
                flows_by_switch[switch] = flows
            else:
                flows_by_switch[switch] = f'Error: Unable to get flow information for {switch}'
    except Exception as e:
        flows_by_switch['error'] = str(e)
    return flows_by_switch

def parse_flows(raw_data):
    flows = []
    lines = raw_data.splitlines()
    for line in lines:
        if "cookie" in line:  # Filtering lines that contain flow information
            flow_info = parse_flow_line(line.strip())
            # Skip storing flows where actions are directed to the controller
            if flow_info.get('actions') and 'controller' in flow_info['actions'].lower():
                continue
            flows.append(flow_info)
    return flows

def parse_flow_line(flow_line):
    """
    Parse a single line of flow information and extract relevant metrics, excluding timeout values.
    """
    flow_info = {}
    try:
        # Extracting common flow metrics using regular expressions
        flow_info['cookie'] = re.search(r'cookie=([0-9a-fx]+)', flow_line).group(1) if re.search(r'cookie=([0-9a-fx]+)', flow_line) else None
        flow_info['duration'] = re.search(r'duration=([0-9.]+s)', flow_line).group(1) if re.search(r'duration=([0-9.]+s)', flow_line) else None
        flow_info['table'] = re.search(r'table=([0-9]+)', flow_line).group(1) if re.search(r'table=([0-9]+)', flow_line) else None
        flow_info['n_packets'] = re.search(r'n_packets=([0-9]+)', flow_line).group(1) if re.search(r'n_packets=([0-9]+)', flow_line) else None
        flow_info['n_bytes'] = re.search(r'n_bytes=([0-9]+)', flow_line).group(1) if re.search(r'n_bytes=([0-9]+)', flow_line) else None
        flow_info['priority'] = re.search(r'priority=([0-9]+)', flow_line).group(1) if re.search(r'priority=([0-9]+)', flow_line) else None
        flow_info['match'] = re.search(r'(?:, )?(.*?)(?:actions=|$)', flow_line).group(1).strip() if re.search(r'(?:, )?(.*?)(?:actions=|$)', flow_line) else None
        flow_info['actions'] = re.search(r'actions=(.*)', flow_line).group(1).strip() if re.search(r'actions=(.*)', flow_line) else None
        
        # Extract ARP specific fields if present
        if 'arp' in flow_line:
            flow_info['arp_spa'] = re.search(r'arp_spa=([0-9\\.]+)', flow_line).group(1) if re.search(r'arp_spa=([0-9\\.]+)', flow_line) else None
            flow_info['arp_tpa'] = re.search(r'arp_tpa=([0-9\\.]+)', flow_line).group(1) if re.search(r'arp_tpa=([0-9\\.]+)', flow_line) else None
    except Exception as e:
        flow_info['error'] = str(e)
    return flow_info

if __name__ == '__main__':
    last_print_time = 0
    while True:
        try:
            flow_data = get_flows()
            current_time = time.time()
            if current_time - last_print_time >= 5:
                # Print data to terminal
                print(json.dumps(flow_data, indent=2))
                
                # Save data to a file that inspect_flow.py can read
                with open('flow_data.json', 'w') as outfile:
                    json.dump(flow_data, outfile, indent=2)

                last_print_time = current_time
        except Exception as e:
            print(f"Error occurred while getting flow data: {str(e)}")
        time.sleep(3)
