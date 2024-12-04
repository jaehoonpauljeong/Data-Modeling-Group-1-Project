import json
import time
import subprocess
import os
import sys
from scan_xml import get_mitigation_xml  # Import XML generator function

# Threshold for detecting port scanning attacks
NETWORK_SCAN_FLOW_COUNT_THRESHOLD = 50  # Minimum number of flows for detecting port scan attack
DURATION_THRESHOLD = 5  # Flows with duration < 5 seconds
SCAN_FLOW_PERCENTAGE_THRESHOLD = 0.3  # 30% of flows from the same src_ip indicate a port scan

def execute_command(command):
    """
    Execute a shell command with proper environment variables.
    """
    try:
        env = os.environ.copy()
        subprocess.run(command, shell=True, env=env, check=True)
        print(f"[INFO] Command executed successfully: {command}")
    except subprocess.CalledProcessError as e:
        print(f"[ERROR] Command failed: {e}")

def collect_flow_data():
    """
    Collect flow data from a JSON file.
    """
    try:
        with open('flow_data.json', 'r') as infile:
            return json.load(infile)
    except FileNotFoundError:
        print("[ERROR] Flow data file not found.")
    except json.JSONDecodeError as e:
        print(f"[ERROR] Error decoding JSON from flow data file: {str(e)}")
        print("[ERROR] Error decoding JSON from flow data file.")
    except Exception as e:
        print(f"[ERROR] Unexpected error: {str(e)}")
    return {}

def block_target(flow_data, target_src_ip, protocol_type):
    """
    Block traffic originating from a specific src_ip across all switches.
    """
    print(f"[ALERT] Blocking traffic from src_ip={target_src_ip}")

    switch_list = flow_data.keys()  # Dynamically generate the switch list from flow_data
    for switch in switch_list:
        try:
            # Delete existing flows originating from src_ip
            delete_command = f"sudo ovs-ofctl -O OpenFlow13 del-flows {switch} \"ip,nw_src={target_src_ip}\""
            execute_command(delete_command)

            # Add a rule to drop traffic originating from src_ip
            block_command = f"sudo ovs-ofctl -O OpenFlow13 add-flow {switch} \"priority=100,ip,nw_src={target_src_ip},actions=drop\""
            execute_command(block_command)

        except Exception as e:
            print(f"[ERROR] Failed to block target on switch {switch}: {e}")

    # Generate and print the mitigation XML for the detected attack
    mitigation_xml = get_mitigation_xml(protocol_type)
    print(f"[INFO] Generated Mitigation XML for src_ip={target_src_ip}: {mitigation_xml}")

    # Exit the program after mitigation
    sys.exit(0)

def detect_port_scan(flow_data):
    """
    Detect port scan attacks based on flow data.
    If the number of entries from the same src_ip with duration < 5 seconds is
    more than 30% of the total entries, mark it as a port scan attack.
    """
    try:
        # Track the count of flows grouped by src_ip
        short_duration_flow_count = {}

        # Calculate total flow count by summing all flows from all switches
        total_flow_count = sum(len(flows) for flows in flow_data.values())
        

        for switch, flows in flow_data.items():
            

            for flow in flows:
                # Skip entries with action drop
                actions = flow.get("actions", "")
                if "drop" in actions:
                    continue

                # Extract relevant fields
                match = flow.get("match", "")
                duration_str = flow.get("duration", "0").replace("s", "")
                duration = float(duration_str)
                src_ip = None
                protocol = None

                # Safely parse match fields for src_ip and protocol
                if "nw_src=" in match:
                    src_ip = match.split("nw_src=")[1].split(",")[0]
                if "tcp" in match:
                    protocol = "tcp"
                elif "udp" in match:
                    protocol = "udp"

                # Ignore entries without src_ip or protocol
                if not src_ip or not protocol:
                    continue

                # Count short duration flows per src_ip
                if duration < DURATION_THRESHOLD:
                    if src_ip not in short_duration_flow_count:
                        short_duration_flow_count[src_ip] = {"count": 0, "protocol": protocol}
                    short_duration_flow_count[src_ip]["count"] += 1

        # Detect potential port scan attacks
        for src_ip, data in short_duration_flow_count.items():
            
            count = data["count"]
            protocol = data["protocol"]
            # Check if the count of short duration flows for the src_ip exceeds 30% of the total number of flows and is at least 50 entries
            if total_flow_count > 0 and (count / total_flow_count) >= SCAN_FLOW_PERCENTAGE_THRESHOLD and count >= NETWORK_SCAN_FLOW_COUNT_THRESHOLD:
                print(f"[ALERT] Detected port scan attack from src_ip={src_ip}, flow_count={count}, total_flows={total_flow_count}")
                # Block target based on src_ip
                block_target(flow_data, src_ip, protocol)

    except Exception as e:
        print(f"[ERROR] Unexpected error in port scan detection: {str(e)}")

# Example usage
if __name__ == "__main__":
    while True:
        # Collect data from JSON files
        flow_data = collect_flow_data()

        # Run port scan detection
        detect_port_scan(flow_data)

        time.sleep(3)  # Check every 3 seconds

