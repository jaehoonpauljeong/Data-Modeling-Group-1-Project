import json
import time
import subprocess
import os
import sys
from r2l_xml import get_mitigation_xml  # Import XML generator function


# Threshold for detecting brute force attacks
DURATION_THRESHOLD = 5  # Flows with duration < 5 seconds
BRUTE_FORCE_FLOW_COUNT_THRESHOLD = 50  # Number of flows targeting the same dst_ip and dst_port

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
    except json.JSONDecodeError:
        print("[ERROR] Error decoding JSON from flow data file.")
    except Exception as e:
        print(f"[ERROR] Unexpected error: {str(e)}")
    return {}

def block_target(flow_data, target_nw_dst, target_tp_dst):
    """
    Block traffic targeting a specific nw_dst (destination IP) and tp_dst (destination port)
    across all switches.
    """
    print(f"[ALERT] Blocking traffic to nw_dst={target_nw_dst}, tp_dst={target_tp_dst}")

    switch_list = flow_data.keys()  # Dynamically generate the switch list from flow_data
    for switch in switch_list:
        try:
            # Delete existing flows targeting nw_dst and tp_dst
            delete_command = f"sudo ovs-ofctl -O OpenFlow13 del-flows {switch} \"tcp,nw_dst={target_nw_dst},tp_dst={target_tp_dst}\""
            execute_command(delete_command)

            # Add a rule to drop traffic targeting nw_dst and tp_dst
            block_command = f"sudo ovs-ofctl -O OpenFlow13 add-flow {switch} \"priority=100,tcp,nw_dst={target_nw_dst},tp_dst={target_tp_dst},actions=drop\""
            execute_command(block_command)

        except Exception as e:
            print(f"[ERROR] Failed to block target on switch {switch}: {e}")

    # Generate and print the mitigation XML for the detected port
    mitigation_xml = get_mitigation_xml(target_tp_dst)
    print(f"[INFO] Generated Mitigation XML for tp_dst={target_tp_dst}:\n{mitigation_xml}")

    # Exit the program after mitigation
    sys.exit(0)


def detect_brute_force(flow_data):
    """
    Detect brute force attacks based on flow data.
    If the number of entries with the same dst_ip and dst_port exceeds the threshold
    and constitutes at least 30% of the total entries, mark it as an attack.
    """
    try:
        # Track the count of entries grouped by (nw_dst, tp_dst)
        target_entry_count = {}
        total_entries = 0  # Count of total flow entries

        for switch, flows in flow_data.items():
            for flow in flows:
                total_entries += 1  # Increment total entry count
                # Extract relevant fields
                match = flow.get("match", "")
                nw_dst = None
                tp_dst = None

                # Safely parse match fields for nw_dst and tp_dst
                if "nw_dst=" in match:
                    nw_dst = match.split("nw_dst=")[1].split(",")[0]
                if "tp_dst=" in match:
                    tp_dst = match.split("tp_dst=")[1].split(",")[0]

                # Ignore entries without nw_dst and tp_dst
                if not nw_dst or not tp_dst:
                    continue

                # Group by (nw_dst, tp_dst) and count occurrences
                key = (nw_dst, tp_dst)
                if key not in target_entry_count:
                    target_entry_count[key] = 0
                target_entry_count[key] += 1

        # Detect potential brute force attacks
        for (nw_dst, tp_dst), entry_count in target_entry_count.items():
            entry_percentage = (entry_count / total_entries) * 100 if total_entries > 0 else 0
            if entry_count > BRUTE_FORCE_FLOW_COUNT_THRESHOLD and entry_percentage >= 30:
                print(f"[ALERT] Detected brute force attack on nw_dst={nw_dst}, tp_dst={tp_dst}, "
                      f"entry_count={entry_count}, entry_percentage={entry_percentage:.2f}%")
                # Block target based on nw_dst and tp_dst
                block_target(flow_data, nw_dst, tp_dst)

    except Exception as e:
        print(f"[ERROR] Unexpected error in brute force detection: {str(e)}")


if __name__ == '__main__':
    while True:
        # Collect data from JSON files
        flow_data = collect_flow_data()

        # Run brute force detection
        detect_brute_force(flow_data)

        time.sleep(3)  # Check every 3 seconds

