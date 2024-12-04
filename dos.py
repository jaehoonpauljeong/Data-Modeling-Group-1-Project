import json
import time
import subprocess
import os
import sys
from dos_xml import generate_dos_xml  # Import the XML generation function

# Threshold for comparing flow's ratio against overall averages
FLOW_RATIO_THRESHOLD = 20  # Ratio threshold for detecting high traffic flows

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

def collect_packet_in_data():
    """
    Collect packet_in data from a JSON file.
    """
    try:
        with open('packet_in_data.json', 'r') as infile:
            return json.load(infile)
    except FileNotFoundError:
        print("[ERROR] Packet in data file not found.")
    except json.JSONDecodeError:
        print("[ERROR] Error decoding JSON from packet in data file.")
    except Exception as e:
        print(f"[ERROR] Unexpected error: {str(e)}")
    return []

def block_attacker(flow_data, attacker_ip, switch, src_ip, dst_ip, flow_n_packets_per_duration, flow_n_bytes_per_duration):
    """
    Block traffic from the attacker's IP address on all switches and
    delete existing flows with nw_src = attacker_ip.
    """
    print(
        f"[ALERT] DDoS-related flow confirmed on switch {switch}! "
        f"src_ip={src_ip}, dst_ip={dst_ip}, "
        f"n_packets/duration={flow_n_packets_per_duration:.2f}, "
        f"n_bytes/duration={flow_n_bytes_per_duration:.2f}"
    )

    print(
        f"[ALERT] Attacker identified! "
        f"src_ip={attacker_ip} sent SYN to dst_ip={dst_ip}"
    )

    switch_list = flow_data.keys()  # Dynamically generate the switch list from flow_data
    for switch in switch_list:
        try:
            # Delete existing flows with nw_src = attacker_ip
            delete_command = f"sudo ovs-ofctl -O OpenFlow13 del-flows {switch} \"ip,nw_src={attacker_ip}\""
            execute_command(delete_command)
            # Add a rule to drop traffic from the attacker's IP
            block_command = f"sudo ovs-ofctl -O OpenFlow13 add-flow {switch} \"priority=100,ip,nw_src={attacker_ip},actions=drop\""
            execute_command(block_command)

        except Exception as e:
            print(f"[ERROR] Failed to block attacker on switch {switch}: {e}")

    # Generate and print the dynamic XML using the `dos_xml` module
    generate_dos_xml(
        traffic_threshold=int(flow_n_bytes_per_duration),
        rate_limit_value=flow_n_packets_per_duration // 2,
        connection_rate_limit=FLOW_RATIO_THRESHOLD
    )
    sys.exit(0)
    

def detect_ddos(flow_data, packet_in_data):
    """
    Detect potential DDoS flows based on flow data and packet_in data.
    """
    try:
        # Initialize variables for total calculations
        total_n_packets = 0
        total_n_bytes = 0
        total_duration = 0
        total_flows = 0

        # Calculate total n_packets, n_bytes, and total duration for all flows
        for switch, flows in flow_data.items():
            for flow in flows:
                actions = flow.get("actions", "").strip().lower()              
                # Skip flows with action=drop
                if "drop" in actions:                    
                    continue  # Ignore drop rules

                n_packets = int(flow.get("n_packets", "0"))
                n_bytes = int(flow.get("n_bytes", "0"))
                duration = float(flow.get("duration", "0s").replace("s", ""))  # Convert to float

                total_n_packets += n_packets
                total_n_bytes += n_bytes
                total_duration += duration
                total_flows += 1

        # Calculate the overall averages for n_packets/duration and n_bytes/duration
        if total_flows > 0 and total_duration > 0:
            avg_n_packets_per_duration = total_n_packets / total_duration
            avg_n_bytes_per_duration = total_n_bytes / total_duration

            print(f"[INFO] Average n_packets per duration: {avg_n_packets_per_duration:.2f}")
            print(f"[INFO] Average n_bytes per duration: {avg_n_bytes_per_duration:.2f}")

        # Analyze each flow and compare with the average
        for switch, flows in flow_data.items():
            for flow in flows:
                actions = flow.get("actions", "").strip().lower()

                # Skip flows with action=drop
                if "drop" in actions:                    
                    continue  # Ignore drop rules

                n_packets = int(flow.get("n_packets", "0"))
                n_bytes = int(flow.get("n_bytes", "0"))
                duration = float(flow.get("duration", "0s").replace("s", ""))  # Convert to float

                if duration > 0:
                    flow_n_packets_per_duration = n_packets / duration
                    flow_n_bytes_per_duration = n_bytes / duration

                    # Extract src_ip and dst_ip from the match field
                    match = flow.get("match", "")
                    src_ip = match.split("nw_src=")[1].split(",")[0] if "nw_src=" in match else "Unknown"
                    dst_ip = match.split("nw_dst=")[1].split(",")[0] if "nw_dst=" in match else "Unknown"

                    # Check if the flow's ratio is higher than the threshold compared to overall average
                    if (
                        flow_n_packets_per_duration > avg_n_packets_per_duration * FLOW_RATIO_THRESHOLD
                        or flow_n_bytes_per_duration > avg_n_bytes_per_duration * FLOW_RATIO_THRESHOLD
                    ):
                        # Check packet_in data to identify the attacker with SYN packets
                        for packet in packet_in_data:
                            packet_src_ip = packet.get("src_ip", "Unknown")
                            packet_dst_ip = packet.get("dst_ip", "Unknown")
                            tcp_flags = packet.get("tcp_flags", [])

                            # Match src_ip and dst_ip with SYN packets
                            if (
                                packet_src_ip == src_ip
                                and packet_dst_ip == dst_ip
                                and "SYN" in tcp_flags
                            ):
                                # Block attacker on all switches
                                block_attacker(
                                    flow_data, packet_src_ip, switch, src_ip, dst_ip, 
                                    flow_n_packets_per_duration, flow_n_bytes_per_duration
                                )
                                break

    except Exception as e:
        print(f"[ERROR] Unexpected error in DDoS detection: {str(e)}")

if __name__ == '__main__':
    while True:
        # Collect data from JSON files
        flow_data = collect_flow_data()
        packet_in_data = collect_packet_in_data()

        # Run DDoS detection
        detect_ddos(flow_data, packet_in_data)

        time.sleep(3)  # Check every 3 seconds

