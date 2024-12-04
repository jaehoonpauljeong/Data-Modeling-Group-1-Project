# Data-Modeling-Group-1-Project
This is the Term Project for the Course entitled Data Modeling for Intelligent Networks and Security (ESW7002-41), Fall 2024.


## Automated Security Management in SDN: Hybrid Framework Using OpenFlow and NETCONF/YANG
### Introduction
This project presents a hybrid framework for automated security management in Software-Defined Networking (SDN) environments. It leverages OpenFlow for dynamic flow control and NETCONF/YANG for robust configuration and monitoring of network devices. The primary goal is to enhance network security by automating policy enforcement, detecting anomalies, and ensuring scalability and reliability in SDN architectures.

### Features
- Hybrid Framework: Combines the strengths of OpenFlow and NETCONF/YANG protocols for unified security management.
- Automated Security Policy Enforcement: Automatically applies security policies to SDN controllers and switches.
- Anomaly Detection: Monitors network traffic and identifies unusual patterns or potential threats in real-time.
- Dynamic Flow Control: Utilizes OpenFlow to adjust traffic flows dynamically based on security policies.
- Configuration Management: Uses NETCONF/YANG for device configuration, monitoring, and security policy synchronization.

### Architecture
1. SDN Controller
- Inspect packet_in data and update flow table.
2. Packet Inspector
- Inspect packet and flow table via controller.
- Detect network attack and classify its type.
- Apply appropriate OpenFlow and NETCONF/YANG instruction.
3. YANG DB
- Stores predefined YANG data model mitigating network attack.
4. OpenFlow Module
- Handles flow-based packet forwarding.
- Dynamically applies security policies to traffic flows.
5. NETCONF/YANG Module
- Manages the configuration and monitoring of network devices.
- Ensures the alignment of security policies across the network.

### Technologies Used
- Programming Languages: Python, XML, JSON.
- Protocols:
  - OpenFlow: For dynamic flow management.
  - NETCONF/YANG: For device configuration and policy management.
- SDN Controllers: Ryu.
- Sumulation Environment: Mininet.

### Installation and Steps to Test System
#### Prerequisites
1. Install Python 3.8+ and pip.
2. Install Mininet and ryu.
#### Steps
1. Start controller and generate flowtable at each terminal.
```bash
# Start Controller
sudo python3 packet_in.py
# Start Flowtable generator
sudo python3 flowtable.py
```
2. Start Mininet.
```bash
sudo mn --custom largetopo.py --topo mylargetopo --mac --controller=remote,ip=127.0.0.1,port=6653 --switch=ovsk,protocols=OpenFlow13
```
3. Generate normal traffic by using _traffic_instruction.txt_ or some instructions you want.
4. Start Packet Inspector.
```bash
sudo ./inspect_flow.sh
```
5. Test system by give network attack instruction among _attack_instruction.txt_.



