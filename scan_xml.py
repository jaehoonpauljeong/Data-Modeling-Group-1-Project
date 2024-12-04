def generate_tcp_scan_mitigation_xml():
    """
    Generate XML for TCP Port Scan mitigation.
    """
    return f"""
<rpc xmlns="urn:ietf:params:xml:ns:netconf:base:1.0" message-id="1">
  <edit-config>
    <target>
      <candidate/>
    </target>
    <config>
      <port-scan-mitigation xmlns="urn:example:port-scan-mitigation">
        <mitigation-policy>
          <policy-id>tcp-scan-policy-001</policy-id>
          <policy-name>TCP-SCAN-MITIGATION</policy-name>
          <target>192.168.192.130/24</target>
          <scan-detection-threshold>30</scan-detection-threshold>
          <observation-window>60</observation-window>
          <mitigation-actions>
            <block-src-ip>
              <blocked-src-ip>
                <ip>192.168.1.100</ip>
                <block-duration>300</block-duration>
              </blocked-src-ip>
            </block-src-ip>
          </mitigation-actions>
          <detection-parameters>
            <scan-type>tcp-syn-scan</scan-type>
            <short-duration-threshold>5</short-duration-threshold>
            <connection-rate-threshold>100</connection-rate-threshold>
            <alert-threshold>50</alert-threshold>
            <geo-location-block>false</geo-location-block>
          </detection-parameters>
        </mitigation-policy>
      </port-scan-mitigation>
    </config>
  </edit-config>
</rpc>
"""

def generate_udp_scan_mitigation_xml():
    """
    Generate XML for UDP Port Scan mitigation.
    """
    return f"""
<rpc xmlns="urn:ietf:params:xml:ns:netconf:base:1.0" message-id="2">
  <edit-config>
    <target>
      <candidate/>
    </target>
    <config>
      <port-scan-mitigation xmlns="urn:example:port-scan-mitigation">
        <mitigation-policy>
          <policy-id>udp-scan-policy-001</policy-id>
          <policy-name>UDP-SCAN-MITIGATION</policy-name>
          <target>192.168.192.130/24</target>
          <scan-detection-threshold>40</scan-detection-threshold>
          <observation-window>120</observation-window>
          <mitigation-actions>
            <rate-limit>
              <rate-limit-value>50</rate-limit-value>
              <duration>180</duration>
            </rate-limit>
          </mitigation-actions>
          <detection-parameters>
            <scan-type>udp-scan</scan-type>
            <short-duration-threshold>3</short-duration-threshold>
            <connection-rate-threshold>150</connection-rate-threshold>
            <alert-threshold>75</alert-threshold>
            <geo-location-block>true</geo-location-block>
          </detection-parameters>
        </mitigation-policy>
      </port-scan-mitigation>
    </config>
  </edit-config>
</rpc>
"""

def get_mitigation_xml(protocol_type):
    """
    Return the appropriate mitigation XML based on the protocol type.
    """
    if protocol_type.lower() == "tcp":
        return generate_tcp_scan_mitigation_xml()
    elif protocol_type.lower() == "udp":
        return generate_udp_scan_mitigation_xml()
    else:
        return f"<error>Unsupported protocol: {protocol_type}</error>"

# Example usage
if __name__ == "__main__":
    protocol = "tcp"  # You can change this to "udp" to test UDP mitigation
    xml_output = get_mitigation_xml(protocol)
    print(xml_output)

