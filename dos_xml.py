def generate_dos_xml(traffic_threshold, rate_limit_value, connection_rate_limit):
    """
    Generate and print a dynamic XML for DDoS mitigation.
    """
    xml_template = f"""<rpc xmlns="urn:ietf:params:xml:ns:netconf:base:1.0" message-id="101">
  <edit-config>
    <target>
      <running/>
    </target>
    <config>
      <ddos-mitigation xmlns="urn:example:ddos-mitigation">
        <mitigation-policy>
          <policy-id>policy-001</policy-id>
          <policy-name>High Traffic Mitigation</policy-name>
          <target>192.168.192.130/24</target>
          <traffic-threshold>{traffic_threshold}</traffic-threshold>
          <mitigation-actions>
            <rate-limit-value>{rate_limit_value}</rate-limit-value>
            <duration>60</duration>
          </mitigation-actions>
          <detection-parameters>
            <protocol-type>tcp</protocol-type>
            <syn-flag-threshold>200</syn-flag-threshold>
            <connection-rate-limit>{connection_rate_limit}</connection-rate-limit>
          </detection-parameters>
        </mitigation-policy>
      </ddos-mitigation>
    </config>
  </edit-config>
</rpc>"""
    print("[INFO] Generated DDoS Mitigation XML:")
    print(xml_template)

