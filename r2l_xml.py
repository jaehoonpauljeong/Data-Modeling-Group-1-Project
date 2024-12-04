def generate_ssh_mitigation_xml(dst_port):
    """
    Generate XML for SSH mitigation.
    """
    return f"""
<rpc xmlns="urn:ietf:params:xml:ns:netconf:base:1.0" message-id="1">
  <edit-config>
    <target>
      <candidate/>
    </target>
    <config>
      <brute-force-mitigation xmlns="urn:example:brute-force-mitigation">
        <mitigation-policy>
          <policy-id>ssh-policy-001</policy-id>
          <policy-name>SSH-MITIGATION</policy-name>
          <target>192.168.192.130/24</target>
          <authentication-failure-threshold>10</authentication-failure-threshold>
          <observation-window>60</observation-window>
          <mitigation-actions>
            <block-src-ip>
              <blocked-src-ip>
                <ip>192.168.1.100</ip>
                <block-duration>30</block-duration>
              </blocked-src-ip>
            </block-src-ip>
          </mitigation-actions>
          <detection-parameters>
            <protocol-type>ssh</protocol-type>
            <failed-login-threshold>10</failed-login-threshold>
            <connection-rate-threshold>5</connection-rate-threshold>
          </detection-parameters>
        </mitigation-policy>
      </brute-force-mitigation>
    </config>
  </edit-config>
</rpc>
"""

def generate_ftp_mitigation_xml(dst_port):
    """
    Generate XML for FTP mitigation.
    """
    return f"""
<rpc xmlns="urn:ietf:params:xml:ns:netconf:base:1.0" message-id="2">
  <edit-config>
    <target>
      <candidate/>
    </target>
    <config>
      <brute-force-mitigation xmlns="urn:example:brute-force-mitigation">
        <mitigation-policy>
          <policy-id>ftp-policy-001</policy-id>
          <policy-name>FTP-MITIGATION</policy-name>
          <target>192.168.192.130/24</target>
          <authentication-failure-threshold>15</authentication-failure-threshold>
          <observation-window>90</observation-window>
          <mitigation-actions>
            <drop-traffic>
              <drop-duration>45</drop-duration>
            </drop-traffic>
          </mitigation-actions>
          <detection-parameters>
            <protocol-type>ftp</protocol-type>
            <failed-login-threshold>15</failed-login-threshold>
            <connection-rate-threshold>10</connection-rate-threshold>
          </detection-parameters>
        </mitigation-policy>
      </brute-force-mitigation>
    </config>
  </edit-config>
</rpc>
"""

def generate_http_mitigation_xml(dst_port):
    """
    Generate XML for HTTP mitigation.
    """
    return f"""
<rpc xmlns="urn:ietf:params:xml:ns:netconf:base:1.0" message-id="3">
  <edit-config>
    <target>
      <candidate/>
    </target>
    <config>
      <brute-force-mitigation xmlns="urn:example:brute-force-mitigation">
        <mitigation-policy>
          <policy-id>http-policy-001</policy-id>
          <policy-name>HTTP-MITIGATION</policy-name>
          <target>192.168.192.130/24</target>
          <authentication-failure-threshold>20</authentication-failure-threshold>
          <observation-window>120</observation-window>
          <mitigation-actions>
            <rate-limit>
              <rate-limit-value>100</rate-limit-value>
              <duration>60</duration>
            </rate-limit>
          </mitigation-actions>
          <detection-parameters>
            <protocol-type>http</protocol-type>
            <failed-login-threshold>15</failed-login-threshold>
            <connection-rate-threshold>20</connection-rate-threshold>
          </detection-parameters>
        </mitigation-policy>
      </brute-force-mitigation>
    </config>
  </edit-config>
</rpc>
"""

def get_mitigation_xml(dst_port):
    """
    Return the appropriate mitigation XML based on the destination port.
    """
    if dst_port == "22":
        return generate_ssh_mitigation_xml(dst_port)
    elif dst_port == "21":
        return generate_ftp_mitigation_xml(dst_port)
    elif dst_port == "80" or dst_port == "443":
        return generate_http_mitigation_xml(dst_port)
    else:
        return f"<error>Unsupported port: {dst_port}</error>"

