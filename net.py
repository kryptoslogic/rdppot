import uuid

import libvirt
import utils

# TODO: Don't hardcode the template, eww.
network_template = """
<network>
  <name>default</name>
  <uuid>0bf306b9-1b8d-4b1b-b44e-e0e94b30e5c1</uuid>
  <forward mode='nat'>
    <nat>
      <port start='1024' end='65535'/>
    </nat>
  </forward>
  <bridge name='virbr0' stp='on' delay='0'/>
  <mac address='52:54:00:6e:db:3f'/>
  <ip address='192.168.122.1' netmask='255.255.255.0'>
    <dhcp>
      <range start='192.168.122.2' end='192.168.122.254'/>
    </dhcp>
  </ip>
</network>
"""

class Net():
    name = ""
    offset = 0
    network = None

    def __init__(self, template, offset):
        self.name = "{}_{}".format(template, offset)
        self.offset = offset

    def get(self, conn):
        try:
            self.network = conn.networkLookupByName(self.name)
        except libvirt.libvirtError as e:
            print("Error getting {}: {}".format(self.name, e))
            return False

        return True

    def create(self, conn):
        # TODO: Do this properly
        template = network_template
        template = template.replace("default", self.name)
        template = template.replace("virbr0", "virbr{}".format(self.offset))

        template = template.replace("0bf306b9-1b8d-4b1b-b44e-e0e94b30e5c1", str(uuid.uuid4()))
        template = template.replace("52:54:00:6e:db:3f", str(utils.randomMAC()))
        base = "192.168.{}".format(5 + self.offset)
        template = template.replace("192.168.122.1", base + ".1")
        template = template.replace("192.168.122.2", base + ".2")
        template = template.replace("192.168.122.254", base + ".254")
        self.network = conn.networkCreateXML(template)

def cleanup_networks(template_name, conn):
    for net in conn.listAllNetworks():
        if net.name().startswith("{}_".format(template_name)):
            print("Found RDP network")
            net.destroy()
