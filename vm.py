import utils
import xml.etree.ElementTree as ET
import uuid
import subprocess
import pyping
import libvirt
import subprocess

class VM(object):
    name = None
    domain = None
    ip_address = None
    interface = None

    # tcpdump process
    tcpdump = None

    def __init__(self, domain):
        self.domain = domain
        self.name = domain.name()

    def get_ip(self):
        interfaces = self.domain.interfaceAddresses(libvirt.VIR_DOMAIN_INTERFACE_ADDRESSES_SRC_LEASE)
        interface_count = len(interfaces)
        if interface_count != 1:
            print("{} | unable to find correct amount of interfaces: {}!=1".format(self.name, interface_count))
            return False

        interface = interfaces[list(interfaces.keys())[0]]
        ip = interface['addrs'][0]['addr']
        self.ip_address = ip
        self.interface = list(interfaces.keys())[0]
        return True

    def healthcheck(self):
        r = pyping.ping(self.ip_address)
        if r.ret_code != 0:
            print("Unable to ping: {}".format(self.name))
            return False

        # TODO: Check RDP port is up
        return True

    def get_disk_path(self):
        source_xml_str = self.domain.XMLDesc()
        source_xml = ET.fromstring(source_xml_str)

        devices_element = source_xml.find("devices")
        disks = []
        for disk in devices_element.iterfind("disk"):
            disk_device = disk.attrib["device"]
            if disk_device == "disk":
                disks.append(disk)

        if(len(disks)) != 1:
            raise Exception("Incorrect number of disks in the VM")

        disk = disks[0]
        source_file = disk.find("source").attrib["file"]
        return source_file

    def start_pcap(self, pcap_location):
        tcpdump = subprocess.Popen([
            "/usr/sbin/tcpdump",
            "-w",
            "{}/{}.pcap".format(pcap_location, self.name),
            "-U", #no buffering please :)
            "-i",
            self.interface,
            'not stp',
        ])
        self.tcpdump = tcpdump

def copy_disk(source, destination):
    subprocess.run([
        "qemu-img",
        "create",
        "-f",
        "qcow2",
        "-b",
        source,
        destination
    ], check=True)

def clone_vm(source, network_name, destination, path):
    print("Cloning {} to {}".format(source.name(), destination))
    new_name = destination
    new_uuid = uuid.uuid4()
    new_mac = utils.randomMAC()
    new_disk_location = "{}/{}.qcow2".format(path, destination)

    source_xml_str = source.XMLDesc()
    source_xml = ET.fromstring(source_xml_str)
    
    # Update VM name
    name_element = source_xml.find("name")
    name_element.text = new_name

    # Update VM UUID
    uuid_element = source_xml.find("uuid")
    uuid_element.text = str(new_uuid)
    
    # Get devices...
    devices_element = source_xml.find("devices")

    # Disk management
    disks = []
    for disk in devices_element.iterfind("disk"):
        disk_device = disk.attrib["device"]
        # No CDROMs in our pool please :)
        if disk_device == "cdrom":
            devices_element.remove(disk)
        elif disk_device == "disk":
            disks.append(disk)    
        else:
            raise Exception("Unknown disk in template")

    if(len(disks)) != 1:
        raise Exception("Incorrect number of disks in the template VM")

    # Copy disk with the template disk as a backing for copy on write storage
    disk = disks[0]
    source_file = disk.find("source").attrib["file"]
    copy_disk(source_file, new_disk_location)
    disk.find("source").attrib["file"] = new_disk_location

    #Network
    interface_element = devices_element.find("interface")
    mac_element = interface_element.find("source")
    mac_element.attrib["network"] = network_name

    # Mac Address
    interface_element = devices_element.find("interface")
    mac_element = interface_element.find("mac")
    mac_element.attrib["address"] = new_mac

    vm_xml = ET.tostring(source_xml, encoding='utf8', method='xml').decode("utf8")
    return vm_xml
