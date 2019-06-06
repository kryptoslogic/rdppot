import argparse
import os
import shutil
import signal
import subprocess
import time
import uuid

import libvirt
import utils
from balancer import Balancer
from net import Net, cleanup_networks
from vm import VM, clone_vm

parser = argparse.ArgumentParser()
parser.add_argument('--reset', help='Reset the VMs before running', action='store_true')
parser.add_argument('--delete', help='Delete the VMs without running', action='store_true')

args = parser.parse_args()

template_name = "winxp_template"

finished_disk_location = "/home/mochafrappuccino/rdp-pot/disks"
analysis_location = "/home/mochafrappuccino/rdp-pot/output"
pcap_location = "/home/mochafrappuccino/rdp-pot/pcaps"

if not os.path.isdir(finished_disk_location):
    raise Exception("finished_disk_location is missing")

if not os.path.isdir(analysis_location):
    raise Exception("analysis_location is missing")

if not os.path.isdir(pcap_location):
    raise Exception("pcap_location is missing")

# No underscore is allowed because we add one and split on it to get the ID
vm_template_name = "rdppot"
pool_size = 16

template_domain = None
vm_pool = {}
networks = {}

conn = libvirt.open()
if conn == None:
    raise Exception("Failed to open hypervisor...")

for domain in conn.listAllDomains():
    name = domain.name()
    if name == template_name:
        print("Found template: {}".format(name))
        template_domain = domain
        continue

    split_name = name.split("_")
    if len(split_name) != 2:
        print("Ignoring VM that does not follow format: {}".format(name))
        continue

    name_template, server_id = split_name
    if name_template == vm_template_name:
        print("Found pool VM: {} | {}".format(name, server_id))
        vm_pool[server_id] = VM(domain)
        continue

# TODO: Verify the VM template state before making VMs from it, check it listens on 3389, etc etc

if args.delete:
    cleanup_networks(vm_template_name, conn)
    for i in list(vm_pool.keys()):
        print("Deleting old VM: {}".format(i))
        vm_pool[i].domain.snapshotCurrent().delete()
        vm_pool[i].domain.destroyFlags(libvirt.VIR_DOMAIN_DESTROY_GRACEFUL)
        del vm_pool[i]
    exit()

# Arg: Reset the VMs before running
if args.reset:
    cleanup_networks(vm_template_name, conn)
    for i in list(vm_pool.keys()):
        print("Resetting old VM: {}".format(i))
        vm_pool[i].domain.snapshotCurrent().delete()
        vm_pool[i].domain.destroyFlags(libvirt.VIR_DOMAIN_DESTROY_GRACEFUL)
        del vm_pool[i]

# TODO: Remove excess networks, atm though I've not seen a bunch of dangaling networks so maybe this is fine
# Create network objects
for i in range(1, pool_size + 1):
    network = Net(vm_template_name, i)
    if not network.get(conn):
        network.create(conn)
    
    networks[i] = network

# Make sure the pool is complete
if len(vm_pool) < pool_size:
    print("Spinning up {} missing pool VMs".format(pool_size - len(vm_pool) + 1))
    for i in range(1, pool_size + 1):
        print("Looking for VM: {}".format(i))
        # VM already exists?
        if str(i) in vm_pool:
            # TODO: Check the VM is happy, not running and revert to snapshot
            continue

        new_vm_name = "{}_{}".format(vm_template_name, i)
        network_name = "{}_{}".format(vm_template_name, i)
        print("VM: {} is missing - creating: {}".format(i, new_vm_name))
        domain_xml = clone_vm(template_domain, network_name, new_vm_name, finished_disk_location)
        domain = conn.createXML(domain_xml)
        vm_pool[i] = VM(domain)

# Prune any excess VMs if we've reduced the pool size
if len(vm_pool) > pool_size:
    for i in list(vm_pool.keys()):
        if int(i) > pool_size:
            print("Killing old VM: {}".format(i))
            vm_pool[i].domain.destroyFlags(libvirt.VIR_DOMAIN_DESTROY_GRACEFUL)
            del vm_pool[i]
            # vm_pool[i].undefine()

# TODO: Add timeout on this working
for i in vm_pool:
    v = vm_pool[i]
    while not v.get_ip():
        time.sleep(1)

    while not v.healthcheck():
        time.sleep(1)

    if v.domain.snapshotNum() == 0:
        print("Creating initial snapshot of {} - {}".format(i, v.name))
        v.domain.snapshotCreateXML("<domainsnapshot><name>base</name></domainsnapshot>")

# Create a base snapshot on each VM and start pcaping
for i in vm_pool:
    v = vm_pool[i]
    v.start_pcap(pcap_location)

print("All VMs look good, let's find some baddies")

def reset_vm_callback(balancer, host_ip, remote_ip, user_data):
    global vm_pool
    print("Resetting {} (user_data: {}, remote_ip: {})".format(host_ip, user_data, remote_ip))
    vm = vm_pool[user_data]
    vm.domain.suspend()
    # TODO: Check it's dead
    vm.tcpdump.send_signal(signal.SIGINT)
    analysis_id = uuid.uuid4()
    os.mkdir("{}/{}".format(analysis_location, analysis_id))
    analysis_folder = "{}/{}".format(analysis_location, analysis_id)
    pcap_output = "{}/pcap.pcap".format(analysis_folder)
    disk_output = "{}/disk.qcow2".format(analysis_folder)
    metadata_output = "{}/metadata".format(analysis_folder)
    with open(metadata_output, 'w') as m:
        m.write("{}".format(remote_ip))
    os.rename("{}/{}.pcap".format(pcap_location, vm.name), pcap_output)
    shutil.copyfile(vm.get_disk_path(), disk_output)
    # TODO: Run YARA/Snort?

    # Run Suricata on the pcap
    subprocess.run([
        "/usr/bin/suricata",
        "-c",
        "/etc/suricata/suricata.yaml",
        "-r",
        pcap_output,
        "-l",
        analysis_folder
    ], check=True)

    snapshot = vm.domain.snapshotCurrent()
    vm.domain.revertToSnapshot(snapshot)

    # Make sure VM responds after resetting it
    while not v.get_ip():
        time.sleep(1)

    while not v.healthcheck():
        time.sleep(1)

    vm.start_pcap(pcap_location)
    print("Done resetting {} - analysis ID is: {}".format(host_ip, analysis_id))
    balancer.add_new_host(host_ip, user_data=user_data)

def new_session_callback(balancer, addr, port, host_ip, user_data):
    #print("New connection from {}:{} to {}".format(addr, port, host_ip))
    pass

balancer = Balancer(reset_vm_callback, new_session_callback, listen_port=3389)
for i in vm_pool:
    v = vm_pool[i]
    print("VM added to pool: {} | {} - {} | {}".format(i, v.name, v.interface, v.ip_address))
    balancer.add_new_host(v.ip_address, user_data=i)

balancer.serve_forever()

# Kill all tcpdumps
for i in vm_pool:
    v = vm_pool[i]
    if v.tcpdump is not None:
        v.tcpdump.kill()
