# rdppot

RDP based Honeypot

## What does this actually do

Listens on 3389, on a new connection it'll create a session & assign a virtual machine from a pool to that session. After 300 seconds (default) of the session being opened or 30 second (default) of no activity the connection will be closed and the session will be terminated. We'll store a copy of the disk & a full pcap, additionally we'll run Suricata against the pcap and will save the output with the disk image and the pcap.

## Requirements

- qemu
- libvirt
- qemu
- Python3.7
- Suricata
- tcpdump

### Suricata installation

```shell
wget https://www.openinfosecfoundation.org/download/suricata-4.1.4.tar.gz
tar -xvf suricata-4.1.4.tar.gz
cd suricata-4.1.4
apt-get -y install libpcre3 libpcre3-dbg libpcre3-dev build-essential autoconf automake libtool libpcap-dev libnet1-dev libyaml-0-2 libyaml-dev zlib1g zlib1g-dev libmagic-dev libcap-ng-dev libjansson-dev pkg-config cargo liblz4-dev
cargo install cargo-vendor
./configure --prefix=/usr --sysconfdir=/etc --localstatedir=/var
PATH=$PATH:/root/.cargo/bin ./configure --prefix=/usr --sysconfdir=/etc --localstatedir=/var
make
make install-full
```

## How to use this

- Grab a Windows XP image and create a new VM called `winxp_template`
- Setup RDP on that VM
- Make sure it's accessible
- Run main.py (Probably don't run this as root though, add your user to the libvirtd group & give yourself the permissions for pcaping)

## Support

We're unable to provide support for this repository but will do our best to work with anyone who wishes to contribute to the codebase. The code isn't perfect and probably should not be used in production, it was quickly hacked together to get telemetry about CVE-2019-0708 (Bluekeep) in the wild.

## Potential ideas:

Some things that we thought might be useful but didn't get round to implementing:

- YARA on the disk image
- Snort as well as Suricata?
- TLS decryption
- Testing [Context's RDP replay tool](https://github.com/ctxis/RDP-Replay)
- Making disk images smaller (I don't think this is fully optimized atm & there's probably a method to make them smaller)
