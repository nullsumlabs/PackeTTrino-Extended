/**
 * "Autogen enterprise" scenario — the largest canvas in the set: three routers in a
 * star around a backbone switch, four edge subnets, a DNS server, an Apache2 intranet
 * host, and a Kerberos showcase (krb5-kdc + an Nginx web server with the
 * "Kerberos Authentication Required" toggle on). Clients seed `/etc/hosts` entries so
 * `intranet.corp.lan` and `secure.corp.lan` resolve to the server farm directly.
 */

registerAutogenScenario(
    "enterprise",
    "Autogen enterprise",
    "Three routers + backbone: west 10.1.10.0/24, east 10.1.20.0/24, branch 10.1.40.0/24, servers 10.1.30.0/24, backbone 10.0.0.0/24. Includes the Kerberos KDC + gated Nginx demo.",

    {
        "devices": [
            {
                "type": "router",
                "id": "router-core",
                "x": 480, "y": 60,
                "interfaces": {
                    "enp0s3": {"ip": "10.0.0.1", "netmask": "255.255.255.0", "switch": "switch-backbone"},
                    "enp0s9": {"ip": "10.1.30.1", "netmask": "255.255.255.0", "switch": "switch-servers"}
                },
                "routes": [
                    {"destination": "10.1.10.0", "netmask": "255.255.255.0", "iface": "enp0s3", "nexthop": "10.0.0.2"},
                    {"destination": "10.1.20.0", "netmask": "255.255.255.0", "iface": "enp0s3", "nexthop": "10.0.0.3"},
                    {"destination": "10.1.40.0", "netmask": "255.255.255.0", "iface": "enp0s3", "nexthop": "10.0.0.4"}
                ]
            },
            {
                "type": "router",
                "id": "router-west",
                "x": 150, "y": 160,
                "interfaces": {
                    "enp0s3": {"ip": "10.1.10.1", "netmask": "255.255.255.0", "switch": "switch-west"},
                    "enp0s8": {"ip": "10.0.0.2", "netmask": "255.255.255.0", "switch": "switch-backbone"}
                },
                "routes": [
                    {"destination": "10.1.20.0", "netmask": "255.255.255.0", "iface": "enp0s8", "nexthop": "10.0.0.3"},
                    {"destination": "10.1.30.0", "netmask": "255.255.255.0", "iface": "enp0s8", "nexthop": "10.0.0.1"},
                    {"destination": "10.1.40.0", "netmask": "255.255.255.0", "iface": "enp0s8", "nexthop": "10.0.0.4"}
                ]
            },
            {
                "type": "router",
                "id": "router-east",
                "x": 480, "y": 160,
                "interfaces": {
                    "enp0s3": {"ip": "10.1.20.1", "netmask": "255.255.255.0", "switch": "switch-east"},
                    "enp0s8": {"ip": "10.0.0.3", "netmask": "255.255.255.0", "switch": "switch-backbone"}
                },
                "routes": [
                    {"destination": "10.1.10.0", "netmask": "255.255.255.0", "iface": "enp0s8", "nexthop": "10.0.0.2"},
                    {"destination": "10.1.30.0", "netmask": "255.255.255.0", "iface": "enp0s8", "nexthop": "10.0.0.1"},
                    {"destination": "10.1.40.0", "netmask": "255.255.255.0", "iface": "enp0s8", "nexthop": "10.0.0.4"}
                ]
            },
            {
                "type": "router",
                "id": "router-branch",
                "x": 800, "y": 160,
                "interfaces": {
                    "enp0s3": {"ip": "10.1.40.1", "netmask": "255.255.255.0", "switch": "switch-branch"},
                    "enp0s8": {"ip": "10.0.0.4", "netmask": "255.255.255.0", "switch": "switch-backbone"}
                },
                "routes": [
                    {"destination": "10.1.10.0", "netmask": "255.255.255.0", "iface": "enp0s8", "nexthop": "10.0.0.2"},
                    {"destination": "10.1.20.0", "netmask": "255.255.255.0", "iface": "enp0s8", "nexthop": "10.0.0.3"},
                    {"destination": "10.1.30.0", "netmask": "255.255.255.0", "iface": "enp0s8", "nexthop": "10.0.0.1"}
                ]
            },
            {
                "type": "switch",
                "id": "switch-backbone",
                "x": 480, "y": 255
            },
            {
                "type": "switch",
                "id": "switch-west",
                "x": 150, "y": 300
            },
            {
                "type": "switch",
                "id": "switch-east",
                "x": 480, "y": 300
            },
            {
                "type": "switch",
                "id": "switch-branch",
                "x": 800, "y": 300
            },
            {
                "type": "switch",
                "id": "switch-servers",
                "x": 960, "y": 255
            },
            {
                "type": "pc",
                "id": "pc-w1",
                "x": 60, "y": 430,
                "interfaces": {"enp0s3": {"ip": "10.1.10.10", "netmask": "255.255.255.0", "switch": "switch-west"}},
                "gateway": "10.1.10.1",
                "files": [
                    {"path": "/etc/hosts", "content": "127.0.0.1 localhost\n10.1.30.20 secure.corp.lan\n10.1.30.21 intranet.corp.lan\n"}
                ]
            },
            {
                "type": "pc",
                "id": "pc-w2",
                "x": 180, "y": 430,
                "interfaces": {"enp0s3": {"ip": "10.1.10.11", "netmask": "255.255.255.0", "switch": "switch-west"}},
                "gateway": "10.1.10.1",
                "files": [
                    {"path": "/etc/hosts", "content": "127.0.0.1 localhost\n10.1.30.20 secure.corp.lan\n10.1.30.21 intranet.corp.lan\n"}
                ]
            },
            {
                "type": "pc",
                "id": "pc-w3",
                "x": 300, "y": 430,
                "interfaces": {"enp0s3": {"ip": "10.1.10.12", "netmask": "255.255.255.0", "switch": "switch-west"}},
                "gateway": "10.1.10.1",
                "files": [
                    {"path": "/etc/hosts", "content": "127.0.0.1 localhost\n10.1.30.20 secure.corp.lan\n10.1.30.21 intranet.corp.lan\n"}
                ]
            },
            {
                "type": "pc",
                "id": "pc-e1",
                "x": 500, "y": 430,
                "interfaces": {"enp0s3": {"ip": "10.1.20.10", "netmask": "255.255.255.0", "switch": "switch-east"}},
                "gateway": "10.1.20.1",
                "files": [
                    {"path": "/etc/hosts", "content": "127.0.0.1 localhost\n10.1.30.20 secure.corp.lan\n10.1.30.21 intranet.corp.lan\n"}
                ]
            },
            {
                "type": "pc",
                "id": "pc-e2",
                "x": 620, "y": 430,
                "interfaces": {"enp0s3": {"ip": "10.1.20.11", "netmask": "255.255.255.0", "switch": "switch-east"}},
                "gateway": "10.1.20.1",
                "files": [
                    {"path": "/etc/hosts", "content": "127.0.0.1 localhost\n10.1.30.20 secure.corp.lan\n10.1.30.21 intranet.corp.lan\n"}
                ]
            },
            {
                "type": "pc",
                "id": "pc-br1",
                "x": 800, "y": 430,
                "interfaces": {"enp0s3": {"ip": "10.1.40.10", "netmask": "255.255.255.0", "switch": "switch-branch"}},
                "gateway": "10.1.40.1",
                "files": [
                    {"path": "/etc/hosts", "content": "127.0.0.1 localhost\n10.1.30.20 secure.corp.lan\n10.1.30.21 intranet.corp.lan\n"}
                ]
            },
            {
                "type": "dns-server",
                "id": "dns-server-1",
                "x": 900, "y": 380,
                "interfaces": {"enp0s3": {"ip": "10.1.30.10", "netmask": "255.255.255.0", "switch": "switch-servers"}},
                "gateway": "10.1.30.1",
                "files": [
                    {"path": "/etc/hosts", "content": "127.0.0.1 localhost\n"}
                ]
            },
            {
                "type": "pc",
                "id": "pc-kdc",
                "x": 1020, "y": 380,
                "interfaces": {"enp0s3": {"ip": "10.1.30.30", "netmask": "255.255.255.0", "switch": "switch-servers"}},
                "gateway": "10.1.30.1",
                "packages": ["krb5-kdc"],
                "attrs": {"kdc": "true", "krb5-realm": "PACKETTRINO.EDU"}
            },
            {
                "type": "pc",
                "id": "pc-websecure",
                "x": 900, "y": 470,
                "interfaces": {"enp0s3": {"ip": "10.1.30.20", "netmask": "255.255.255.0", "switch": "switch-servers"}},
                "gateway": "10.1.30.1",
                "packages": ["nginx"],
                "attrs": {"krb5-required": "true"}
            },
            {
                "type": "pc",
                "id": "pc-intranet",
                "x": 1020, "y": 470,
                "interfaces": {"enp0s3": {"ip": "10.1.30.21", "netmask": "255.255.255.0", "switch": "switch-servers"}},
                "gateway": "10.1.30.1",
                "packages": ["apache2"]
            }
        ]
    }
);
