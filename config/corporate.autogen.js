/**
 * "Autogen corp net" scenario — a mid-sized office network: an edge router serving the
 * staff LAN and a core router serving a second department plus a server farm, joined by
 * a transit subnet. Cross-subnet traffic relies on static routes, so it is a good
 * topology for traceroute / routing-table exercises.
 */

registerAutogenScenario(
    "corp-net",
    "Autogen corp net",
    "Two routed sites: staff LAN 192.168.10.0/24, dept LAN 192.168.20.0/24, servers 192.168.30.0/24 over a 172.16.0.0/24 transit.",

    {
        "devices": [
            {
                "type": "router",
                "id": "router-edge",
                "x": 260, "y": 60,
                "interfaces": {
                    "enp0s3": {"ip": "192.168.10.1", "netmask": "255.255.255.0", "switch": "switch-lan-a"},
                    "enp0s8": {"ip": "172.16.0.1", "netmask": "255.255.255.0", "switch": "switch-transit"}
                },
                "routes": [
                    {"destination": "192.168.20.0", "netmask": "255.255.255.0", "iface": "enp0s8", "nexthop": "172.16.0.2"},
                    {"destination": "192.168.30.0", "netmask": "255.255.255.0", "iface": "enp0s8", "nexthop": "172.16.0.2"}
                ]
            },
            {
                "type": "router",
                "id": "router-core",
                "x": 560, "y": 60,
                "interfaces": {
                    "enp0s3": {"ip": "172.16.0.2", "netmask": "255.255.255.0", "switch": "switch-transit"},
                    "enp0s8": {"ip": "192.168.20.1", "netmask": "255.255.255.0", "switch": "switch-lan-b"},
                    "enp0s9": {"ip": "192.168.30.1", "netmask": "255.255.255.0", "switch": "switch-servers"}
                },
                "routes": [
                    {"destination": "192.168.10.0", "netmask": "255.255.255.0", "iface": "enp0s3", "nexthop": "172.16.0.1"}
                ]
            },
            {
                "type": "switch",
                "id": "switch-lan-a",
                "x": 260, "y": 200
            },
            {
                "type": "switch",
                "id": "switch-lan-b",
                "x": 560, "y": 200
            },
            {
                "type": "switch",
                "id": "switch-servers",
                "x": 800, "y": 200
            },
            {
                "type": "switch",
                "id": "switch-transit",
                "x": 410, "y": 135
            },
            {
                "type": "pc",
                "id": "pc-a1",
                "x": 80, "y": 330,
                "interfaces": {"enp0s3": {"ip": "192.168.10.10", "netmask": "255.255.255.0", "switch": "switch-lan-a"}},
                "gateway": "192.168.10.1"
            },
            {
                "type": "pc",
                "id": "pc-a2",
                "x": 200, "y": 330,
                "interfaces": {"enp0s3": {"ip": "192.168.10.11", "netmask": "255.255.255.0", "switch": "switch-lan-a"}},
                "gateway": "192.168.10.1"
            },
            {
                "type": "pc",
                "id": "pc-a3",
                "x": 320, "y": 330,
                "interfaces": {"enp0s3": {"ip": "192.168.10.12", "netmask": "255.255.255.0", "switch": "switch-lan-a"}},
                "gateway": "192.168.10.1"
            },
            {
                "type": "pc",
                "id": "pc-a4",
                "x": 440, "y": 330,
                "interfaces": {"enp0s3": {"ip": "192.168.10.13", "netmask": "255.255.255.0", "switch": "switch-lan-a"}},
                "gateway": "192.168.10.1"
            },
            {
                "type": "pc",
                "id": "pc-b1",
                "x": 500, "y": 330,
                "interfaces": {"enp0s3": {"ip": "192.168.20.10", "netmask": "255.255.255.0", "switch": "switch-lan-b"}},
                "gateway": "192.168.20.1"
            },
            {
                "type": "pc",
                "id": "pc-b2",
                "x": 620, "y": 330,
                "interfaces": {"enp0s3": {"ip": "192.168.20.11", "netmask": "255.255.255.0", "switch": "switch-lan-b"}},
                "gateway": "192.168.20.1"
            },
            {
                "type": "dns-server",
                "id": "dns-server-1",
                "x": 740, "y": 330,
                "interfaces": {"enp0s3": {"ip": "192.168.30.10", "netmask": "255.255.255.0", "switch": "switch-servers"}},
                "gateway": "192.168.30.1"
            },
            {
                "type": "pc",
                "id": "pc-web",
                "x": 860, "y": 330,
                "interfaces": {"enp0s3": {"ip": "192.168.30.20", "netmask": "255.255.255.0", "switch": "switch-servers"}},
                "gateway": "192.168.30.1",
                "packages": ["apache2"]
            }
        ]
    }
);
