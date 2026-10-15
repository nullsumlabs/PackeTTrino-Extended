/**
 * "Autogen homelab" scenario — a single-family home network: one gateway router, one
 * LAN switch, three household PCs, a dedicated DNS (bind9) server, and a NAS box
 * serving pages with Apache2. Clients resolve `homelab.lan` through seeded
 * `/etc/hosts` entries and `/etc/resolv.conf` pointing at the in-board bind9 server.
 */

registerAutogenScenario(
    "homelab",
    "Autogen homelab",
    "Home LAN 192.168.1.0/24: router, switch, 3 PCs, bind9 DNS and an Apache2 NAS.",

    {
        "devices": [
            {
                "type": "router",
                "id": "router-home",
                "x": 320, "y": 60,
                "interfaces": {
                    "enp0s3": {"ip": "192.168.1.1", "netmask": "255.255.255.0", "switch": "switch-lan"}
                }
            },
            {
                "type": "switch",
                "id": "switch-lan",
                "x": 320, "y": 190
            },
            {
                "type": "pc",
                "id": "pc-laptop",
                "x": 90, "y": 320,
                "interfaces": {"enp0s3": {"ip": "192.168.1.10", "netmask": "255.255.255.0", "switch": "switch-lan"}},
                "gateway": "192.168.1.1",
                "files": [
                    {"path": "/etc/resolv.conf", "content": "nameserver 192.168.1.53\n"},
                    {"path": "/etc/hosts", "content": "127.0.0.1 localhost\n192.168.1.20 nas homelab.lan\n"}
                ]
            },
            {
                "type": "pc",
                "id": "pc-desktop",
                "x": 235, "y": 330,
                "interfaces": {"enp0s3": {"ip": "192.168.1.11", "netmask": "255.255.255.0", "switch": "switch-lan"}},
                "gateway": "192.168.1.1",
                "files": [
                    {"path": "/etc/resolv.conf", "content": "nameserver 192.168.1.53\n"},
                    {"path": "/etc/hosts", "content": "127.0.0.1 localhost\n192.168.1.20 nas homelab.lan\n"}
                ]
            },
            {
                "type": "pc",
                "id": "pc-family",
                "x": 405, "y": 330,
                "interfaces": {"enp0s3": {"ip": "192.168.1.12", "netmask": "255.255.255.0", "switch": "switch-lan"}},
                "gateway": "192.168.1.1",
                "files": [
                    {"path": "/etc/resolv.conf", "content": "nameserver 192.168.1.53\n"},
                    {"path": "/etc/hosts", "content": "127.0.0.1 localhost\n192.168.1.20 nas homelab.lan\n"}
                ]
            },
            {
                "type": "dns-server",
                "id": "dns-server-1",
                "x": 490, "y": 140,
                "interfaces": {"enp0s3": {"ip": "192.168.1.53", "netmask": "255.255.255.0", "switch": "switch-lan"}},
                "files": [
                    {"path": "/etc/hosts", "content": "127.0.0.1 localhost\n192.168.1.20 nas homelab.lan\n"}
                ]
            },
            {
                "type": "pc",
                "id": "pc-nas",
                "x": 550, "y": 320,
                "interfaces": {"enp0s3": {"ip": "192.168.1.20", "netmask": "255.255.255.0", "switch": "switch-lan"}},
                "gateway": "192.168.1.1",
                "packages": ["apache2"],
                "files": [
                    {"path": "/etc/hosts", "content": "127.0.0.1 localhost\n"}
                ]
            }
        ]
    }
);
