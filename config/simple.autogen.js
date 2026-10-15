/**
 * "Autogen simple net" scenario — the smallest complete network: one gateway router,
 * one switch, and three PCs sharing a single /24 subnet. Ideal for first ping / ARP /
 * terminal experiments; every device is statically addressed.
 *
 * Registered into the autogen scenario registry at script load time.
 */

registerAutogenScenario(
    "simple-net",
    "Autogen simple net",
    "One router + one switch + three PCs on a single 192.168.10.0/24 subnet.",

    {
        "devices": [
            {
                "type": "router",
                "id": "router-gw",
                "x": 320, "y": 80,
                "interfaces": {
                    "enp0s3": {"ip": "192.168.10.1", "netmask": "255.255.255.0", "switch": "switch-main"}
                }
            },
            {
                "type": "switch",
                "id": "switch-main",
                "x": 320, "y": 200
            },
            {
                "type": "pc",
                "id": "pc-alpha",
                "x": 140, "y": 320,
                "interfaces": {"enp0s3": {"ip": "192.168.10.10", "netmask": "255.255.255.0", "switch": "switch-main"}},
                "gateway": "192.168.10.1"
            },
            {
                "type": "pc",
                "id": "pc-beta",
                "x": 320, "y": 330,
                "interfaces": {"enp0s3": {"ip": "192.168.10.11", "netmask": "255.255.255.0", "switch": "switch-main"}},
                "gateway": "192.168.10.1"
            },
            {
                "type": "pc",
                "id": "pc-gamma",
                "x": 500, "y": 320,
                "interfaces": {"enp0s3": {"ip": "192.168.10.12", "netmask": "255.255.255.0", "switch": "switch-main"}},
                "gateway": "192.168.10.1"
            }
        ]
    }
);
