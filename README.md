# UPNPsuedographia

## Dependencies

Clone the repository:

```bash
git clone https://github.com/nuvious/UPNPseudograph.git
cd UPNPseudograph
```

This project uses Pillow which requires external libraries:

```bash
sudo apt-get install -y \
    libjpeg-dev \
    zlib1g-dev \
    libtiff5-dev \
    libfreetype6-dev \
    liblcms2-dev \
    libwebp-dev \
    tcl8.6-dev \
    tk8.6-dev \
    python-tk
```

You can then install the python requirements:

```bash
pip install .
```

## Usage

### List Supported Devices

Before starting an agent, you must copy a fully qualified class path for one of the supported devices:

```bash
$> upnpseudograph --supported-devices                                      
upnpseudograph.upnp.RokuDevice
```

### C2 Agent

A C2 agent is one that can send out messages and command for other agents to run.

```bash
upnpseudograph --preferred-device=upnpseudograph.upnp.RokuDevice --is-c2
```


### Generic Agent

A generic agent will only send messages out and will not have a command line interface
to interact with. It will receive messages and commands from the C2.

```bash
upnpseudograph --preferred-device=upnpseudograph.upnp.RokuDevice
```

### Other Arguments

There are other arguments you can pass in depending on preference:

|Argument|Description|
|-|-|
|--disable-passthrough|By default passthrough is enabled forwarding all requests to the cloned device to the actual device to help minimize an unintentional denial of service. This flag disables that functionality.|
|--search-frequency|Sets the number of seconds to search for other agents. Default is 30 seconds.|


# References

https://quimby.gnus.org/internet-drafts/draft-cai-ssdp-v1-03.txt
https://openconnectivity.org/upnp-specs/UPnP-arch-DeviceArchitecture-v2.0-20200417.pdf
https://github.com/MoshiBin/ssdpy