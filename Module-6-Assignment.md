# UPNPsuedographia

## Requirements

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
pip install -r requirements.txt
```

# References

https://quimby.gnus.org/internet-drafts/draft-cai-ssdp-v1-03.txt
https://openconnectivity.org/upnp-specs/UPnP-arch-DeviceArchitecture-v2.0-20200417.pdf
https://github.com/MoshiBin/ssdpy