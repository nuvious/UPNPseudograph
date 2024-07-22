"""A module for UPNP device classes
"""
import asyncio
import json
import logging
import queue
import socket
import struct
import sys
import threading
import time
import typing

import requests
from cryptography.hazmat.primitives.asymmetric import rsa
from flask import Flask, Response, request # pylint: disable=E0401
from flask_sock import Sock
import websockets
import xmltodict
import zlib

from upnpseudograph import secret_pixel
from upnpseudograph import ssdp
from upnpseudograph import utils


log = logging.getLogger(__name__)


SSDP_ADDR = "239.255.255.250"
SSDP_PORT = 1900
SSDP_DISCOVER_SHORTCYCLE_DELAY = 5


class UPNPDevice:
    """
    A base class for devices. Searches UPNP devices and clones one based on
    match criteria
    """
    def __init__(
        self,
        passthrough: bool,
        public_key: rsa.RSAPublicKey,
        message_queue: queue.Queue,
        oversized_queue: queue.Queue,
        ssdp_filter: str = ''
    ) -> None:
        """Clones a device without modification of any metadata.

        Parameters
        ----------
        ip : str
            IP address of the target device
        port : int
            Port of the target device
        ssdp : typing.List[typing.Dict]
            The SSDP discover response
        target_devices: typing.List[typing.Dict]
            A list of dict representations of SSDP devices
        passthrough : bool, default = True
            If True, calls to the device will be passed through to cloned
                device. More detectable.
            If False, calls will be cached and repeated back.
        ssdp_filter : str, default ''
            A simple text filter to selectively search for specific devices
        """
        self.public_key = public_key
        self.passthrough = passthrough
        self.ssdp_filter = ssdp_filter
        self.host_ip = utils.get_host_ip_address()
        target_services, root_device, icons, target_ip, target_port = self.find_spoofable_upnp()
        self.path_cache = {}
        self.message_queue = message_queue
        self.oversized_queue = oversized_queue
        self.message_queues = {}
        self.has_key_list = []
        if root_device:
            self.target_services = target_services
            self.target_device_ip = target_ip
            self.target_device_port = target_port
            self.target_root_device = root_device
            self.target_icons = icons
        else:
            raise Exception("No matching UPNP devices")  # pylint: disable=W0719
        icon_benchmarks = utils.benchmark_icons(
            self.public_key,
            self.target_icons
        )
        # Set max message size and raise an error if no image can encode the
        # public key
        self.max_size = min([v['_capacity'] for v in icon_benchmarks.values()])
        if self.max_size < len(utils.get_compact_key(self.public_key)):
            raise OverflowError("No icons can encode public key.")
        self.start_flask_app()
        self.start_ssdp_server()
        self.monitor_queue()

    def monitor_queue(self):
        def _monitor_queue():
            while True:
                if not self.message_queue.empty():
                    ip, public_key, message = self.message_queue.get()
                    # Don't need to lock because we only have a single thread and
                    # modifying one message at a time
                    message_queue = self.message_queues.get(ip, queue.Queue())
                    message_queue.put((public_key, zlib.compress(message)))
                    self.message_queues[ip] = message_queue
                time.sleep(0.1)
        threading.Thread(target=_monitor_queue).start()

    def _queue_message(
        self,
        public_key: rsa.RSAPublicKey,
        ip: str,
        message: bytes
    ):
        """Splits a message up into parts for each of the available icons

        Parameters
        ----------
        ip : str
            IP of the agent to send the message to
        public_key : rsa.RSAPublicKey
            The public key to encrypt the message with
        message : bytes
            The bytes of the message

        Raises
        ------
        OverflowError
            Raised if the total message size can't be encoded in the available icons
        """
        capacity = self.target_icons[0].get('_capacity')
        if len(message) > capacity:
            raise OverflowError("Message too big to be encoded.")
        message_queue : queue.Queue = self.message_queues.get(ip, queue.Queue())
        message_queue.put((public_key, message))
        self.message_queues[ip] = message_queue


    def update_fields(self, device):
        """Updates fields in the SSDP or UPNP responses to replace IP's or other fields.
        """
        # Replace the IP with the host ip
        device['location'] = utils.replace_ip(device['location'])
        return device

    def start_ssdp_server(self):
        """Starts the SSDP server to respond to discover requests
        """
        def handle_ssdp_packet(data, client_address, sock, last_discover_time):
            log.debug("Handling ssdp discover from %s", client_address)
            if client_address == self.host_ip:
                return
            if b'ssdp:discover' in data or b'ssdp:all':
                if time.time() - last_discover_time > SSDP_DISCOVER_SHORTCYCLE_DELAY:
                    for service in self.target_services:
                        response = ssdp.generate_ssdp_response(service)
                        sock.sendto(response.encode('utf-8'), client_address)
                    return time.time()
                return last_discover_time
            else:
                for service in self.target_services:
                    keys = ssdp.parse_ssdp_response(data)
                    if service.get('st','not') == keys.get('st', 'equal'):
                        response = ssdp.generate_ssdp_response(service)
                        sock.sendto(response.encode('utf-8'), client_address)
                return None

        def server_thread():
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 2)
            sock.bind(('', SSDP_PORT))
            mreq = struct.pack('4sl', socket.inet_aton(SSDP_ADDR), socket.INADDR_ANY)
            sock.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, mreq)

            logging.debug("SSDP server is listening...")
            last_discover_time = 0
            try:
                while True:
                    # Receive data and client address
                    data, client_address = sock.recvfrom(1024)
                    last_discover_time = (
                        handle_ssdp_packet(
                            data,
                            client_address,
                            sock,
                            last_discover_time) or
                        last_discover_time
                    )
            except KeyboardInterrupt:
                pass
            finally:
                sock.close()

        threading.Thread(target=server_thread).start()


    def start_flask_app(self, ip='0.0.0.0'):
        """
        Starts the flask app and registers a catch-all endpoint that passes
        requests to handle_path

        Parameters
        ----------
        port : int
            Port to start the flask app on
        ip : str, optional
            IP to bind to, by default '0.0.0.0'
        """
        def _start_flask():
            app = Flask(__name__)

            logging.getLogger('werkzeug').setLevel(logging.ERROR)


            self.add_custom_routes(app)

            @app.route('/', defaults={'path': ''})
            @app.route('/<path:path>')
            def catch_all(path):
                response = self.handle_path(path)
                logging.info(
                    "Flask returning response for %s - %d",
                    path, response.status_code
                )
                return response

            logging.info(
                "Starting flask app on port %d.",
                self.target_device_port
            )
            app.run(ip, port=self.target_device_port, debug=False)

        threading.Thread(target=_start_flask).start()


    def add_custom_routes(self, app: Flask):
        pass


    def generate_message(self, request_ip, cloned_response):
        # We're talking to an agent
        message_queue: queue.Queue = self.message_queues.get(request_ip)
        # Ensure the request_ip has received at least one message with the key
        if request_ip not in self.has_key_list:
            message = utils.get_compact_key(self.public_key)
            public_key = None
            self.has_key_list.append(request_ip)
            print(f"Sent initial key to {request_ip}.")
        # If we get here, we know the ip has our public key so see if there's a
        # message or not in the queue
        elif message_queue and not message_queue.empty():
            public_key, message = message_queue.get()
            print(f"Sending message {message} to {request_ip}")
            if len(message) > self.max_size:
                self.oversized_queue.put((request_ip, zlib.decompress(message)))
                message = None
                public_key = None
        else:
            # As a default, just set the message to a public key
            print(f"Defaulting to sending key to {request_ip}")
            message = utils.get_compact_key(self.public_key)
            public_key = None

        # If we've set a message, encode it into the content
        if message:
            # Encode the message into image
            content = secret_pixel.encode_bytes(
                cloned_response['content'],
                message,
                public_key
            )
            cloned_response['content'] = content

        return cloned_response


    def handle_path(self, path):
        """Handles requests by other devices and responds with the spoofed devices information

        Parameters
        ----------
        path : str
            the requested path
        """
        request_ip = request.remote_addr
        if request_ip == utils.get_host_ip_address():
            return Response(
                b'',
                status=200
            )
        is_icon_request = False
        args = [f"{k}={v}" for k, v in request.args.items()]
        full_path = path
        if args:
            full_path = path + "?" + "&".join(args)
        log.debug("Handling full path %s", full_path)
        cloned_response = self.target_icons.get(full_path)
        if cloned_response:
            is_icon_request = True
        if not cloned_response:
            cloned_response = self.path_cache.get(full_path)
        if self.passthrough:
            cloned_response = None
        device_full_path = (
            f'http://{self.target_device_ip}:{self.target_device_port}'
            f'{path if path.startswith("/") else f"/{path}"}'
        )
        if not cloned_response:
            try:
                log.debug("Requesting %s from target device", device_full_path)
                device_response = requests.get(device_full_path, timeout=10)
                if device_response.status_code != 200:
                    log.debug(
                        "Failed request to %s code %d:\n%s",
                        full_path,
                        device_response.status_code,
                        device_response.text
                    )
                cloned_response = {
                    'content': device_response.content,
                    'status': device_response.status_code,
                    'headers': device_response.headers
                }
            except Exception as e:  # pylint: disable=W0718
                log.error(
                    "Exception raised %s while getting path from target device",
                    e, exc_info=sys.exc_info
                )
        if is_icon_request:
            cloned_response = self.generate_message(request_ip, cloned_response)
        response = Response(
            cloned_response['content'],
            status=cloned_response['status']
        )
        for k, v in cloned_response['headers'].items():
            response.headers.set(k, v)
        content_length = len(cloned_response['content'])
        response.headers.set('Content-Length', content_length)
        return response

    def find_spoofable_upnp(self):
        """Discovers and saves device information if they satisfy match criteria
        """
        max_icons = 0
        ssdp_devices = ssdp.discover_ssdp_devices(ssdp_filter=self.ssdp_filter)
        icon_lists = {}
        target_ip = None
        target_port = None
        target_services = []
        root_device = None
        # Go through the device list
        for ip, st_services in ssdp_devices.items():
            for st, service in st_services.items():
                try:
                    location = service.get('location')
                    if location:
                        port = int(location.split(":")[2].split("/")[0])
                        response = requests.get(location, timeout=10)
                        response.raise_for_status()
                        xml = response.text
                        xml_dict = xmltodict.parse(xml)
                        # Find devices that have icon lists and select the one with
                        # the most icons
                        icon_list = xml_dict.get(
                            'root', {}
                        ).get(
                            'device',{}
                        ).get(
                            'iconList',None
                        )
                        if icon_list:
                            # Go through the icons and filter out ones that
                            # can't be fetched or are corrupted, potentially
                            # due to the presence of other agents on the network
                            log.debug("Found device with iconlist.")
                            icon_list = utils.filter_icon_list(
                                location, icon_list.get('icon', [])
                            )
                            icon_count = len(icon_list)
                            if icon_count > max_icons:
                                target_ip = ip
                                log.debug("Setting new target device")
                                max_icons = icon_count
                                icon_lists[ip] = {
                                    **icon_lists.get(ip, {}),
                                    **icon_list
                                }
                                target_port = port
                        target_services.append(
                            self.update_fields(service)
                        )
                        if 'root' in service.get('st', ''):
                            root_device = service
                except Exception as e:  # pylint: disable=W0718
                    log.error(
                        "%s error while attempting to spoof device.",
                        e, exc_info=sys.exc_info
                    )
                    continue
        if root_device:
            return (
                target_services,
                root_device,
                icon_lists[target_ip],
                target_ip,
                target_port
            )
        return tuple([None] * 5)


class RokuDevice(UPNPDevice):
    def __init__(
        self,
        passthrough: bool,
        public_key: rsa.RSAPublicKey,
        message_queue: queue.Queue,
        oversized_queue: queue.Queue,
    ) -> None:
        super().__init__(
            passthrough,
            public_key,
            message_queue,
            oversized_queue,
            ssdp_filter='roku'
        )

    def add_custom_routes(self, app: Flask):
        sock = Sock(app)
        async def consume_ws(ws, target_ws):
            async for message in ws:
                await target_ws.send(message)

        async def produce_ws(ws, target_ws):
            async for message in target_ws:
                await ws.send(message)

        @sock.route('/ecp-session')
        async def websocket_proxy(ws):
            async with websockets.connect(self.target_device_ip) as target_ws:
                consumer_task = asyncio.ensure_future(consume_ws(ws, target_ws))
                producer_task = asyncio.ensure_future(produce_ws(ws, target_ws))
                _, pending = await asyncio.wait(
                    [consumer_task, producer_task],
                    return_when=asyncio.FIRST_COMPLETED,
                )

                for task in pending:
                    task.cancel()
