import argparse
import logging
import os
import time

from upnpseudograph import utils, upnp, agent

def list_agents(spoofed_device):
    for i, ip in enumerate(spoofed_device.agents):
        print(i, ip)

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--is-c2', action='store_true', help="Whether this agent is acting as the C2.", default=False)
    parser.add_argument('--disable-passthrough', action='store_false', help="Disables passthrough mode to cloned device.", default=True)
    parser.add_argument('--search-frequency', type=int, help="Number of seconds between SSDP discover calls.", default=30)
    parser.add_argument('--preferred-device', type=str, help="The device class to clone from upnp", default=None)
    parser.add_argument('--supported-devices', action='store_true', help='Lists supported devices for cloning.', default=False)
    args = parser.parse_args()
    if args.supported_devices:
        for _class in utils.find_subclasses(upnp.UPNPDevice):
            print(f"{_class.__module__}.{_class.__name__}")
            exit(0)
    elif not args.preferred_device:
        print("Preferred device is a required field. Use --supported-devices to list available devices.")
        exit(1)
    logging.basicConfig(level=logging.ERROR)
    spoofed_device = agent.UPNPAgent(
        preferred_devices=[utils.instantiate_class(args.preferred_device)],
        search_frequency=args.search_frequency,
        passthrough=not args.disable_passthrough,
        is_c2=args.is_c2
    )
    try:
        print("Searching for agents...")
        while len(spoofed_device.agents) < 1:
            time.sleep(0.5)
        while True:
            print("""
            Control Panel:
                m:[MESSAGE] - Send a message
                c:[COMMAND] - Execute a command (c2 only)
                l - List agents
                q - quit
            """)
            command_input = input("Enter command:")
            if command_input == 'l':
                list_agents(spoofed_device)
            elif command_input == 'q':
                os._exit(0)
            elif command_input.startswith('m') or command_input.startswith('c'):
                if not args.is_c2 and command_input.startswith('c'):
                    print("C2 only command.")
                    continue
                if command_input[1] != ':':
                    print("Malformed command.")
                    continue
                list_agents(spoofed_device)
                agent_ip = None
                while not agent_ip:
                    try:
                        agent_index = int(input("Select agent to send to or type c to cancel:"))
                        if agent_index == 'c':
                            break
                        elif agent_index < len(spoofed_device.agents):
                            agent_ip = list(spoofed_device.agents.keys())[agent_index]
                    except:
                        raise
                if agent_ip:
                    command = command_input[0].encode('utf8')
                    content = command_input[2:].encode('utf8')
                    queued = spoofed_device.queue_message(agent_ip, command, content)
                    if queued:
                        print(f"Message queued for {agent_ip}")
                    else:
                        print("Failed to queue message.")
            else:
                print("Malformed command.")

    except KeyboardInterrupt:
        os._exit(0)

if __name__ == "__main__":
    main()