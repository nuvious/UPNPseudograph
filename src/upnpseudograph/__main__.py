import argparse
import logging
import os

from upnpseudograph import utils, upnp, agent

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
        while True:
            print("""
            Control Panel:
                m:[MESSAGE] - Send a message
                c:[COMMAND] - Execute a command
            """)
            command_input = input("Enter command:")

    except KeyboardInterrupt:
        os._exit(0)

if __name__ == "__main__":
    main()