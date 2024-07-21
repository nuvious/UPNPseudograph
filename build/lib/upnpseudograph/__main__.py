from .agent import UPNPAgent

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--is-c2', action='store_true', help="Whether this agent is acting as the C2.", default=False)
    parser.add_argument('--disable-passthrough', action='store_false', help="Disables passthrough mode to cloned device.", default=True)
    parser.add_argument('--search-frequency', type=int, help="Number of seconds between SSDP discover calls.", default=30)
    parser.add_argument('--preferred-device', type=str, help="The device class to clone from upnp")
    logging.basicConfig(level=logging.INFO)
    spoofed_device = UPNPAgent(preferred_devices = [upnp.RokuDevice], is_c2=True)
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