from scapy.all import sniff

def packet_callback(packet):
    print(packet.summary())

def start_sniffing(filter, count, timeout):
    packets = sniff(
        filter=filter,
        prn=packet_callback,
        count=count,
        timeout=timeout
        )
    return packets

def sniff_menu():

    while True:
        # Showmain menu
        print("Packet Sniffer Menu")
        print("1. Sniff all packets")
        print("2. Filter by protocol")
        print("3. Quit")
        choice = input("Enter your choice: ")

        # Quit choice
        if choice == '3':
            print ("Goodbye!")
            break

        filter_to_use = None

        if choice == '1':
            pass

        elif choice == '2':
            # Show filter submenu
            print("1. ICMP (ping)")
            print("2. UDP")
            print("3. HTTP (TCP port 80)")
            print("4. DNS (UDP port 53)")
            print("5. TCP")
            print("6. Back to main menu")

            filter_choice = input("Enter your choice: ")

            if filter_choice == '1':
                filter_to_use = 'icmp'
            elif filter_choice == '2':
                filter_to_use = 'udp'
            elif filter_choice == '3':
                filter_to_use = 'tcp port 80'
            elif filter_choice == '4':
                filter_to_use = 'udp port 53'
            elif filter_choice == '5':
                filter_to_use = 'tcp'
            elif filter_choice == '6':
                print("Goodbye!")
                continue
            else:
                print("Invalid choice. Please try again.")
                continue
      
        else:
            print("Invalid choice. Please try again.")
            continue

        user_count = int(input("How many packets do you want to capture? "))
        user_timeout = int(input("How long until timeout? (10 seconds recommended) "))

        captured_packets = start_sniffing(filter=filter_to_use, count=user_count, timeout=user_timeout)

        actual_count = len(captured_packets)
        if actual_count < user_count:
            print(f"Timeout reached: Only {actual_count} out of {user_count} requested packets were captured.")
        else:
            print (f"Capture complete: {actual_count} out of {user_count} packets retrieved.")
       
sniff_menu()