from scapy.all import sniff

def packet_callback(packet):
    print(packet.summary())

def start_sniffing(filter, count):
    sniff(
        filter=filter,
        prn=packet_callback,
        count=count,
        )

def sniff_menu():

    while True:
        print("Packet Sniffer Menu")
        print("1. Sniff all packets")
        print("2. Filter by protocol")
        print("3. Quit")
        choice = input("Enter your choice: ")

        count = int(input("How many packets do you want to capture? "))

        if choice == '1':
            start_sniffing(filter=None, count=count)

        elif choice == '2':
            print("1. ICMP (ping)")
            print("2. UDP")
            print("3. HTTP (TCP port 80)")
            print("4. DNS (UDP port 53)")
            print("5. TCP")
            print("6. Quit")

            filter_choice = input("Enter your choice: ")
            if filter_choice == '1':
                start_sniffing(filter='icmp', count=count)
            elif filter_choice == '2':
                start_sniffing(filter='udp', count=count)
            elif filter_choice == '3':
                start_sniffing(filter='tcp port 80', count=count)
            elif filter_choice == '4':
                start_sniffing(filter='udp port 53', count=count)
            elif filter_choice == '5':
                start_sniffing(filter='tcp', count=count)
            elif filter_choice == '6':
                print("Goodbye!")
                break
            else:
                print("Invalid. Please try again.")
                break
        
        elif choice == '3':
            print ("Goodbye!")
            break

        else:
            print("Invalid choice. Please try again.")
            break
        
sniff_menu()