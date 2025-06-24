from scapy.all import sniff

def packet_callback(packet):
    print(packet.summary())

def sniffing(packet):
    sniff(
        prn=packet_callback,
        timeout=10,
        count=1
        )

def sniff_menu():

    while True:
        print("Packet Sniffer Menu")
        print("1. Sniff all packets")
        print("2. Filter by protocol")
        print("3. Quit")
        choice = input("Enter your choice: ")

        if choice == '1':
            sniffing()

        elif choice == '2':
            print("1. ICMP (ping)")
            print("2. UDP")
            print("3. HTTP (TCP port 80)")
            print("4. DNS (UDP port 53)")
            print("5. Quit")

            filter_choice = input("Enter your choice: ")
            if filter_choice == '1':
                sniff(filter='icmp', prn=sniffing)
            elif filter_choice == '2':
                sniff(filter='udp', prn=sniffing)
            elif filter_choice == '3':
                sniff(filter='tcp port 80', prn=sniffing)
            elif filter_choice == '4':
                sniff(filter='udp port 53', prn=sniffing)
            elif filter_choice == '5':
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



