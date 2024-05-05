# Packet Sniffer

This is a simple packet sniffer implemented in Python using the `tkinter` and `scapy` libraries. It allows you to capture and display network packets in real-time.

## Features
1. **Start Sniffing:** Begin capturing network packets.
2. **Stop Sniffing:** Stop capturing network packets.
3. **Download Log:** Save the captured packets to a log file.
4. **Clear Output:** Clear the displayed packet information.

## Logic
1. The program uses the scapy library to sniff packets on the network interface specified ("Ethernet" in this case).
2. Each captured packet is processed by the `packet_callback` function, which extracts and displays relevant information.
3. The program displays information about each captured packet, including the source IP, destination IP, and payload.
4. The program also maintains an IP summary, counting the number of packets received from each unique IP address.

   ![image](https://github.com/CaptHarsh/PRODIGY_CS_05/assets/117205669/e310040b-1ef0-4191-a3e5-85d26edeecc9)
   ![image](https://github.com/CaptHarsh/PRODIGY_CS_05/assets/117205669/499fa7ba-4adf-4fc0-b8c3-ac35cc4bf8f1)

## Usage
1. Click the "Start Sniffing" button to begin capturing packets.
2. The program will display information about each captured packet, including the source IP, destination IP, and payload.
3. Click the "Stop Sniffing" button to stop capturing packets.
4. You can download the captured packets as a log file by clicking the "Download Log" button.
5. Use the "Clear Output" button to clear the displayed packet information.

## Installation
1. Clone the repository:

        git clone https://github.com/CaptHarsh/PRODIGY_CS_05.git
2. Install the required dependencies:

        pip install scapy

## IP Summary
After capturing packets, the program generates an IP summary, counting the number of packets received from each unique IP address. You can view this summary by checking the console output.
