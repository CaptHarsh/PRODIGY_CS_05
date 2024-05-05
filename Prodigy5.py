import tkinter as tk
from tkinter import scrolledtext, messagebox
import threading
import scapy.all as scapy
import os

stop_sniffing_flag = False
ip_summary = {}


def start_sniffing():
    global sniffing_thread, stop_sniffing_flag

    def packet_callback(packet):
        if stop_sniffing_flag:
            return

        try:
            if packet.haslayer(scapy.IP) and packet.haslayer(scapy.Raw):
                src_ip = packet[scapy.IP].src
                dst_ip = packet[scapy.IP].dst
                payload = packet[scapy.Raw].load.decode('utf-8', 'ignore')

                # Update IP summary
                if src_ip not in ip_summary:
                    ip_summary[src_ip] = 1
                else:
                    ip_summary[src_ip] += 1

                if dst_ip not in ip_summary:
                    ip_summary[dst_ip] = 1
                else:
                    ip_summary[dst_ip] += 1

                # Display packet information
                output.insert(
                    tk.END, f"Source IP: {src_ip} | Destination IP: {dst_ip}\n")
                output.insert(tk.END, f"Payload: {payload}\n\n")

                output.see(tk.END)  # Auto-scroll to the end of the text
        except Exception as e:
            print(f"Error processing packet: {e}")

    sniffing_button.config(state=tk.DISABLED)
    stop_button.config(state=tk.NORMAL)
    output.delete(1.0, tk.END)  # Clear previous output
    output.insert(tk.END, "[+] Sniffing Started...\n")
    output.see(tk.END)  # Auto-scroll to the end of the text

    stop_sniffing_flag = False

    try:
        # Change "Ethernet" to your actual Ethernet interface name
        sniffing_thread = threading.Thread(target=scapy.sniff, kwargs={
            "iface": "Ethernet", "store": False, "prn": packet_callback})
        sniffing_thread.start()
    except Exception as e:
        messagebox.showerror("Error", f"An error occurred: {e}")
        stop_sniffing()


def stop_sniffing():
    global sniffing_thread, stop_sniffing_flag
    stop_sniffing_flag = True
    sniffing_button.config(state=tk.NORMAL)
    stop_button.config(state=tk.DISABLED)
    output.insert(tk.END, "[+] Sniffing Stopped.\n")
    output.see(tk.END)  # Auto-scroll to the end of the text


def save_log():
    log_text = output.get(1.0, tk.END)
    log_file_path = os.path.join(os.path.expanduser(
        "~"), "Downloads", "packet_log.txt")
    with open(log_file_path, "w", encoding="utf-8") as file:  # Specify UTF-8 encoding
        file.write(log_text)
    messagebox.showinfo("Saved", "Log file saved successfully.")



def clear_output():
    output.delete(1.0, tk.END)


root = tk.Tk()
root.title("Packet Sniffer")
root.configure(bg="#001f3f")  # Dark blue background color
root.geometry("800x600")
root.protocol("WM_DELETE_WINDOW", stop_sniffing)  # Stop sniffing when window is closed

roboto_font = ("Roboto", 12)
consolas_font = ("Consolas", 10)

main_frame = tk.Frame(root, bg="#001f3f")  # Dark blue frame background
main_frame.pack(padx=10, pady=10, fill=tk.BOTH, expand=True)

button_frame = tk.Frame(main_frame, bg="#001f3f")  # Dark blue button frame
button_frame.pack(side=tk.TOP, padx=10, pady=10)

sniffing_button = tk.Button(button_frame, text="Start Sniffing",
                            command=start_sniffing, bg="#0074D9", fg="white", font=roboto_font, width=20)
sniffing_button.pack(side=tk.LEFT, padx=10)

stop_button = tk.Button(button_frame, text="Stop Sniffing", command=stop_sniffing,
                        bg="#FF4136", fg="white", font=roboto_font, width=20, state=tk.DISABLED)
stop_button.pack(side=tk.LEFT, padx=10)

download_button = tk.Button(button_frame, text="Download Log",
                            command=save_log, bg="#2ECC40", fg="white", font=roboto_font, width=20)
download_button.pack(side=tk.LEFT, padx=10)

clear_button = tk.Button(button_frame, text="Clear Output",
                         command=clear_output, bg="#FFDC00", fg="black", font=roboto_font, width=20)
clear_button.pack(side=tk.LEFT, padx=10)

output = scrolledtext.ScrolledText(
    main_frame, wrap=tk.WORD, font=consolas_font, bg="#002F6C", fg="white")
output.pack(padx=10, pady=10, fill=tk.BOTH, expand=True)

root.mainloop()

# Print IP summary
print("IP Summary:")
for ip, count in ip_summary.items():
    print(f"{ip}: {count} packets")
