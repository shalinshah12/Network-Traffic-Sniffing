# Network-Traffic-Sniffing
CSE 508 Network Security Lab Assignment 2 (HW2)

SBU ID: 113261194
First Name: Shalin Rakesh
Last Name: Shah

Program Specification:
go run mydump.go [-i interface] [-r file] [-s string] expression

1. -i: specifies the interface on which the packet capture has to be performed. If nothing is specified, it will automatically fetch the data from the default.
2. -r: specifies the .pcap file from which tthe packets are to be read. If nothing is specified, it will give an error.
3. -s: A string is specified, based on which only the packets containing that string are returned.
4. expression: It is the BPF filter that specifies the type of packet that needs to be captured. 

Implementation:
The default interface is specified using the FindAllDevs() function by taking the first interface from the list of interfaces present on the network.
The command line arguments are stored in the list which is then parsed to get the arguments and thier values.
The order of the arguments in which they are passed doesnot really matter much.

If the interface and .pcap file both are mentioned, as of now the priority will be given to the .pcap file first. 

Funtions and what they return:
main(): this funtion is the driving code of the file
readpackets(): this function is used to read the packets from the .pcap file specified in the argument. It then calls handlePacket funtion which fetches the content at every layer.
livetraffic(): this function is used to read the packets by monitoring the live packets. It then calls handlePacket() function which fetches the content at every layer.
handlePacket(): it basically calls the function dedicated for each layer. 

ethernetlayer(): returns the source and destination MAC addresses along with the ethernet type.
ipv4layer(): basically returns the source and destination IP address and ip protocol for both the IPv4 and IPv6 protocol.
tcplayer(): returns the source and destination ports for both the TCP and UDP layer along with the flags for TCP layer.
applayer(): basically returns the payload of the ethernet layer. and checks if the string is present in the payload. 

Note: Use SUDO to avoid any permission related errors.

Sample examples:

1. sudo go run mydump.go
2. sudo go run mydump.go -r "hw1.pcap"
3. sudo go run mydump.go -r "hw1.pcap" "scr host 192.168.0.3"
4. sudo go run mydump.go -r "hw1.pcap" "tcp"
5. go run mydump.go -r hw1.pcap -s png
