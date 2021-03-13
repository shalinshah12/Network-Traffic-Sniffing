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
Answer:
Args: [/tmp/go-build814257484/b001/exe/mydump]

2021-03-12 19:52:02.711505 00:15:5d:99:a2:72 -> 00:15:5d:44:45:d2 type 0x800 len 60
172.27.228.239:42529 -> 172.27.224.1:50989 TCP ACK PSH
00000000  45 00 00 2e ee 33 40 00  40 06 2f 6e ac 1b e4 ef  |E....3@.@./n....|
00000010  ac 1b e0 01 a6 21 c7 2d  f6 f2 38 5c 66 49 9b 21  |.....!.-..8\fI.!|
00000020  50 18 01 f5 1d 49 00 00  c2 04 42 e1 00 00        |P....I....B...|


2021-03-12 19:52:02.76336  00:15:5d:44:45:d2 -> 00:15:5d:99:a2:72 type 0x800 len 54
172.27.224.1:50989 -> 172.27.228.239:42529 TCP ACK
00000000  45 00 00 28 15 7e 40 00  80 06 c8 29 ac 1b e0 01  |E..(.~@....)....|
00000010  ac 1b e4 ef c7 2d a6 21  66 49 9b 21 f6 f2 38 62  |.....-.!fI.!..8b|
00000020  50 10 20 10 d4 8c 00 00                           |P. .....|

2. sudo go run mydump.go -r "hw1.pcap"
Answer:
2013-01-12 12:03:24.675522 44:6d:57:f6:7e:00 -> ff:ff:ff:ff:ff:ff type 0x800 len 92
192.168.0.11:137(netbios-ns) -> 192.168.0.255:137(netbios-ns) UDP
00000000  45 00 00 4e 73 ba 00 00  80 11 44 8a c0 a8 00 0b  |E..Ns.....D.....|
00000010  c0 a8 00 ff 00 89 00 89  00 3a 38 2b fc 6e 01 10  |.........:8+.n..|
00000020  00 01 00 00 00 00 00 00  20 45 4a 46 44 45 42 46  |........ EJFDEBF|
00000030  45 45 42 46 41 43 41 43  41 43 41 43 41 43 41 43  |EEBFACACACACACAC|
00000040  41 43 41 43 41 43 41 41  41 00 00 20 00 01        |ACACACAAA.. ..|

2013-01-12 12:03:32.66923  c4:3d:c7:17:6f:9b -> ff:ff:ff:ff:ff:ff type 0x806 len 60
00000000  00 01 08 00 06 04 00 01  c4 3d c7 17 6f 9b c0 a8  |.........=..o...|
00000010  00 01 00 00 00 00 00 00  c0 a8 00 0c 00 00 00 00  |................|
00000020  00 00 00 00 00 00 00 00  00 00 00 00 00 00        |..............|


2013-01-12 12:03:50.898842 c4:3d:c7:17:6f:9b -> 01:00:5e:7f:ff:fa type 0x800 len 395
192.168.0.1:1900(ssdp) -> 239.255.255.250:1900(ssdp) UDP
00000000  45 00 01 7d d3 fd 00 00  01 11 33 cf c0 a8 00 01  |E..}......3.....|
00000010  ef ff ff fa 07 6c 07 6c  01 69 f1 2f 4e 4f 54 49  |.....l.l.i./NOTI|
00000020  46 59 20 2a 20 48 54 54  50 2f 31 2e 31 0d 0a 48  |FY * HTTP/1.1..H|
00000030  6f 73 74 3a 20 32 33 39  2e 32 35 35 2e 32 35 35  |ost: 239.255.255|
00000040  2e 32 35 30 3a 31 39 30  30 0d 0a 43 61 63 68 65  |.250:1900..Cache|
00000050  2d 43 6f 6e 74 72 6f 6c  3a 20 6d 61 78 2d 61 67  |-Control: max-ag|
00000060  65 3d 36 30 0d 0a 4c 6f  63 61 74 69 6f 6e 3a 20  |e=60..Location: |
00000070  68 74 74 70 3a 2f 2f 31  39 32 2e 31 36 38 2e 30  |http://192.168.0|
00000080  2e 31 3a 31 39 30 30 2f  57 46 41 44 65 76 69 63  |.1:1900/WFADevic|
00000090  65 2e 78 6d 6c 0d 0a 4e  54 53 3a 20 73 73 64 70  |e.xml..NTS: ssdp|
000000a0  3a 61 6c 69 76 65 0d 0a  53 65 72 76 65 72 3a 20  |:alive..Server: |
000000b0  50 4f 53 49 58 2c 20 55  50 6e 50 2f 31 2e 30 20  |POSIX, UPnP/1.0 |
000000c0  42 72 6f 61 64 63 6f 6d  20 55 50 6e 50 20 53 74  |Broadcom UPnP St|
000000d0  61 63 6b 2f 65 73 74 69  6d 61 74 69 6f 6e 20 31  |ack/estimation 1|
000000e0  2e 30 30 0d 0a 4e 54 3a  20 75 72 6e 3a 73 63 68  |.00..NT: urn:sch|
000000f0  65 6d 61 73 2d 77 69 66  69 61 6c 6c 69 61 6e 63  |emas-wifiallianc|
00000100  65 2d 6f 72 67 3a 64 65  76 69 63 65 3a 57 46 41  |e-org:device:WFA|
00000110  44 65 76 69 63 65 3a 31  0d 0a 55 53 4e 3a 20 75  |Device:1..USN: u|
00000120  75 69 64 3a 46 35 31 39  33 39 30 41 2d 34 34 44  |uid:F519390A-44D|
00000130  44 2d 32 39 35 38 2d 36  32 33 37 2d 45 41 33 37  |D-2958-6237-EA37|
00000140  42 39 38 37 43 33 46 44  3a 3a 75 72 6e 3a 73 63  |B987C3FD::urn:sc|
00000150  68 65 6d 61 73 2d 77 69  66 69 61 6c 6c 69 61 6e  |hemas-wifiallian|
00000160  63 65 2d 6f 72 67 3a 64  65 76 69 63 65 3a 57 46  |ce-org:device:WF|
00000170  41 44 65 76 69 63 65 3a  31 0d 0a 0d 0a           |ADevice:1....|

3. sudo go run mydump.go -r "hw1.pcap" "scr host 192.168.0.3"
2013-01-13 07:52:17.431826 00:16:44:b5:86:2e -> 01:00:5e:7f:ff:fa type 0x800 len 555
192.168.0.3:1900(ssdp) -> 239.255.255.250:1900(ssdp) UDP
00000000  45 00 02 1d 74 9d 00 00  01 11 92 8d c0 a8 00 03  |E...t...........|
00000010  ef ff ff fa 07 6c 07 6c  02 09 07 19 4e 4f 54 49  |.....l.l....NOTI|
00000020  46 59 20 2a 20 48 54 54  50 2f 31 2e 31 0d 0a 48  |FY * HTTP/1.1..H|
00000030  6f 73 74 3a 32 33 39 2e  32 35 35 2e 32 35 35 2e  |ost:239.255.255.|
00000040  32 35 30 3a 31 39 30 30  0d 0a 4e 54 3a 75 72 6e  |250:1900..NT:urn|
00000050  3a 6d 69 63 72 6f 73 6f  66 74 2e 63 6f 6d 3a 73  |:microsoft.com:s|
00000060  65 72 76 69 63 65 3a 58  5f 4d 53 5f 4d 65 64 69  |ervice:X_MS_Medi|
00000070  61 52 65 63 65 69 76 65  72 52 65 67 69 73 74 72  |aReceiverRegistr|
00000080  61 72 3a 31 0d 0a 4e 54  53 3a 73 73 64 70 3a 61  |ar:1..NTS:ssdp:a|
00000090  6c 69 76 65 0d 0a 4c 6f  63 61 74 69 6f 6e 3a 68  |live..Location:h|
000000a0  74 74 70 3a 2f 2f 31 39  32 2e 31 36 38 2e 30 2e  |ttp://192.168.0.|
000000b0  33 3a 32 38 36 39 2f 75  70 6e 70 68 6f 73 74 2f  |3:2869/upnphost/|
000000c0  75 64 68 69 73 61 70 69  2e 64 6c 6c 3f 63 6f 6e  |udhisapi.dll?con|
000000d0  74 65 6e 74 3d 75 75 69  64 3a 35 37 35 33 30 66  |tent=uuid:57530f|
000000e0  36 32 2d 36 61 39 37 2d  34 62 65 33 2d 39 61 63  |62-6a97-4be3-9ac|
000000f0  62 2d 63 38 35 36 36 66  35 62 31 31 66 32 0d 0a  |b-c8566f5b11f2..|
00000100  55 53 4e 3a 75 75 69 64  3a 35 37 35 33 30 66 36  |USN:uuid:57530f6|
00000110  32 2d 36 61 39 37 2d 34  62 65 33 2d 39 61 63 62  |2-6a97-4be3-9acb|
00000120  2d 63 38 35 36 36 66 35  62 31 31 66 32 3a 3a 75  |-c8566f5b11f2::u|
00000130  72 6e 3a 6d 69 63 72 6f  73 6f 66 74 2e 63 6f 6d  |rn:microsoft.com|
00000140  3a 73 65 72 76 69 63 65  3a 58 5f 4d 53 5f 4d 65  |:service:X_MS_Me|
00000150  64 69 61 52 65 63 65 69  76 65 72 52 65 67 69 73  |diaReceiverRegis|
00000160  74 72 61 72 3a 31 0d 0a  43 61 63 68 65 2d 43 6f  |trar:1..Cache-Co|
00000170  6e 74 72 6f 6c 3a 6d 61  78 2d 61 67 65 3d 39 30  |ntrol:max-age=90|
00000180  30 0d 0a 53 65 72 76 65  72 3a 4d 69 63 72 6f 73  |0..Server:Micros|
00000190  6f 66 74 2d 57 69 6e 64  6f 77 73 2d 4e 54 2f 35  |oft-Windows-NT/5|
000001a0  2e 31 20 55 50 6e 50 2f  31 2e 30 20 55 50 6e 50  |.1 UPnP/1.0 UPnP|
000001b0  2d 44 65 76 69 63 65 2d  48 6f 73 74 2f 31 2e 30  |-Device-Host/1.0|
000001c0  0d 0a 4f 50 54 3a 22 68  74 74 70 3a 2f 2f 73 63  |..OPT:"http://sc|
000001d0  68 65 6d 61 73 2e 75 70  6e 70 2e 6f 72 67 2f 75  |hemas.upnp.org/u|
000001e0  70 6e 70 2f 31 2f 30 2f  22 3b 20 6e 73 3d 30 31  |pnp/1/0/"; ns=01|
000001f0  0d 0a 30 31 2d 4e 4c 53  3a 33 34 33 35 64 64 66  |..01-NLS:3435ddf|
00000200  63 66 32 32 64 66 61 62  33 38 32 62 33 65 66 32  |cf22dfab382b3ef2|
00000210  62 31 66 34 34 30 38 64  39 0d 0a 0d 0a           |b1f4408d9....|

4. sudo go run mydump.go -r "hw1.pcap" "tcp"
Answer:
2013-01-14 02:52:52.192768 c4:3d:c7:17:6f:9b -> 00:0c:29:e9:94:8e type 0x800 len 74
91.189.91.14:80(http) -> 192.168.0.200:54634 TCP SYN ACK
00000000  45 00 00 3c 00 00 40 00  30 06 d2 80 5b bd 5b 0e  |E..<..@.0...[.[.|
00000010  c0 a8 00 c8 00 50 d5 6a  d2 4f ff 3f 82 64 41 39  |.....P.j.O.?.dA9|
00000020  a0 12 38 90 a0 cb 00 00  02 04 05 b4 04 02 08 0a  |..8.............|
00000030  e0 a5 2a 45 02 24 7e 60  01 03 03 08              |..*E.$~`....|


2013-01-14 02:52:52.19283  00:0c:29:e9:94:8e -> c4:3d:c7:17:6f:9b type 0x800 len 66
192.168.0.200:54634 -> 91.189.91.14:80(http) TCP ACK
00000000  45 00 00 34 3f 59 40 00  40 06 83 2f c0 a8 00 c8  |E..4?Y@.@../....|
00000010  5b bd 5b 0e d5 6a 00 50  82 64 41 39 d2 4f ff 40  |[.[..j.P.dA9.O.@|
00000020  80 10 03 91 78 62 00 00  01 01 08 0a 02 24 7e 7e  |....xb.......$~~|
00000030  e0 a5 2a 45                                       |..*E|
