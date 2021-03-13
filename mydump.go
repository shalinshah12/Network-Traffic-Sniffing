package main
import (
	"fmt"
	"os"
    "strings"
    "encoding/hex"
    "github.com/google/gopacket"
    "github.com/google/gopacket/layers"
    "github.com/google/gopacket/pcap"
    "strconv"
)


//function to extract information from the ethernet layer
func ethernetlayer(packet gopacket.Packet) (string, string, string, string) {
    ethernetLayer := packet.Layer(layers.LayerTypeEthernet)
    if ethernetLayer != nil {
        ethernetPacket, _ := ethernetLayer.(*layers.Ethernet)
        srcmac := ethernetPacket.SrcMAC.String()
        dstmac := ethernetPacket.DstMAC.String()
        ethernettype := int64(ethernetPacket.EthernetType)
        payload_ether := hex.Dump(ethernetPacket.LayerPayload())
        return srcmac,dstmac, strconv.FormatInt(ethernettype, 16), payload_ether
    }
    return "","","",""
}

//function to extract information from the ipv4 and ipv4 layer
func ipv4layer(packet gopacket.Packet) (string, string, string, string) {
    ipLayer := packet.Layer(layers.LayerTypeIPv4)
    var srcip string
    var dstip string
    var ip_protocol string
    var payload_ip string
    if ipLayer != nil {
        ip, _ := ipLayer.(*layers.IPv4)
        srcip = ip.SrcIP.String()
        dstip = ip.DstIP.String()
        ip_protocol = ip.Protocol.String()
        payload_ip = hex.Dump(ipLayer.LayerPayload())
    }
    if (ip_protocol == "TCP" || ip_protocol == "UDP" || ip_protocol == "ICMPv4") {
        fmt.Println("")
    } else {
        ip_protocol = "Other"
    }
    // checks if there is any ipv6 layer present
    ipv6layer := packet.Layer(layers.LayerTypeIPv6)
    if ipv6layer != nil {
        ip, _ := ipv6layer.(*layers.IPv6)
        srcip = ip.SrcIP.String()
        dstip = ip.DstIP.String()
        payload_ip = hex.Dump(ipv6layer.LayerPayload())
    }
    return srcip, dstip, ip_protocol, payload_ip
}

// function to get the information from the TCP and UDP layer
func tcplayer(packet gopacket.Packet) (string, string,string,string) {
    var srcport string
    var dstport string
    var flags_output string
    var payload_tcp string
    // checks for the port information from UDP layer
    udpLayer := packet.Layer(layers.LayerTypeUDP)
    if udpLayer != nil {
        udp, _ := udpLayer.(*layers.UDP)
        srcport = udp.SrcPort.String()
        dstport = udp.DstPort.String()
        payload_tcp = hex.Dump(udpLayer.LayerPayload())
    }

    //checks for the flags and port information from TCP layer
    tcpLayer := packet.Layer(layers.LayerTypeTCP)
    if tcpLayer != nil {
        tcp, _ := tcpLayer.(*layers.TCP)
        srcport = tcp.SrcPort.String()
        dstport = tcp.DstPort.String()
        payload_tcp = hex.Dump(tcpLayer.LayerPayload())
        syn := bool(tcp.SYN)
        ack := bool(tcp.ACK)
        psh := bool(tcp.PSH)
        fin := bool(tcp.FIN)
        rst := bool(tcp.RST)
        urg := bool(tcp.URG)
        if syn {
            flags_output += "SYN "
        }
        if ack {
            flags_output += "ACK "
        }
        if psh {
            flags_output += "PSH "
        }
        if fin {
            flags_output += "FIN "
        }
        if rst {
            flags_output += "RST "
        }
        if urg {
            flags_output += "URG"
        }
    }
    return srcport, dstport, flags_output, payload_tcp
}

//checks for the payload at the application layer
func applayer(packet gopacket.Packet, stringf string) (string) {
    applicationLayer := packet.ApplicationLayer()
    if applicationLayer != nil {
        payload_app := hex.Dump(applicationLayer.Payload())
        return payload_app
    }
    return ""
}

func handlePacket(packet gopacket.Packet, stringf string) {
    srcmac, dstmac, ethernettype, payload_ether := ethernetlayer(packet)
    srcip, dstip, ip_protocol, payload_ip := ipv4layer(packet)
    srcport, dstport, flags, payload_tcp := tcplayer(packet)
    app_layer := applayer(packet, stringf)
    time:=((packet.Metadata().Timestamp).String())[0:26]
    packet_len := strconv.Itoa(packet.Metadata().Length)
    var payload string
    if payload_ether != "" {
        payload=payload_ether
    }
    if payload_ip != "" {
        payload=payload_ip
    }
    if payload_tcp != "" {
        payload=payload_tcp
    }
    if app_layer != "" {
        payload=app_layer
    }

    // output the entire data in specific format
    var end_result string = ""
    end_result+=time+" "+srcmac+" "+"->"+" "+dstmac+" "+"type"+" "+"0x"+ethernettype+" "+"len"+" "+packet_len+"\n"
    // if the information is of ARP layer, there won't be source and destination ip addresses and port addresses
    // 806 is the hex code for ARP packets
    if ethernettype != "806" {
        end_result+=srcip+":"+srcport+" "+"->"+" "+dstip+":"+dstport+" "+ip_protocol+" "+flags+"\n"
    }
    if(payload!=""){
        end_result+=payload
    }
    fmt.Println(end_result)
}

// function to read packets from the pcap file specified in the arguments
func readpackets(pcapfile string, stringf string, bpf string){
    var flag bool
    
	if handle, err := pcap.OpenOffline(pcapfile); err != nil {
		panic(err)
	  } else {
        handle.SetBPFFilter(bpf)
		packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
    	for packet := range packetSource.Packets() {
            flag = false
            if stringf!="" {
                ethernetLayer := packet.Layer(layers.LayerTypeEthernet)
                if ethernetLayer!=nil{
                    payload := ethernetLayer.LayerPayload()
                    if ( strings.Contains(string(payload), stringf)) {
                        flag=true
                    }
                }
                ipLayer := packet.Layer(layers.LayerTypeIPv4)
                if ipLayer!=nil{
                    payload := ipLayer.LayerPayload()
                    if (strings.Contains(string(payload), stringf)) {
                        flag=true
                    }
                }
                applicationLayer := packet.ApplicationLayer()
                if applicationLayer!=nil{
                    payload := applicationLayer.LayerPayload()
                    if (strings.Contains(string(payload), stringf)) {
                        fmt.Println("in app")
                        flag=true
                    }
                }
                if flag {
                handlePacket(packet, stringf)
                }
            } else {
                handlePacket(packet, stringf)
            }
		}
	  }
}

// function to capture live packets when either the interface is provided or it is a default one "eth0"
func livetraffic(interfaceName string, stringf string, bpf string ) {
    if handle, err := pcap.OpenLive(interfaceName, 1600, true, pcap.BlockForever); err!=nil {
        panic(err)
    } else {
        handle.SetBPFFilter(bpf)
        packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
        for packet := range packetSource.Packets() {
            handlePacket(packet, stringf)
        }
    }
}

func main() {
	cmd_args := os.Args // fetches a list of arguments from the command line.
	fmt.Println("Args:",cmd_args)
    
    //takes the first captured device name as the default interface
    devices_info, _ := pcap.FindAllDevs()
    var interfaces string = devices_info[0].Name

    var pcapf string
    var stringf string
    var bpf string = ""

    var r_flag int
    var i_flag int
    var s_flag int
    var b_flag int
    
    // if len(cmd_args)<2 {
    //     fmt.Println("Please run the file with the following format: go run mydump.go [-i interface] [-r file] [-s string] expression")
    // } else {
    for i:=1; i<len(cmd_args); i=i+2 {
        if cmd_args[i]=="-i" {
            if i_flag==1 {
                fmt.Println("please specify -i argument only once")
                os.Exit(1)
            }
            i_flag=1
            interfaces = cmd_args[i+1]
            if (interfaces ==" " || interfaces=="-i" || interfaces=="-s" || interfaces=="-r" || interfaces==""){
                fmt.Println("Please specify ethernet file")
                os.Exit(1)
            }
        } else if cmd_args[i]=="-r" {
            if(r_flag==1) {
                fmt.Println("Please specify -r argument only once")
                os.Exit(1)
            }
            r_flag=1
            pcapf = cmd_args[i+1]
            if (pcapf==" " || pcapf=="-i" || pcapf=="-s" || pcapf=="-r" || pcapf==""){
                fmt.Println("Please specify .pcap file")
                os.Exit(1)
            }
        } else if cmd_args[i]=="-s" {
            if s_flag==1 {
                fmt.Println("please specify -s argument only once")
                os.Exit(1)
            }
            s_flag=1
            stringf = cmd_args[i+1]
            if (stringf ==" " || stringf=="-i" || stringf=="-s" || stringf=="-r" || stringf==""){
                fmt.Println("Please specify string")
                os.Exit(1)
            }
        } else {
            if b_flag==1 {
                os.Exit(1)
            }
            b_flag=1
            bpf=cmd_args[i]
            i-=1
        }
    }
    // fmt.Println(interfaces)
    // fmt.Println(pcapf)
    // fmt.Println(bpf)
    // fmt.Println(stringf)
    // checks if both the pcap file and interfaces are present, if yes, the pcap file is by default selected.
    if pcapf!="" && interfaces!="" {
        interfaces=""
    }
    if pcapf!="" {
        readpackets(pcapf, stringf, bpf)
    } else if interfaces!="" {
        livetraffic("eth0", stringf, bpf)
    }
}

