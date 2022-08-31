MONITOR
Nicholas Mastorakis


All the tasks of this assigment were implemented successfully 

In this task I created monitor network traffic tool using the Packet Capture library.

At the start of I declared some nessecary structures that I needed to implement all the tasks of this assigment.The first two structures network_flow_tcp and network_flow_udp were used to find the count of different udp and tcp network flows.Also network_flow_tcp was used to check if a packet was retransmitted.Structure sniff_ethernet,sniff_ip,sn,iff_tcp,sniff_udp were used to get the information of the packets that we needed in the process_packet function which was the function called for the proccess of each packet.After the declarations of the structures I declared some variables that were needed to hold the numbers of some values that were needed to print to the user after the programm ended.
The way I managed to print the results to the user after the programm ended was by using the atexit() function which called another function named function_exit after all the packets were processed and printed to the user all the information the assigment asked us to print.

First of all to run the programm you must run the command 'sudo ./monitor -f "pcap file name" ' because you need sudo proviledges.Also after inputing the flag '-f' you  must specify the pcap file name to monitor.

In case you dont input the correct flag or arguments there is an error message presented in the terminal which prompts the user to use flags '-f' or '-h'. 

The way I opened the pcap file was by calling function pcap_open_offline() which got as argument the name of the pcap file and a buffer which was filled with an appropriate error message if pcap_open_offline failed and instead of returning a pcap_t* it returned 0.

After getting a handler of the pcap file with pcap_open_offline() I used the function pcap_loop() to read each packet and process each information to implement all the nessecary tasks that were needed for this assigment.The arguments of the pcap_loop was the handler from the previous function called,0 so we get an infinite loop until all packets are read and the name of the function which will be called to proccess each packet and NULL.

Function declarations:
        
void process_packet(u_char , const struct pcap_pkthdr ,): This function was called for each packet through the function pcap_loop().The third argument was the actual packet that all the operation were used for.The packets was a number of bytes which included all the information of an encapsulated packet.An encapsulated packet consisted all layer headers which were the ethernet header information from the datalink layer,ip header information from the network layer and tcp or udp header information from the transport layer.The rest information could be found in the actual payload.At the start after I got the packet I travesed sizeof ethernet packets ahead so I can pass the ethernet information which were not needed and go to the start of the ip packet information.After this I multiplied IP_HL by 4 since the length of the ip packet at the field of the length had to be converted to bytes.More specifically the second-half of the first byte in ip_header contains the IP header length (IHL). IHL field indicates the number of 4 byte units of IP header.After getting the header length I extracted the protocol of the packet by going to the 10th byte of the packet which was the start of the protocol used.I only proceeded to the rest implementation of the function if the packet was tcp or udp.Else I returned and started processing the next packet.

TCP packet:
After I checked if the packet was tcp I incremented the count of tcpPackets and then I used a for loop to check if it was a new network flow or this network flow existed.I did these by looping in all the network flows and checking if the 5-tuple (src port,dst port ,src ip,dst ip) existed.The protocol was checked if it was the same  all the packets were tcp and the network flows that were checked were only the tcp.If the network flow existed then I used a variable called "found" so I know If i should later add a new network flow in the tcp network flow structure or not.At this point I also checked if this packet was retransmitted by checking its sequence number.More specifically if the seq number was lower than the highest sequence number of this network flow then this meant that the packet had already been sent from the sender once and now he is sending this packet again.After checking for retransmission I print out to the user the "Retransmitted packet" and then src and dst ip number and src and dst port number.To get the payload I had to traverse through the packet number of bytes SIZE_ETHERNET + size_ip + size_tcp since payload is the deepest encapsulated information in the packet.After this I printed to the user the number of bytes and also summed to the variable tcp_bytes the number of payload bytes of current packet so I can get at the end of the programm the total number of tcp bytes read.

UPD packet:
After I checked if the packet was udp most of the implementation to print to the user the nessecary information was similar to tcp with some differences.First of all I did not check if the packet was retransmitted since udp packets can not be retransmitted since there is no retransmission mechanism in udp protocol for the sender and the reciever.Also udp header length is always 8 bytes in contrast to tcp were header length is not always the same number.

The way I managed to print upper layer protocols like https ,http and dns(domain name system) was by using the function getservbyport(int portnumber,char * protocoltype).More specifically this function returns the internet service associated with port for the specified protocol as per /etc/services.The parameters are the port number and the transport layer protocol which is "tcp" or "udp".In case of failure this function instead of returning the internet service name as a string it returns false.

gcc --version output:
        gcc (Ubuntu 9.3.0-17ubuntu1~20.04) 9.3.0

        

