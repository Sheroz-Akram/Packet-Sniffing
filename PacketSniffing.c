#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <errno.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

// Packet Capture Library
#include <pcap.h>

#define MAXBYTES 2048

// Function to convert a 16-bit integer to binary string
const char *ushortToBinaryString(uint16_t num)
{
    static char binStr[17];
    binStr[17] = '\0'; // Null-terminate the string

    for (int i = 16; i >= 0; --i)
    {
        if (i == 8)
        {
            binStr[i] = ' ';
            continue;
        }
        binStr[i] = (num & 1) + '0';
        num >>= 1;
    }

    return binStr;
}

// Function to display the Ethernet header
void displayEthernetHeader(const unsigned char *packetdata)
{

    printf("\n*****  ETHERNET HEADER *****\n");

    // Display Destination MAC Address
    printf("Destination Mac Address: ");
    for (int i = 0; i < 6; i++)
    {
        printf("%02x", packetdata[i]);
        if (i != 5)
            printf(":");
    }
    printf("\n");

    // Display Source MAC Address
    printf("Source Mac Address: ");
    for (int i = 6; i < 12; i++)
    {
        printf("%02x", packetdata[i]);
        if (i != 11)
            printf(":");
    }
    printf("\n");

    // Checking if it is an IPv4 packet
    if (packetdata[12] == 0x08 && packetdata[13] == 0x00)
    {
        printf("Type: IPv4\n");
    }
}

// Function to display the IP header
void displayIPHeader(const unsigned char *packetdata)
{

    printf("\n*****  IP HEADER *****\n");

    // Extracting version and header length
    unsigned char version = packetdata[14] >> 4;
    unsigned char header_length = packetdata[14] & 0x0f;
    printf("Version: %d\n", version);
    printf("Header length: %d\n", header_length);

    // Type of Service (ToS)
    unsigned char tos = packetdata[15]; // ToS is at byte 15
    printf("Type of Service (ToS): %d\n", tos);

    // Total length
    unsigned short total_length = ntohs(*((unsigned short *)(packetdata + 16)));
    printf("Total length: %d\n", total_length);

    // Identification
    unsigned short identification = ntohs(*((unsigned short *)(packetdata + 18)));
    printf("Identification: %d\n", identification);

    // Flags and Fragment Offset
    unsigned short flags_fragment = ntohs(*((unsigned short *)(packetdata + 20)));
    unsigned short flags = (flags_fragment >> 13) & 0x7;      // Extracting the three flag bits
    unsigned short fragment_offset = flags_fragment & 0x1FFF; // Extracting the lower 13 bits

    // Displaying Flags
    printf("Flags:\n");
    printf("  Reserved: %d\n", (flags >> 2) & 0x1);
    printf("  Don't Fragment: %d\n", (flags >> 1) & 0x1);
    printf("  More Fragments: %d\n", flags & 0x1);

    printf("Fragment Offset: %d\n", fragment_offset);

    // TTL
    printf("TTL: %d\n", packetdata[22]);

    // Protocol
    unsigned char protocol = packetdata[23];
    printf("Protocol: ");
    switch (protocol)
    {
    case IPPROTO_TCP:
        printf("TCP\n");
        break;
    case IPPROTO_UDP:
        printf("UDP\n");
        break;
    default:
        printf("Unknown\n");
        break;
    }

    // Header Checksum
    unsigned short header_checksum = ntohs(*((unsigned short *)(packetdata + 24)));
    printf("Header Checksum: %s\n", ushortToBinaryString(header_checksum));

    // Source IP
    printf("Source IP: %d.%d.%d.%d\n", packetdata[26], packetdata[27], packetdata[28], packetdata[29]);

    // Destination IP
    printf("Destination IP: %d.%d.%d.%d\n", packetdata[30], packetdata[31], packetdata[32], packetdata[33]);
}

// Function to display the TCP header
void displayTCPHeader(const unsigned char *packetdata)
{

    printf("\n*****  TCP HEADER *****\n");

    // Source port
    unsigned short source_port = ntohs(*((unsigned short *)(packetdata + 34)));
    printf("Source port: %d\n", source_port);

    // Destination port
    unsigned short destination_port = ntohs(*((unsigned short *)(packetdata + 36)));
    printf("Destination port: %d\n", destination_port);

    // Sequence number
    unsigned int sequence_number = ntohl(*((unsigned int *)(packetdata + 38)));
    printf("Sequence number: %u\n", sequence_number);

    // Acknowledgement number
    unsigned int acknowledgement_number = ntohl(*((unsigned int *)(packetdata + 42)));
    printf("Acknowledgement number: %u\n", acknowledgement_number);

    // Data offset
    unsigned char data_offset = packetdata[46] >> 4;
    printf("Data offset: %d\n", data_offset);

    // Flags
    unsigned char flags = packetdata[47];
    printf("Flags:\n");
    printf(" FIN: %d\n", (flags & 0x01) > 0 ? 1 : 0);
    printf(" SYN: %d\n", (flags & 0x02) > 0 ? 1 : 0);
    printf(" RST: %d\n", (flags & 0x04) > 0 ? 1 : 0);
    printf(" PSH: %d\n", (flags & 0x08) > 0 ? 1 : 0);
    printf(" ACK: %d\n", (flags & 0x10) > 0 ? 1 : 0);
    printf(" URG: %d\n", (flags & 0x20) > 0 ? 1 : 0);
    printf("\n");

    // Window size
    unsigned short window_size = ntohs(*((unsigned short *)(packetdata + 48)));
    printf("Window size: %d\n", window_size);
}

// Function to display the UDP header
void displayUDPHeader(const unsigned char *packetdata)
{

    printf("\n*****  UDP HEADER *****\n");

    // Source port
    unsigned short source_port = ntohs(*((unsigned short *)(packetdata + 34)));
    printf("Source port: %d\n", source_port);

    // Destination port
    unsigned short destination_port = ntohs(*((unsigned short *)(packetdata + 36)));
    printf("Destination port: %d\n", destination_port);

    // Length
    unsigned short length = ntohs(*((unsigned short *)(packetdata + 38)));
    printf("Length: %d\n", length);
}

// Function to handle the packet and display headers
void packetHandler(char *args, const struct pcap_pkthdr *pkthdr, const unsigned char *packetdata)
{
    displayEthernetHeader(packetdata);

    // Checking if it is an IPv4 packet
    if (packetdata[12] == 0x08 && packetdata[13] == 0x00)
    {

        displayIPHeader(packetdata);

        unsigned char protocol = packetdata[23];
        if (protocol == IPPROTO_TCP)
        {
            displayTCPHeader(packetdata);
        }
        else if (protocol == IPPROTO_UDP)
        {
            displayUDPHeader(packetdata);
        }
    }
    else
    {
        printf("Not IPv4\n");
    }
}

// Program Start from Hear
int main(int argc, char **argv)
{
    char *dev = NULL;       // Pointer to store the device name
    pcap_t *descptr = NULL; // pcap descriptor for packet capture
    int count = 0;          // Counter for captured packets
    char errbuff[PCAP_ERRBUF_SIZE];

    memset(errbuff, 0, PCAP_ERRBUF_SIZE); // Clear error buffer

    // Lookup and get the default network device
    dev = pcap_lookupdev(errbuff);
    if (dev == NULL)
    {
        printf("Error finding default device: %s \n", errbuff);
        exit(1);
    }
    else
    {
        printf("Opening the device: %s \n", dev);
    }

    // Open the network device for packet capture
    descptr = pcap_open_live(dev, MAXBYTES, 1, 512, errbuff);
    if (descptr == NULL)
    {
        printf("Error opening device: %s \n", errbuff);
        exit(1);
    }

    // Select the Mode to Capture the Packet
    int mode = 0;
    printf("\nSelect Capture Mode: \n");
    printf("1. Only one. \n");
    printf("2. Multiple loop. \n");
    printf("Enter : ");
    scanf("%d", &mode);

    // Single Packet Capture Mode
    // Start capturing packets
    if (mode == 1)
    {
        struct pcap_pkthdr *packerInfo;

        // Use pcap_next_ex instead of pcap_next for better error handling
        char *packet = pcap_next(descptr, &packerInfo);
        packetHandler(NULL, packerInfo, packet);
    }
    // Capture Multiple Packets
    else if (mode == 2)
    {
        // Start capturing packets and process each packet using the process_pkt function
        pcap_loop(descptr, -1, packetHandler, (char *)&count);
    }

    printf("\nDone capturing packets.\n");

    return 0;
}