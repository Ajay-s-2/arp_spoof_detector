// this is the arp spoof dectector tool in c
#include <stdio.h>
#include <stdlib.h>
#include <pcap.h> // to invoke the libpcap library abd use its functions
#include <errno.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <time.h>
#include <netinet/if_ether.h> 
#include<string.h>
#define ARP_REQUEST 1 // arp request
#define ARP_RESPONSE 2 // arp response
// struct for arp header
typedef struct _arp_hdr arp_hdr;
     struct arp_hdr{
        uint16_t htype; // hardware type
        uint16_t ptype; // protocol type
        uint8_t hlen;   // hardware address length
        uint8_t plen;   // protocol address len
        uint16_t opcode; // operation code (request or responce )
        uint8_t sender_mac[6]; //sender mac address
        uint8_t sender_ip[4];// sender ip address
        uint8_t target_mac[6]; // target mac address
        uint8_t target_ip[4];// target ip address
     };

 
 // function to list the avalible devices
 int print_available_interfaces(){
    char error[PCAP_ERRBUF_SIZE];
    pcap_if_t *interfaces,*temp;
    int i=0;
    if(pcap_findalldevs(&interfaces,error)==-1){
        printf("cannot find any interfaces %s\n",error);
        return -1;
    }
    printf("the available interfaces are\n");
    for(temp=interfaces;temp!=NULL;temp=temp->next){
        printf("=>%d: %s\n",++i,temp->name);
    }
    
    return 0;
 }
 // function to print version
 void print_version(){
    // print in asscii art
    printf("    _    ____  ____                    \n");
    printf("   / \\  |  _ \\|  _ \\                   \n");
    printf("  / _ \\ | |_) | |_) |                  \n");
    printf(" / ___ \\|  _ <|  __/                   \n");
    printf("/_/   \\_\\_| \\_\\_|                      \n");
    printf(" ____                     __           \n");
    printf("/ ___| _ __   ___   ___  / _|          \n");
    printf("\\___ \\| '_ \\ / _ \\ / _ \\| |_           \n");
    printf(" ___) | |_) | (_) | (_) |  _|          \n");
    printf("|____/| .__/ \\___/ \\___/|_|            \n");
    printf(" ____ |_|   _            _             \n");
    printf("|  _ \\  ___| |_ ___  ___| |_ ___  _ __ \n");
    printf("| | | |/ _ \\ __/ _ \\/ __| __/ _ \\| '__|\n");
    printf("| |_| |  __/ ||  __/ (__| || (_) | |   \n");
    printf("|____/ \\___|\\__\\___|\\___|\\__\\___/|_|   \n");
    printf("          _   ___                      \n");
    printf(" __   __ / | / _ \\                     \n");
    printf(" \\ \\ / / | || | | |                    \n");
    printf("  \\ V /  | || |_| |                    \n");
    printf("   \\_/   |_(_)___/                     \n");
    printf("                                       \n");
    printf("\nThis tool will sniff for ARP packets in the interface and can possibly detect if there is an ongoing 48 ARP spoofing attack. This tool is still in a beta stage. \n");
 }
 // function to print help
 void print_help(char *bin){
     printf("Avaliable arguments:\n");
     printf("------------------------------------------------------------\n");
     printf("-h or --help:\t\tprint help text\n");
     printf("-v or --version:\tprint version\n");
     printf("-h or-help:\t\tPrint this help text.\n"); 
     printf("-l orlookup:\t\tPrint the available interfaces.\n");
     printf("-i or-interface:\tProvide the interface to sniff on.\n");
     printf("------------------------------------------------------------\n"); 
     printf("Usage: %s -i <interface> [you can lookup the available interfaces using -l]\n",bin);
        
 }
 //monitering the packet
 int sniff_arp(){
    char error[PCAP_ERRBUF_SIZE];
    pcap_t *pack_desc;
    const u_char *packet;
    struct pcap_pkthdr header;
    struct ether_header *eptr;
    u_char *hard_ptr;
     pack_desc = pcap_open_live(interfaces->name, BUFSIZ, 0, 1, error);
     
    if (pack_desc == NULL) {
        printf("Error opening device: %s\n", error);
        return -1;
    }

    while (1) {
        // Capture a packet
        packet = pcap_next(pack_desc, &header);
        if (packet == NULL) {
            printf("Error: cannot capture packet\n");
            continue; // Continue instead of returning -1
        }

        // Print packet information
        printf("----------------------------------------------\n");
        printf("Received a packet with length %d\n", header.len);
        printf("Received at %s", ctime((const time_t*)&header.ts.tv_sec));
        printf("Ethernet header length: %d\n", ETHER_HDR_LEN);

        eptr = (struct ether_header *)packet;
        if(ntohs(eptr->ether_type) != ETHERTYPE_ARP){
             printf("Ethernet address constant length: %zu\n", sizeof(*eptr));

            // Print Ethernet addresses manually
            printf("Destination Address: ");
            do{
                printf("%s%02x", (i==ETHER_ADDR_LEN) ? "" : ":", *hard_ptr++);
            }while(--i>0);
            hard_ptr=eptr->ether_shost;
            printf("\n");

            printf("Source Address: ");
            do{
                printf("%s%02x", (i==ETHER_ADDR_LEN) ? "" : ":", *hard_ptr++);
            }while(--i>0);
            printf("\n");
            printf("----------------------------------------------\n");
            
        }
       

       /* if (ntohs(eptr->ether_type) == ETHERTYPE_IP) {
            printf("Ethernet type hex: %x; dec: %d is an IP packet\n", ETHERTYPE_IP, ETHERTYPE_IP);
        } else if (ntohs(eptr->ether_type) == ETHERTYPE_ARP) {
            printf("Ethernet type hex: %x; dec: %d is an ARP packet\n", ETHERTYPE_ARP, ETHERTYPE_ARP);
        } else {
            printf("Ethernet type hex: %x; dec: %d is an unknown packet type:\n", ntohs(eptr->ether_type), ntohs(eptr->ether_type));
        } */
        printf("----------------------------------------------\n");
    }


 }
 // main function
 int main(int argc, char *argv[]){
     for (int i=1;i<argc;i++){
        printf("%d: %s\n",i,argv[i]);
        printf("\n");         
     }
     if(argc<2 || strcmp(argv[1],"-h")==0 || strcmp(argv[1],"--help")==0){
        print_version();
        print_help(argv[0]);
     }
     else if(strcmp(argv[1],"-v")==0 || strcmp(argv[1],"--version")==0){
        print_version();
        exit(1); 
     }
     else if(strcmp(argv[1],"-l")==0 || strcmp(argv[1],"--lookup")==0){
        print_available_interfaces();
     }else if(strcmp(argv[1],"-i")==0 || strcmp(argv[1],"--interface")==0){
         if(argc<3){
             printf("Please provide the interface to sniff on . select from the following\n");
             print_available_interfaces();
             printf("Usage: %s -i <interface> [you can lookup the available interfaces using -l]\n",argv[0]);
         }else{

             sniff_arp(argv[2]); 
         }
        
     }
     else{
        printf("Invalid arguments\n");
        print_help(argv[0]);
     }
 }

