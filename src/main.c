#include <stdio.h>
#include <stdlib.h>
#include <inttypes.h>
#include <stdbool.h>

#ifdef __linux__ 
	#define u_char unsigned char
	#define u_short unsigned short
	#define u_int unsigned int
#endif

#include <pcap/pcap.h>

#define PRT_FIRST 20
#define PRT_LAST 0 

#define ROLL(x)                                                  \
        {                                                        \
                for (size_t i = 0; i < (x); ++i, data++);        \
        }                                                        \

#define UNROLL(x)                                                \
        {                                                        \
                for (size_t i = 0; i < (x); ++i, data--);        \
        }                                                        \

#define PRINT(x)                                                 \
        {                                                        \
                for (size_t i = 0; i < (x); ++i, data++)         \
                        printf("%02X ", *data);                  \
        }                                                        \
                

typedef struct {
        uint8_t dst_addr[6];
        uint8_t src_addr[6];
} MAC;

typedef struct {
        MAC mac;
        uint8_t l_o_et[2];
        uint8_t payload_fcs[1504];
} FRAME;

char* etherTypes[0x10000] = {
        [0x0800] = "IPv4",
        [0x0806] = "ARP"
};

bool is_etherII(const uint8_t fields[2]);
bool is_ipv4_tcp(const uint8_t type[2]);
char* get_ethertype(const uint8_t fields[2]);
void print_bytes(const uint8_t *data, size_t len);

void print_struct_data(const u_char *data, size_t caplen, size_t wire_len, size_t count)
{
        printf("---%ld----\n", count++);

        const FRAME *frm = (FRAME*)data;
        
        printf("%s", "Destination MAC: ");
        print_bytes(frm->mac.dst_addr, 6);
        putchar('\n');
        
        printf("%s", "Source MAC: ");
        print_bytes(frm->mac.src_addr, 6);
        putchar('\n');

        for (size_t i = 0; i < caplen; ++i)
                printf("%02X ", data[i]);
        putchar('\n');

        printf("Len on wire: %ld\n", wire_len);
}

void print_data(const u_char *data, size_t len, size_t pktlen, size_t count)
{
        printf("---%ld----\n", count++);
        for (size_t i = 0; i < len; ++i) {
                if (i && i % 32 == 0)
                        putchar('\n');
                printf("%02X ", data[i]);
        }
        putchar('\n');
        printf("Captured len: %lu\n", len);
        printf("Total len: %lu\n", pktlen);
        
        printf("%s", "Dst MAC:\t");
        PRINT(6);
        putchar('\n');
        
        printf("%s", "Src MAC:\t");
        PRINT(6);
        putchar('\n');

        if (is_etherII(data)) {
                printf("%s\n", "frame: Ethernet II");
                printf("%s%s\n", "EtherType:", etherTypes[data[0]<<8 | data[1]]);

                if (is_ipv4_tcp(data)) {
                        
                }
        } else {
                printf("%s\n", "frame: IEEE 802.3");
                printf("%s%dB\n", "Length: ", data[0] <<8 | data[1]);
                ROLL(3);        /* To ssap */

             
                switch (data[0]) {
                case 0xAA:
                        printf("%s\n", "Type: SNAP");
                        break;
                case 0xE0:
                        printf("%s\n", "Type: IPX");
                        break;
                default:
                        puts("Type: LLC");
                }
                return;
        }

        
        /* Get frame type */
        /* if ipv4 Get protocol type */
        /* Get tcp or udp */
        /* Get higher protocol */
        /* if arp  */
        

        
        /* printf("\n--------\n"); */
                //putchar('\n');
}

size_t get_cap_count(char *savefile)
{
        size_t cap_count = 0;
        char errbuf[PCAP_ERRBUF_SIZE];
        pcap_t *handle = pcap_open_offline(savefile, errbuf);
        if (!handle) {
                puts(errbuf);
                exit(1);
        }

        struct pcap_pkthdr *ph = malloc(sizeof *ph);
        while (pcap_next(handle, ph))
                cap_count++;

        pcap_close(handle);
        return cap_count;
}

int main(int argc, char **argv)
{
        char errbuf[PCAP_ERRBUF_SIZE];
        if (argc != 2) {
                puts("Usage: ./test.c <savefile>");
                return 1;
        }

        int cap_count = get_cap_count(argv[1]);
        
        pcap_t *handle = pcap_open_offline(argv[1], errbuf);
        if (!handle) {
                puts(errbuf);
                return 1;
        }

        struct pcap_pkthdr *ph = malloc(sizeof *ph);

        const u_char *data;
        int count = 1;
        while ((data = pcap_next(handle, ph))) {
                if (cap_count > PRT_FIRST + PRT_LAST)
                        if (count <= PRT_FIRST || count > cap_count - PRT_LAST)
                                print_data(data, ph->caplen, ph->len, count);
                count++;
        }
        
        pcap_close(handle);
		getchar();
        return 0;
}

bool is_etherII(const uint8_t fields[2])
{
        if (((fields[0] << 8) | fields[1]) >= 0x0600)
                return true;
        return false;
}

void print_bytes(const uint8_t *data, size_t len)
{
        for (size_t i = 0; i < len; ++i, data++)
                printf("%02X ", *data);
}

bool is_ipv4_tcp(const uint8_t type[2])
{
        if ((type[0]<<8 | type[1]) == 0x0800)
                return true;
        return false;
}
