/* Use only data analysis and collect all data via an array of COLLECTOR structs
every and each needs a test function, for the main capture(all the frames), there will be
a default collector present with a test that always returns true. every frame has to go through
all the collector tests if a positive frame is found it has to be saved in a linked list(or array maybe)

+
You should also specify what information to collect, you can use a void pointer to an array, and 
specify printing in the print function. I want to use this feature with the ip statistics, but probably will
run in problems

+

 */

#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <inttypes.h>
#include <stdbool.h>

#ifdef __GNUC__ 
	#define u_char unsigned char
	#define u_short unsigned short
	#define u_int unsigned int
#endif

#include <pcap/pcap.h>

#define PRT_FIRST 10
#define PRT_LAST 10 

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

char etherTypes[0x10000][512];
char tcpProts[0x10000][512];
char ip4Prots[0x1000][512];

bool is_etherII(const uint8_t fields[2]);
bool is_ipv4(const uint8_t type[2]);
bool is_tcp(const uint8_t* protocol);
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

/* Contains all transmitting ip addresses + how many B they sent */
typedef struct {
        uint32_t ip;
        long sent;
} IP_list;
IP_list *iplist;
long iplist_len;
void addIp(uint32_t, long);
void print_ip_list();

/* Linked list for frames */
typedef struct node {
        uint8_t dump[1522];
        size_t len;
        struct node *next;
        struct node *prev;
} NODE;
void add_node(const uint8_t*, size_t);
void print_nodes();
NODE *caps;

/* To collect data based on function test */
typedef struct collector {
        char name[250];
        NODE *list;
        bool(*test)(const uint8_t*);
        void(*print)(const struct collector*); /* Must be specifie so that it knows what and how to print */
        void (*destructor)(struct collector*);
} COLLECTOR;
COLLECTOR* new_collector();
/* Also need an array of collectors */
/* Something like this, maybe????? */
/* bool test_for_http(const uint8_t *data) { */
/*         if (*(data + 20) == 0x60) */
/*                 return true; */
/*         return false; */
/* } */
/* void print_http(const uint8_t *data) { */
/*         printf("%d\n", data[22]); */
/* } */

void print_data(const u_char *data, size_t len, size_t pktlen, size_t count)
{
        printf("---%ld----\n", count++);
        for (size_t i = 0; i < len; ++i) {
                if (i && i % 32 == 0)
                        putchar('\n');
                printf("%02X ", data[i]);
        }
        putchar('\n');
        printf("Frame len: %lu\n", pktlen);
        printf("Total len(frame hdr + data + FCS): %lu\n", pktlen + 4);
        
        printf("%s", "Dst MAC:\t");
        PRINT(6);
        putchar('\n');
        
        printf("%s", "Src MAC:\t");
        PRINT(6);
        putchar('\n');

        if (is_etherII(data)) {
                printf("%s\n", "frame: Ethernet II");
                printf("%s%s\n", "EtherType:", etherTypes[data[0]<<8 | data[1]]);

                if (is_ipv4(data)) {
                        ROLL(2);
                        ROLL(9);
                        if (is_tcp(data)) {
                                puts("Analyzing communication");

                        //        Deeper analysis
                        /* Switch for specific stuff */
                                /* Based on type add to linked list of protocols */
                        }
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
}

void data_analysis(const u_char *data, size_t len)
{
        ROLL(12);
        if (is_etherII(data)) {
                if (is_ipv4(data)) {
                        UNROLL(12);
                        add_node(data, len);
                        ROLL(12);
                        ROLL(14);

                        uint32_t ip = data[0] << 24;
                        ip += data[1] << 16;
                        ip += data[2] << 8;
                        ip += data[3];
                        
                        addIp(ip, len);
                        
                        /* if (is_tcp(const uint8_t *protocol)) { */
                        /*         switch() { /\* Protocol ids *\/ */
                        /*         case http: */
                        /*                 add to http linked list/ arp linked list */
                        /*                         /\* At the end print http linked list, with a function *\/ */
                        /*         } */
                        /* } */
                }
        }
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

void init_nums();
int main(int argc, char **argv)
{
        init_nums();
        
        char errbuf[PCAP_ERRBUF_SIZE];
        if (argc != 2) {
                puts("Usage: ./test.c <savefile>");
                return 1;
        }

        int cap_count = get_cap_count(argv[1]);
        
        iplist_len = cap_count;
        iplist = calloc(iplist_len, sizeof *iplist);
        
        pcap_t *handle = pcap_open_offline(argv[1], errbuf);
        if (!handle) {
                puts(errbuf);
                return 1;
        }

        struct pcap_pkthdr *ph = malloc(sizeof *ph);

        const u_char *data;
        int count = 1;
        while ((data = pcap_next(handle, ph))) {
                data_analysis(data, ph->len);
                
                if (cap_count > PRT_FIRST + PRT_LAST)
                        if (count <= PRT_FIRST || count > cap_count - PRT_LAST)
                                print_data(data, ph->caplen, ph->len, count);
                count++;
        }

        puts("Statistika IP odosielatelov");
        print_ip_list();

        pcap_close(handle);
        //getchar();
        //print_nodes();
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

bool is_ipv4(const uint8_t type[2])
{
        if ((type[0]<<8 | type[1]) == 0x0800)
                return true;
        return false;
}

bool is_tcp(const uint8_t* protocol) {
        if (protocol[0] == 0x06)
                return true;
        return false;
}

void addIp(uint32_t ip, long sent)
{
        for (long i = 0; i < iplist_len; ++i) {
                if (iplist[i].ip == ip) {
                        iplist[i].sent += sent;
                        break;
                }

                if (iplist[i].ip == 0) {
                        iplist[i].ip = ip;
                        iplist[i].sent = sent;
                        break;
                }
        }
}

void print_ip_list()
{
        long max_i = 0;

        for (long i = 0; i < iplist_len; ++i) {
                if (iplist[i].ip == 0)
                        break;

                if (iplist[i].sent > iplist[max_i].sent)
                        max_i = i;

                int ip = iplist[i].ip;
                printf("%d.%d.%d.%d -> sent %ld\n",
                       (ip & 0xFF000000) >> 24,
                       (ip & 0xFF0000) >> 16,
                       (ip & 0xFF00) >> 8,
                       (ip & 0xFF),
                        iplist[i].sent);
        }

        puts("Najviac poslal");
        printf("%d.%d.%d.%d -> sent %ld\n",
               (iplist[max_i].ip & 0xFF000000) >> 24,
               (iplist[max_i].ip & 0xFF0000) >> 16,
               (iplist[max_i].ip & 0xFF00) >> 8,
               (iplist[max_i].ip & 0xFF),
                iplist[max_i].sent);
}

void add_node(const uint8_t *d, size_t l)
{
        NODE *new_node = calloc(1, sizeof *new_node);
        memcpy(new_node->dump, d, l);
        new_node->len = l;
        new_node->next = caps;
        caps = new_node;
}

void print_nodes()
{
        NODE *iter = caps;
        while (iter) {
                printf("Len %ld\n", iter->len);
                iter = iter->next;
        }
}

void init_nums()
{
        char name[512];
        int num;

        FILE *eth2f = fopen("src/eth_prots.txt", "r");
        if (!eth2f) {
                perror("ETH FILE");
                exit(1);
        }
        while (fscanf(eth2f, "%d %s", &num, name) != EOF)
                strcpy(etherTypes[num], name);
        fclose(eth2f);
        
        FILE *ipv4f = fopen("src/ip4_prots.txt", "r");
        if (!ipv4f) {
                perror("IP FILE");
                exit(1);
        }
        while (fscanf(ipv4f, "%d %s", &num, name) != EOF)
                strcpy(ip4Prots[num], name);
        fclose(ipv4f);
        
        FILE *tcpf = fopen("src/tcp_prots.txt", "r");
        if (!tcpf) {
                perror("TCP FILE");
                exit(1);
        }
        while (fscanf(tcpf, "%d %s", &num, name) != EOF)
                strcpy(tcpProts[num], name);
        fclose(tcpf);
}
