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

#define PRT_FIRST 20
#define PRT_LAST 20

char etherTypes[0x10000][512];
char tcpProts[0x10000][512];
char udpProts[0x10000][512];
char ip4Prots[0x1000][512];

typedef struct {
        uint8_t dst_addr[6];
        uint8_t src_addr[6];
        uint8_t length[2];
        uint8_t payload_fcs[1504];
} FRAME;

typedef struct data {
        int len;
        int num;
        FRAME raw;
        struct data *next;
} DATA;  

typedef struct collector {
        char name[250];
        DATA *data;
        DATA *tail;
        bool (*test)(const DATA*);
        void (*add)(struct collector*, DATA*);
        void (*print)(const struct collector*);
        void (*destructor)(struct collector*);
} COLLECTOR;

COLLECTOR* new_collector(char *name,
                         bool(*test)(const DATA*),
                         void(*add)(struct collector*,DATA*),
                         void(*print)(const COLLECTOR*),
                         void(*destruct)(COLLECTOR*)
        );

/* Temporary place for functions */

int get_ether_prot_num(char *name) {
        for (int i = 1; i < 0x10000; ++i)
                if (strcmp(name, etherTypes[i]) == 0)
                        return i;
        return 0;
}

int get_ipv4_prot_num(char *name)
{
        for (int i = 1; i < 0x1000; ++i)
                if (strcmp(name, ip4Prots[i]) == 0)
                        return i;
        return 0;
}

int get_tcp_prot_num(char *name)
{
        for (int i = 1; i < 0x1000; ++i)
                if (strcmp(name, tcpProts[i]) == 0)
                        return i;
        return 0;
}

int get_udp_prot_num(char *name)
{
        for (int i = 1; i < 0x1000; ++i)
                if (strcmp(name, udpProts[i]) == 0)
                        return i;
        return 0;
}

char * get_frame_type(FRAME *f)
{
        char *name = malloc(sizeof *name * 40);

        if (f->length[0] >= 0x08)
                strcpy(name, "Ethernet II");
        else {
                if (f->payload_fcs[0] == 0xAA)
                        strcpy(name, "IEEE 802.3 - SNAP");
                else if (f->payload_fcs[0] == 0xE0)
                        strcpy(name, "IEEE 802.3 - IPX");
                else
                        strcpy(name, "IEEE 802.3 - LLC");
        }
        return name;
}

/* TMP END */

bool test_ipv4(const DATA *d)
{
        int prot = d->raw.length[0] << 8 | d->raw.length[1];
        if ( prot == get_ether_prot_num("ipv4"))
                return true;
        return false;
}

bool test_ipv4_udp (const DATA *d, char *name) {
        int prot = d->raw.length[0] << 8 | d->raw.length[1];
        if ( prot == get_ether_prot_num("ipv4")) {
                int ip_len = d->raw.payload_fcs[0] & 0xF;

                prot = d->raw.payload_fcs[9];
                if ( prot  == get_ipv4_prot_num("udp")) {
                        
                        
                        int offset = ip_len * 4;
                        int src_p = d->raw.payload_fcs[offset] << 8 | d->raw.payload_fcs[offset+1];
                        int dst_p = d->raw.payload_fcs[offset+2] << 8 | d->raw.payload_fcs[offset+3];
                        if (src_p == get_udp_prot_num(name) || dst_p == get_udp_prot_num(name))
                                return true;
                }
        }
        
        return false;
}

bool test_ipv4_tcp (const DATA *d, char *name) {
        int prot = d->raw.length[0] << 8 | d->raw.length[1];
        if ( prot == get_ether_prot_num("ipv4")) {
                int ip_len = d->raw.payload_fcs[0] & 0xF;

                prot = d->raw.payload_fcs[9];
                if ( prot  == get_ipv4_prot_num("tcp")) {

                        int offset = ip_len * 4;
                        int src_p = d->raw.payload_fcs[offset] << 8 | d->raw.payload_fcs[offset+1];
                        int dst_p = d->raw.payload_fcs[offset+2] << 8 | d->raw.payload_fcs[offset+3];
                        if (src_p == get_tcp_prot_num(name) || dst_p == get_tcp_prot_num(name))
                                return true;
                }
        }
        
        return false;
}

bool test_http(const DATA *d) { return  (test_ipv4_tcp(d, "http")) ? true : false; }
bool test_https (const DATA *d) { return  (test_ipv4_tcp(d, "https")) ? true : false; }
bool test_telnet (const DATA *d) { return  (test_ipv4_tcp(d, "telnet")) ? true : false; }
bool test_ssh (const DATA *d) { return  (test_ipv4_tcp(d, "ssh")) ? true : false; }
bool test_ftp_data (const DATA *d) { return  (test_ipv4_tcp(d, "ftp_data")) ? true : false; }
bool test_ftp_com (const DATA *d) { return  (test_ipv4_tcp(d, "ftp_com")) ? true : false; }
bool test_tftp (const DATA *d) { return  (test_ipv4_udp(d, "tftp")) ? true : false; }
bool test_icmp(const DATA *d)
{
        if (test_ipv4(d)) {
                int prot = d->raw.payload_fcs[9];
                if ( prot  == get_ipv4_prot_num("icmp"))
                        return true;
        }
        return false;
}
bool test_arp(const DATA *d)
{
        int prot = d->raw.length[0] << 8 | d->raw.length[1];
        if (prot == get_ether_prot_num("arp"))
                return true;
        return false;
}

void print_ip(uint8_t ip[4])
{
        printf("%d.%d.%d.%d", ip[0], ip[1], ip[2], ip[3]);
}

void print_basic_list (DATA*);
void print_generic_list(const COLLECTOR *);
void dump_raw(const DATA*);
void afind_arp_pairs(const COLLECTOR *c)
{
        puts("--------------------------------------------");
        puts(c->name);
        puts("--------------------------------------------");
        
        int poradie = 1;
        DATA *iter = c->data;
        while(iter) {
                if (iter->raw.payload_fcs[7] == 1) {
                        DATA *iter2 = c->data;
                        while (iter2) {
                                if (iter2->raw.payload_fcs[7] == 2 ) {
                                        if (memcmp(&iter->raw.payload_fcs[14],
                                                   &iter2->raw.payload_fcs[24], 4) == 0)
                                        {
                                                printf("Komunikacia c. %d", poradie);
                                                printf("\nARP Request");
                                                print_basic_list(iter);
                                                dump_raw(iter);

                                                printf("\nARP Reply");
                                                print_basic_list(iter2);
                                                dump_raw(iter2);
                                                
                                                break;
                                        }
                                }
                                iter2 = iter2->next;
                        }
                }
                iter = iter->next;
        }
}

void add_list (struct collector* c, DATA *d)
{
        if (c->tail == NULL) {
                c->data = c->tail = d;
        } else {
                c->tail->next = d;
                c->tail = d;
        }
}

void dump_raw(const DATA* d)
{
        uint8_t *raw_data = (uint8_t*)&(d->raw);
        for (int i = 0; i < d->len; ++i) {
                if (i % 8 == 0)
                        printf("  ");
                        
                if (i % 32 == 0)
                        putchar('\n');
                        
                printf("%02X ", raw_data[i]);
        }
}

void print_basic_list (DATA* iter)
{
        printf("\n\nRamec c %d\n", iter->num);

        printf("Dlzka ramca poskytnuta PCAP API: %d\n", iter->len);
        printf("Dlzka ramca prenasana po mediu: %d\n", iter->len+4);

        puts(get_frame_type(&iter->raw));

        printf("Zdrojova MAC adresa: %02X %02X %02X %02X %02X %02X\n",
               iter->raw.dst_addr[0],
               iter->raw.dst_addr[1],
               iter->raw.dst_addr[2],
               iter->raw.dst_addr[3],
               iter->raw.dst_addr[4],
               iter->raw.dst_addr[5]
                );

        printf("Cielova MAC adresa: %02X %02X %02X %02X %02X %02X",
               iter->raw.src_addr[0],
               iter->raw.src_addr[1],
               iter->raw.src_addr[2],
               iter->raw.src_addr[3],
               iter->raw.src_addr[4],
               iter->raw.src_addr[5]
                );
        putchar('\n');
}

void print_list (const COLLECTOR* c)
{
        DATA* iter = c->data;
        puts("--------------------------------------------");
        puts(c->name);
        puts("--------------------------------------------");

        while (iter) {
                printf("%d\n", iter->num);
                printf("%x %x\n", iter->raw.dst_addr[1], iter->raw.src_addr[1]);
                iter = iter->next;
        }
}

void print_udp_list(const COLLECTOR* c)
{
        DATA* iter = c->data;
        puts("\n--------------------------------------------");
        puts(c->name);
        puts("--------------------------------------------");

        while (iter) {
                print_basic_list(iter);

                puts("IPv4");
                printf("Zdrojova ip adresa: %d.%d.%d.%d\n",
                       iter->raw.payload_fcs[12],
                       iter->raw.payload_fcs[13],
                       iter->raw.payload_fcs[14],
                       iter->raw.payload_fcs[15]
                        );
                printf("Cielova ip adresa: %d.%d.%d.%d\n",
                       iter->raw.payload_fcs[16],
                       iter->raw.payload_fcs[17],
                       iter->raw.payload_fcs[18],
                       iter->raw.payload_fcs[19]
                        );

                int ip4len = iter->raw.payload_fcs[0] & 0xF;
                int off = ip4len * 4;
                printf("UDP\nzdrojovy port: %d\n", iter->raw.payload_fcs[off] << 8 | iter->raw.payload_fcs[off + 1]);
                printf("cielovy port: %d", iter->raw.payload_fcs[off+2] << 8 | iter->raw.payload_fcs[off + 3]);
                
                dump_raw(iter);
                
                iter = iter->next;
        }
}

void print_tcp_list(const COLLECTOR* c)
{
        DATA* iter = c->data;
        puts("\n--------------------------------------------");
        puts(c->name);
        puts("--------------------------------------------");

        while (iter) {
                print_basic_list(iter);

                puts("IPv4");
                printf("Zdrojova ip adresa: %d.%d.%d.%d\n",
                       iter->raw.payload_fcs[12],
                       iter->raw.payload_fcs[13],
                       iter->raw.payload_fcs[14],
                       iter->raw.payload_fcs[15]
                        );
                printf("Cielova ip adresa: %d.%d.%d.%d\n",
                       iter->raw.payload_fcs[16],
                       iter->raw.payload_fcs[17],
                       iter->raw.payload_fcs[18],
                       iter->raw.payload_fcs[19]
                        );

                int ip4len = iter->raw.payload_fcs[0] & 0xF;
                int off = ip4len * 4;
                printf("TCP\nzdrojovy port: %d\n", iter->raw.payload_fcs[off] << 8 | iter->raw.payload_fcs[off + 1]);
                printf("cielovy port: %d", iter->raw.payload_fcs[off+2] << 8 | iter->raw.payload_fcs[off + 3]);
                
                dump_raw(iter);
                
                iter = iter->next;
        }
}



void print_generic_list(const COLLECTOR *c)
{
        DATA* iter = c->data;
        puts("--------------------------------------------");
        puts(c->name);
        puts("--------------------------------------------");

        while (iter) {
                print_basic_list(iter);
                dump_raw(iter);
                iter = iter->next;
        }
}

void print_icmp_list(const COLLECTOR *c)
{
        DATA* iter = c->data;
        puts("\n--------------------------------------------");
        puts(c->name);
        puts("--------------------------------------------");

        while (iter) {
                print_basic_list(iter);

                puts("IPv4");
                printf("Zdrojova ip adresa: %d.%d.%d.%d\n",
                       iter->raw.payload_fcs[12],
                       iter->raw.payload_fcs[13],
                       iter->raw.payload_fcs[14],
                       iter->raw.payload_fcs[15]
                        );

                 printf("Cielova ip adresa: %d.%d.%d.%d\n",
                       iter->raw.payload_fcs[16],
                       iter->raw.payload_fcs[17],
                       iter->raw.payload_fcs[18],
                       iter->raw.payload_fcs[19]
                        );

                 char *msg = malloc(sizeof *msg * 50);

                 switch (iter->raw.payload_fcs[14]) {
                 case 3:
                         strcpy(msg, "Host unreachable");
                         break;
                 case 0:
                         strcpy(msg, "Echo Reply");
                         break;
                 case 5:
                         strcpy(msg, "Redirect");
                         break;
                 case 8:
                         strcpy(msg, "Echo");
                         break;
                 case 11:
                         strcpy(msg, "Time Exceede");
                         break;
                 default:
                         strcpy(msg, "Unknown");
                 }

                 printf("Type: %s\n", msg);

                 dump_raw(iter);
                 
                iter = iter->next;
        }
}

/* void print_arp_list(const COLLECTOR* c) { */
        
/* } */

void destruct () { }

COLLECTOR* new_collector(char *name,
                         bool(*test)(const DATA*),
                         void(*add)(COLLECTOR*, DATA*),
                         void(*print)(const COLLECTOR*),
                         void(*destruct)(COLLECTOR*))
{
        COLLECTOR *new_c = malloc(sizeof *new_c);
        strcpy(new_c->name, name);
        new_c->data = NULL;
        new_c->tail = NULL;
        new_c->test = test;
        new_c->add = add;
        new_c->print = print;
        new_c->destructor = destruct;

        return new_c;
}

COLLECTOR** create_collector_set (int *n)
{
        *n = 10;
        COLLECTOR **collector_set = malloc(sizeof *collector_set * (*n));
        
        collector_set[0] = new_collector("http", test_http, add_list, print_tcp_list, destruct);
        collector_set[1] = new_collector("https", test_https, add_list, print_tcp_list, destruct);
        collector_set[2] = new_collector("telnet", test_telnet, add_list, print_tcp_list, destruct);
        collector_set[3] = new_collector("ssh", test_ssh, add_list, print_tcp_list, destruct);
        collector_set[4] = new_collector("ftp_data", test_ftp_data, add_list, print_tcp_list, destruct);
        collector_set[5] = new_collector("ftp_com", test_ftp_com, add_list, print_tcp_list, destruct);
        collector_set[6] = new_collector("tftp", test_tftp, add_list, print_udp_list, destruct);

        collector_set[7] = new_collector("icmp", test_icmp, add_list, print_icmp_list, destruct);
        collector_set[8] = new_collector("arp", test_arp, add_list, afind_arp_pairs , destruct);
        collector_set[9] = new_collector("all", test_http, add_list, print_generic_list, destruct);
        
        return collector_set;
}

int main_loop(int argc, char *argv[]) {
        char errbuf[PCAP_ERRBUF_SIZE];
        if (argc != 2) {
                puts("Usage: ./packet_analyzer.out <savefile>");
                return 1;
        }
        
        pcap_t *handle = pcap_open_offline(argv[1], errbuf);
        if (!handle) {
                puts(errbuf);
                return 1;
        }

        int cn;
        COLLECTOR** cs = create_collector_set(&cn);
        
        struct pcap_pkthdr *ph = malloc(sizeof *ph);
        const u_char *data;
        int count = 1;
        while ((data = pcap_next(handle, ph))) {
                DATA *d = malloc(sizeof *d);
                d->raw = *(FRAME*)(data);
                d->len = ph->caplen;
                d->num = count;

                DATA *dl = malloc(sizeof *dl);
                memcpy(dl, d, sizeof *dl);
                cs[cn-1]->add(cs[cn-1], dl);
        
                for (int i = 0; i < cn-1; ++i)
                        if (cs[i]->test(d)) {
                                cs[i]->add(cs[i], d);
                                break;
                        }
                
                count++;
        }

        cs[cn-1]->print(cs[cn-1]);
        for (int i = 0; i < cn-1; ++i)
                cs[i]->print(cs[i]);
                

        return 0;
}

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
                





bool is_etherII(const uint8_t fields[2]);
bool is_ipv4(const uint8_t type[2]);
bool is_tcp(const uint8_t* protocol);
char* get_ethertype(const uint8_t fields[2]);
void print_bytes(const uint8_t *data, size_t len);

typedef struct arp_frame {
        uint8_t dump[1522];
} ARP_FRAME;

typedef struct arp_pair {
        ARP_FRAME *request;
        ARP_FRAME *reply;
} ARP_PAIR;

void print_struct_data(const u_char *data, size_t caplen, size_t wire_len, size_t count)
{
        printf("---%ld----\n", count++);

        const FRAME *frm = (FRAME*)data;
        
        printf("%s", "Destination MAC: ");
        print_bytes(frm->dst_addr, 6);
        putchar('\n');
        
        printf("%s", "Source MAC: ");
        print_bytes(frm->src_addr, 6);
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
        int p;
} NODE;

typedef struct list {
        NODE *head;
}LIST;

typedef struct lists {
        LIST *http;
        LIST *https;
        LIST *telnet;
        LIST *ssh;
        LIST *ftp_com;
        LIST *ftp_data;
        LIST *tftp;
        LIST *arp_raw;
} LISTS;
LIST *create_list();

void add_node(const uint8_t*, size_t);
LIST* add_node_2(LIST *ls, const uint8_t *d, size_t l, int p);
void print_nodes();
void print_nodes_2(NODE *nd);
NODE *caps;

NODE *icmp;

/* To collect data based on function test */

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

void print_data(const u_char *data, size_t len, size_t pktlen, size_t count, LISTS *lsts)
{
        const u_char *start = data;
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
                        /* Osetrit viac ako 5*4 hlavicku ipv4 */
                        ROLL(2);
                        ROLL(9);

                        /* Move this to data analysis */
                        if (is_tcp(data)) {
                                puts("Analyzing communication");

                                ROLL(11);
                                int src_port = ((*data) << 8) | *(data+1);
                                printf("---SOURCE PORT---%x\n", src_port);
                                ROLL(2);
                                int dst_port = ((*data) << 8) | *(data+1);
                                printf("---DESTINation PORT---%x\n", dst_port);

                                /* Try searching for the protocols, no implicit stuff */

                                /* get_port_n_by_name(); */
                                
                                switch(src_port) {
                                case 8008:
                                case 8080:
                                case 80:
                                        lsts->http = add_node_2(lsts->http, start, len, count);
                                        return;
                                case 443:
                                        lsts->https = add_node_2(lsts->https, start, len, count);
                                        return;
                                case 23:
                                        lsts->telnet = add_node_2(lsts->telnet, start, len, count);
                                        return;
                                case 22:
                                        lsts->ssh = add_node_2(lsts->ssh, start, len, count);
                                        return;
                                case 21:
                                        lsts->ftp_com = add_node_2(lsts->ftp_com, start, len, count);
                                        return;
                                case 20:
                                        lsts->ftp_data = add_node_2(lsts->ftp_data, start, len, count);
                                        return;
                                case 69:
                                        lsts->tftp = add_node_2(lsts->tftp, start, len, count);
                                        return;
                                }

                                switch(dst_port) {
                                case 8008:
                                case 8080:
                                case 80:
                                        lsts->http = add_node_2(lsts->http,start, len, count);
                                        break;
                                case 443:
                                        lsts->https = add_node_2(lsts->https, start, len, count);
                                        break;
                                case 23:
                                        lsts->telnet = add_node_2(lsts->telnet, start, len, count);
                                        break;
                                case 22:
                                        lsts->ssh = add_node_2(lsts->ssh, start, len, count);
                                        break;
                                case 21:
                                        lsts->ftp_com = add_node_2(lsts->ftp_com, start, len, count);
                                        break;
                                case 20:
                                        lsts->ftp_data = add_node_2(lsts->ftp_data, start, len, count);
                                        break;
                                case 69:
                                        lsts->tftp = add_node_2(lsts->tftp, start, len, count);
                                        break;
                                }
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

bool is_arp(const uint8_t data[2]) {
        if (2054 == ((data[0] << 8) | data[1]))
                return true;
        return false;
}

void data_analysis(const u_char *data, size_t len, LISTS *lsts)
{
        add_node(data, len);
        
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
                } else if (is_arp(data)) {
                        lsts->arp_raw = add_node_2(lsts->arp_raw, data, len, 1);
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

void init_lists(LISTS*);
void init_nums();

int get_list_len(LIST *ls) {
        int counter = 0;
        NODE *iter = ls->head;
        while(iter) {
                counter++;
                iter = iter->next;
        }

        return counter;
}

bool is_arp_request(const uint8_t *data)
{
        ROLL(4);
        ROLL(5);

        if (data[0] == 1)
                return true;
        
        return false;
}

bool is_arp_reply(const uint8_t *data)
{
        ROLL(4);
        ROLL(5);

        if (data[0] == 2)
                return true;
        
        return false;
}

bool is_arp_pair(const uint8_t *rq, const uint8_t *re)
{
        int wants_to_know[4];
        int responds_to[4];
        
        const uint8_t *data = rq;
        ROLL(16);

        for (int i = 0; i < 4; ++i)
                wants_to_know[i] = *(data+i);

        data = re;
        ROLL(26);

        for (int i = 0; i < 4; ++i)
                responds_to[i] = *(data+i);

        for (int i = 0; i < 4; ++i)
                if (wants_to_know[i] != responds_to[i])
                        return false;
        return true;
}

int find_arp_pairs(LIST *ls , ARP_PAIR *alp)
{
        int counter = 0;
        NODE *iter = ls->head;
        while(iter) {
                if (is_arp_request(iter->dump)) {
                        NODE *iter2 = ls->head;
                        while (iter2) {
                                if (is_arp_reply(iter2->dump)) {
                                        if (is_arp_pair(iter->dump, iter2->dump)) {
                                                alp[counter].request = malloc(sizeof(ARP_FRAME));
                                                alp[counter].reply = malloc(sizeof(ARP_FRAME));
                                                
                                                memcpy(alp[counter].request->dump, iter->dump, 30);
                                                memcpy(alp[counter++].reply->dump, iter2->dump, 30);
                                                break;
                                        }
                                }
                                iter2 = iter2->next;
                        }
                }
                iter = iter->next;
        }
        
        return counter;
}

void print_arp_pairs(ARP_PAIR *alp, int pair_count)
{
        for (int i = 0; i < pair_count; ++i) {
                printf("Komunikacia c. %d\n", i+1);
                printf("ARP-Request. IP Adresa %d.%d.%d.%d ", alp[i].request->dump[16],
                       alp[i].request->dump[17],
                       alp[i].request->dump[18],
                       alp[i].request->dump[19]
                        );
                puts("MAC Adresa: ???");

                printf("ARP-Reply. IP Adresa %d.%d.%d.%d ", alp[i].reply->dump[26],
                       alp[i].reply->dump[27],
                       alp[i].reply->dump[28],
                       alp[i].reply->dump[29]
                        );
                printf("Mac Adresa: %02X %02X %02X %02X %02X %02X\n", alp[i].reply->dump[10],
                       alp[i].reply->dump[11],
                       alp[i].reply->dump[12],
                       alp[i].reply->dump[13],
                       alp[i].reply->dump[14],
                       alp[i].reply->dump[15]
                        );
        }
}

int main(int argc, char **argv)
{
        init_nums();
        main_loop(argc, argv);
        return 0;
        LISTS *lsts = calloc(1, sizeof *lsts);
        init_lists(lsts);
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
                data_analysis(data, ph->len, lsts);
                
                if (cap_count > PRT_FIRST + PRT_LAST)
                        if (count <= PRT_FIRST || count > cap_count - PRT_LAST)
                                print_data(data, ph->caplen, ph->len, count, lsts);
                count++;
        }

        int arp_len = get_list_len(lsts->arp_raw);
        ARP_PAIR *alp = malloc(sizeof(ARP_PAIR) * arp_len);
        int pair_count =find_arp_pairs(lsts->arp_raw, alp);
        print_arp_pairs(alp, pair_count);
        return 0;
        puts("Statistika IP odosielatelov");
        print_ip_list();

        puts("--------------HTTP--------------");
        print_nodes_2(lsts->http->head);
        puts("--------------HTTPS--------------");
        print_nodes_2(lsts->https->head);
        puts("--------------SSH--------------");
        print_nodes_2(lsts->ssh->head);
        puts("--------------FTP_COM--------------");
        print_nodes_2(lsts->ftp_com->head);
        puts("--------------FTP_DATA--------------");
        print_nodes_2(lsts->ftp_data->head);
        puts("--------------TFTP--------------");
        print_nodes_2(lsts->tftp->head);
        puts("--------------TELNET--------------");
        print_nodes_2(lsts->telnet->head);

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

LIST* add_node_2(LIST *ls, const uint8_t *d, size_t l, int p)
{
        NODE *n = malloc(sizeof *n);
        memcpy(n->dump, d, l);
        n->p = p;
        n->len = l;
        n->next = ls->head;
        ls->head = n;
        printf("\n--->%p\n", (void*)ls->head);

        return ls;
}

void print_nodes()
{
        NODE *iter = caps;
        while (iter) {
                printf("Len %ld\n", iter->len);
                iter = iter->next;
        }
}

void print_nodes_2(NODE *nd)
{
        NODE *iter = nd;
        iter = iter->next;
        while (iter) {
                if (iter->p == 0) {
                        iter = iter->next;
                        continue;
                }
                putchar('\n');
                
                printf("ramec %d\n", iter->p);
                printf("Dlzka poskytnute PCAP API - %ld B\n", iter->len);
                printf("Dlzka prenasana po mediu - %ld B\n", iter->len + 4);
                puts("EthernetII");
                printf("Zdrojova MAC adresa: ");

                uint8_t *data = iter->dump;
                PRINT(6); putchar('\n');

                printf("Cielova MAC adresa: ");
                PRINT(6); putchar('\n');

                ROLL(2);
                ROLL(12);
                puts("IPv4");
                printf("Zdrojova IP adresa: ");

                printf("%u.%u.%u.%u\n", *data, *(data+1), *(data+2), *(data+3));
                ROLL(4);

                printf("Cielova IP adresa: ");
                
                printf("%u.%u.%u.%u\n", *data, *(data+1), *(data+2), *(data+3));

                puts("TCP");

                printf("Zdrojovy port: ");
                ROLL(4);
                printf("%u\n", (data[0] << 8) | data[1]);

                printf("Cielovy port: ");
                ROLL(2);
                printf("%u\n", (data[0] << 8) | data[1]);
                
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

        FILE *udpf = fopen("src/udp_prots.txt", "r");
        if (!udpf) {
                perror("UDP FILE");
                exit(1);
        }
        while (fscanf(udpf, "%d %s", &num, name) != EOF)
                strcpy(udpProts[num], name);
        fclose(udpf);
}

LIST *create_list()
{
        LIST* l;
        l = malloc(sizeof *l);
        l->head = malloc(sizeof *(l->head));
        return l;
}

void init_lists(LISTS* ls)
{
        ls->http = create_list();
        ls->https = create_list();
        ls->ssh = create_list();
        ls->telnet = create_list();
        ls->tftp = create_list();
        ls->ftp_com = create_list();
        ls->ftp_data = create_list();
        ls->arp_raw = create_list();
}
