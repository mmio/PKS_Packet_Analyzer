#ifdef _MSC_VER
#define _CRT_SECURE_NO_WARNINGS
#endif

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

#define PRT_FIRST 11
#define PRT_LAST 11

char frameTypes[0x10000][512];
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
        size_t size; 
        void *data;
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

        /* Prepisat na subor */
        
        if (f->length[0] >= 0x08)
                strcpy(name, "Ethernet II");
        else {
                /* if (f->payload_fcs[0] == 0xAA) */
                /*         strcpy(name, "IEEE 802.3 - SNAP"); */
                /* else if (f->payload_fcs[0] == 0xE0) */
                /*         strcpy(name, "IEEE 802.3 - IPX"); */
                /* else */
                strcpy(name, frameTypes[f->payload_fcs[0]]); /* Tu by malo byt 2 */

                if (strcmp(name, "") == 0)
                        strcpy(name, "IEEE 802.3 - LLC");
        }
        return name;
}

bool test_ipv4(const DATA *d)
{
        int prot = d->raw.length[0] << 8 | d->raw.length[1];
        if ( prot == get_ether_prot_num("ipv4"))
                return true;
        return false;
}

/* bool test_ipv4_L4 (const DATA *d, char *name, char *l4) { */
/*         if (test_ipv4(d)) { */
/*                 int ip_len = d->raw.payload_fcs[0] & 0xF; */

/*                 int prot = d->raw.payload_fcs[9]; */
/*                 if ( prot  == get_ipv4_prot_num(l4)) { */
                        
                        
/*                         int offset = ip_len * 4; */
/*                         int src_p = d->raw.payload_fcs[offset] << 8 | d->raw.payload_fcs[offset+1]; */
/*                         int dst_p = d->raw.payload_fcs[offset+2] << 8 | d->raw.payload_fcs[offset+3]; */
/*                         if (src_p == get_udp_prot_num(name) || dst_p == get_udp_prot_num(name)) */
/*                                 return true; */
/*                 } */
/*         } */
        
/*         return false; */
/* } */

bool test_ipv4_udp (const DATA *d, char *name) {
        if (test_ipv4(d)) {
                int ip_len = d->raw.payload_fcs[0] & 0xF;

                int prot = d->raw.payload_fcs[9];
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
        if (test_ipv4(d)) {
                int ip_len = d->raw.payload_fcs[0] & 0xF;

                int prot = d->raw.payload_fcs[9];
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

bool test_ip(const DATA *d) { return  (test_ipv4(d)) ? true : false; }
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

void print_header(const char *header)
{
        puts(  "\n--------------------------------");
        printf("%s\n", header);
        puts(  "--------------------------------");
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

        print_header(c->name);
        
        int poradie = 1;
        DATA *iter = c->data;
        while(iter) {
                if ( c->size < 20 || (poradie < PRT_FIRST || poradie > (int)(c->size - PRT_LAST))) {
                        bool printed = false;
                        if (iter->raw.payload_fcs[7] == 1) {
                                DATA *iter2 = c->data;
                                while (iter2) {
                                        if (iter2->raw.payload_fcs[7] == 2 ) {
                                                if (memcmp(&iter->raw.payload_fcs[14],
                                                           &iter2->raw.payload_fcs[24], 4) == 0)
                                                {
                                                        printed = true;
                                                
                                                        printf("Komunikacia c. %d", poradie);
                                                        printf("\nARP Request,");
                                                        printf(" IP adresa ");
                                                        print_ip(&iter->raw.payload_fcs[24]);

                                                        printf(", MAC adresa: ???");
                                                        printf("\nZdrjova IP adresa: ");
                                                        print_ip(&iter->raw.payload_fcs[14]);
                                                        putchar('\n');

                                                        printf("Cielova IP adresa: ");
                                                        print_ip(&iter->raw.payload_fcs[24]);
                                                        print_basic_list(iter);
                                                        dump_raw(iter);
                                                
                                                        printf("\n\nARP Reply,");
                                                        printf(" IP adresa ");
                                                        print_ip(&iter->raw.payload_fcs[24]);
                                                        printf(", MAC adresa: %02X %02X %02X %02X %02X %02X",
                                                               iter2->raw.payload_fcs[8],
                                                               iter2->raw.payload_fcs[9],
                                                               iter2->raw.payload_fcs[10],
                                                               iter2->raw.payload_fcs[11],
                                                               iter2->raw.payload_fcs[12],
                                                               iter2->raw.payload_fcs[13]
                                                                );
                                                        printf("\nZdrjova IP adresa: ");
                                                        print_ip(&iter2->raw.payload_fcs[14]);
                                                        putchar('\n');

                                                        printf("Cielova IP adresa: ");
                                                        print_ip(&iter2->raw.payload_fcs[24]);
                                                        print_basic_list(iter2);
                                                        dump_raw(iter2);
                                                        putchar('\n');
                                                        break;
                                                }
                                        }
                                        iter2 = iter2->next;
                                }
                        }


                        /* Vyskusat */
                        if (printed == false) {
                                printf("Komunikacia c. %d", poradie);
                                printf("\nARP Request,");
                                printf(" IP adresa ");
                                print_ip(&iter->raw.payload_fcs[24]);

                                printf(", MAC adresa: ???");
                                printf("\nZdrjova IP adresa: ");
                                print_ip(&iter->raw.payload_fcs[14]);
                                putchar('\n');

                                printf("Cielova IP adresa: ");
                                print_ip(&iter->raw.payload_fcs[24]);
                                print_basic_list(iter);
                                dump_raw(iter);

                                puts("");
                                puts("ZIADNA ODPOVED");
                        }
                }
                poradie++;
                iter = iter->next;
        }
}

int ip_to_int(uint8_t ip[4])
{
        int in = 0;

        in |= ip[0] << 24;
        in |= ip[1] << 16;
        in |= ip[2] << 8;
        in |= ip[3];

        return in;
}

uint8_t *int_to_ip(int in)
{
        uint8_t *ip = malloc(sizeof *ip * 4);

        ip[0] = (0xFF000000 & in) >> 24;
        ip[1] = (0xFF0000 & in) >> 16;
        ip[2] = (0xFF00 & in) >> 8;
        ip[3] = (0xFF & in);

        return ip;
}

typedef struct ip {
        int ipi;
        size_t amount;
}IP_STAT;

void print_ip_stat(COLLECTOR *main) {
        IP_STAT *pip = calloc(main->size , sizeof *pip);
        
        DATA *iter = main->data;
        while (iter) {
                if (test_ipv4(iter)) {
                        int size = iter->len;
                        int inip = ip_to_int(&iter->raw.payload_fcs[16]);
                        for (size_t i = 0; i < main->size; ++i) {
                                if (pip[i].ipi == inip) {
                                        pip[i].amount += size;
                                        break;
                                } else if (pip[i].ipi == 0) {
                                        pip[i].amount += size;
                                        pip[i].ipi = inip;
                                        break;
                                }
                        }
                }

                iter = iter->next;
        }

        size_t max = 0;
        int max_i = -1;
        for (size_t i = 0; i < main->size; ++i) {
                if (pip[i].ipi == 0)
                        break;

                if (pip[i].amount > max) {
                        max = pip[i].amount;
                        max_i = i;
                }
                
                print_ip(int_to_ip(pip[i].ipi));
                printf(" --> %ldB\n", pip[i].amount);
        }

        printf("Najviac poslal ");
        print_ip(int_to_ip(pip[max_i].ipi));
        printf(" %ldB\n", pip[max_i].amount);
}

void add_list (COLLECTOR* c, DATA *d)
{
        ++c->size;
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

/* void print_list (const COLLECTOR* c) */
/* { */
/*         DATA* iter = c->data; */
/*         print_header(c->name); */

/*         while (iter) { */
/*                 printf("%d\n", iter->num); */
/*                 printf("%x %x\n", iter->raw.dst_addr[1], iter->raw.src_addr[1]); */
/*                 iter = iter->next; */
/*         } */
/*         putchar('\n'); */
/* } */

void print_udp_list(const COLLECTOR* c)
{
        size_t count = 1;
        DATA* iter = c->data;
        print_header(c->name);

        while (iter) {

                if (c->size < 20 || (count < PRT_FIRST || count > (c->size - PRT_LAST))) {
                
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
                }
                count++;
                
                iter = iter->next;
        }
        putchar('\n');
}

void print_tcp_list(const COLLECTOR* c)
{
        size_t count = 1;
        DATA* iter = c->data;
        print_header(c->name);
        while (iter) {

                if ( c->size < 20 || (count < PRT_FIRST || count > (c->size - PRT_LAST))) {
                
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

                }
                count++;
                iter = iter->next;
        }
        putchar('\n');
}



void print_generic_list(const COLLECTOR *c)
{
        size_t count = 1;
        DATA* iter = c->data;
        print_header(c->name);
        while (iter) {
                if ( c->size < 20 || ( count < PRT_FIRST || count > (c->size - PRT_LAST))) {
                        print_basic_list(iter);
                        dump_raw(iter);
                }
                count++;
                iter = iter->next;
        }
}

void print_icmp_list(const COLLECTOR *c)
{
        size_t count = 1;
        DATA* iter = c->data;
        print_header(c->name);

        while (iter) {

                if (c->size < 20 || (count < PRT_FIRST || count > (c->size - PRT_LAST))) {
                
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

                        int offset = 4*(iter->raw.payload_fcs[0] & 0xF);
                        switch (iter->raw.payload_fcs[offset]) {
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

                        count++;
                }
                 
                iter = iter->next;
        }
}

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
        new_c->size = 0;
        new_c->test = test;
        new_c->add = add;
        new_c->print = print;
        new_c->destructor = destruct;

        return new_c;
}

bool test_all()
{
        return true;
}

bool test_llc(const DATA *d)
{
        int len = d->raw.length[0] << 8 | d->raw.length[1];
        if (len < 2048)
                return true;
        return false;
}

COLLECTOR** create_collector_set (int *n)
{
        *n = 11;
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

        collector_set[9] = new_collector("llc", test_llc,  add_list, print_generic_list, destruct);
        collector_set[10] = new_collector("all", test_all, add_list, print_generic_list, destruct);
        
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
                DATA *d = calloc(1,sizeof *d);
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

        /* puts("Select action:"); */
        /* int choice; */
        /* if (scanf("%d", &choice) == 1) { */


        
        /*         switch (choice) { */
        /*         case 0: */
        /*                 cs[0]->print(cs[0]); */
        /*         default: */
        /*                 cs[cn-1]->print(cs[cn-1]); */
        /*         } */
        /* } */
        
        cs[cn-1]->print(cs[cn-1]);
        for (int i = 0; i < cn-1; ++i)
                cs[i]->print(cs[i]);

        //cs[9]->print(cs[9]);
        //putchar('\n');
        printf("POCET LLC je :%ld\n", cs[9]->size );

        print_ip_stat(cs[cn-1]);
        
        return 0;
}

void init_nums();

int main(int argc, char **argv)
{
        init_nums();
        main_loop(argc, argv);
        return 0;
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



        FILE *frame_types = fopen("src/frame_types.txt", "r");
        if (!frame_types) {
                perror("Frame types FILE");
                exit(1);
        }
        while (fscanf(frame_types, "%d %s", &num, name) != EOF)
                strcpy(frameTypes[num], name);
        fclose(frame_types);
}

