#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>

#include <netinet/ip.h>
#include <sys/socket.h>
#include <arpa/inet.h>

#define BYTES_PER_LINE 32
#define MSG_LEN 65536

void print_msg(uint8_t* ,size_t);
char* get_ip_protocol_name(unsigned int);
void print_ip_addr(uint32_t);

char **protocol_table = (char*[])
{
  [1] = "icmp",
  [2] = "igmp",
  [6] = "tcp",
  [17] = "udp"
};

int main(void) {
  int sp = socket(PF_INET, SOCK_RAW, IPPROTO_TCP);
  if (sp < 0) {
      perror("Socket ");
      return EXIT_FAILURE;
  }

  size_t msg_len;
  uint8_t* msg_buffer = malloc(sizeof *msg_buffer * MSG_LEN);
  while (true) {
      msg_len = recvfrom(sp, msg_buffer, MSG_LEN, 0, NULL, NULL);

      if (msg_len < 1) {
          perror("Msg ");
          return EXIT_FAILURE;
      }

      print_msg(msg_buffer, msg_len);
  }

  return EXIT_SUCCESS;
}

void
print_msg(uint8_t* msg_buffer, size_t len)
{
  putchar('\n');
  printf("Length: %lu\n", len);

  struct iphdr *iph = (struct iphdr*)msg_buffer;
  printf("Protocol: %d (%s)\n", iph->protocol, get_ip_protocol_name(iph->protocol));

  printf("Destination: ");
  print_ip_addr(iph->daddr);

  printf("Source: ");
  print_ip_addr(iph->saddr);
  
  for (int i = 0; i < len; ++i)
    {
      if (i != 0 && i % 32 == 0)
        putchar('\n');

      printf("%02X ", msg_buffer[i]);
    }
  putchar('\n');
}

char*
get_ip_protocol_name(unsigned int pn)
{
  return (protocol_table[pn]) ? protocol_table[pn] : "Other";

  /* Old stuff */
  /* switch(n) */
  /*   { */
  /*   case 1 : */
  /*     return "icmp"; */
  /*     break; */
  /*   case 2 : */
  /*     return "igmp"; */
  /*     break; */
  /*   case 6 : */
  /*     return "tcp"; */
  /*     break; */
  /*   case 17: */
  /*     return "udp"; */
  /*     break; */
  /*   default: */
  /*     return "other"; */
  /*   } */
}

void
print_ip_addr(uint32_t addr)
{
  for (size_t i = 0; i < 32; i += 8)
    {
      if (i) putchar('.');
      printf("%d", (addr & (255 << i)) >> i);
    }
  putchar('\n');
}
