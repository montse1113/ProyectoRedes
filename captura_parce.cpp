/*
 * Fase 3: Parseo de cabeceras Ethernet, IP y TCP/UDP/ICMP
 * Proyecto Packet Sniffer - Redes I
 *
 * Compilar: gcc capture_parse.c -o capture_parse -lpcap
 * Ejecutar: sudo ./capture_parse wlo1
 *
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <time.h>
#include <pcap.h>
#include <arpa/inet.h>     /* inet_ntoa, ntohs, ntohl */
#include <netinet/in.h>

#define SNAP_LEN  65535
#define PROMISC   1
#define TIMEOUT   1000

#define ETHER_ADDR_LEN  6
#define ETHER_HDR_LEN  14

/* EtherTypes comunes */
#define ETHERTYPE_IP     0x0800
#define ETHERTYPE_ARP    0x0806
#define ETHERTYPE_IPV6   0x86DD

/* Protocolos sobre IP */
#define IPPROTO_ICMP_  1
#define IPPROTO_TCP_   6
#define IPPROTO_UDP_  17

/* ---- Definición de structs que mapean a las cabeceras reales ---- */

/*
 * Cabecera Ethernet. __attribute__((packed)) le dice al compilador
 * que NO inserte padding entre campos, porque los bytes deben quedar
 * exactamente como llegan por la red.
 */
struct ethernet_header {
    u_char  dest_mac[ETHER_ADDR_LEN];
    u_char  src_mac[ETHER_ADDR_LEN];
    u_short ether_type;     /* en network byte order */
} __attribute__((packed));

/*
 * Cabecera IPv4 (mínimo 20 bytes, puede tener opciones).
 */
struct ip_header {
    u_char  ver_ihl;        /* versión (4 bits altos) + IHL (4 bits bajos) */
    u_char  tos;            /* type of service */
    u_short total_length;   /* longitud total del paquete IP */
    u_short id;             /* identificador */
    u_short flags_offset;   /* flags + fragment offset */
    u_char  ttl;            /* time to live */
    u_char  protocol;       /* 6=TCP, 17=UDP, 1=ICMP */
    u_short checksum;
    struct  in_addr src_ip;
    struct  in_addr dest_ip;
} __attribute__((packed));

/* Macros para extraer versión e IHL del primer byte */
#define IP_VERSION(ip)  (((ip)->ver_ihl) >> 4)
#define IP_IHL(ip)      (((ip)->ver_ihl) & 0x0F)

/*
 * Cabecera TCP (mínimo 20 bytes).
 */
struct tcp_header {
    u_short src_port;
    u_short dest_port;
    u_int   seq_num;
    u_int   ack_num;
    u_char  data_offset;    /* 4 bits altos = longitud de cabecera/4 */
    u_char  flags;
    u_short window;
    u_short checksum;
    u_short urgent_ptr;
} __attribute__((packed));

#define TCP_OFFSET(tcp)  (((tcp)->data_offset & 0xF0) >> 4)

/* Flags TCP (bits del byte 'flags') */
#define TCP_FIN  0x01
#define TCP_SYN  0x02
#define TCP_RST  0x04
#define TCP_PSH  0x08
#define TCP_ACK  0x10
#define TCP_URG  0x20

/*
 * Cabecera UDP (8 bytes, fija).
 */
struct udp_header {
    u_short src_port;
    u_short dest_port;
    u_short length;
    u_short checksum;
} __attribute__((packed));

/* ---- Lógica ---- */

static pcap_t *handle = NULL;

static void handle_sigint(int sig) {
    (void)sig;
    if (handle) pcap_breakloop(handle);
}

/* Convierte la MAC en una cadena legible "aa:bb:cc:dd:ee:ff" */
static void mac_to_str(const u_char *mac, char *buf) {
    sprintf(buf, "%02x:%02x:%02x:%02x:%02x:%02x",
            mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
}

/* Devuelve el nombre legible de un flag combo TCP */
static void tcp_flags_to_str(u_char flags, char *buf) {
    buf[0] = '\0';
    if (flags & TCP_SYN) strcat(buf, "SYN ");
    if (flags & TCP_ACK) strcat(buf, "ACK ");
    if (flags & TCP_FIN) strcat(buf, "FIN ");
    if (flags & TCP_RST) strcat(buf, "RST ");
    if (flags & TCP_PSH) strcat(buf, "PSH ");
    if (flags & TCP_URG) strcat(buf, "URG ");
}

static void packet_handler(u_char *user,
                           const struct pcap_pkthdr *header,
                           const u_char *packet) {
    int *counter = (int *)user;
    (*counter)++;

    char time_str[32];
    struct tm *ltime = localtime(&header->ts.tv_sec);
    strftime(time_str, sizeof(time_str), "%H:%M:%S", ltime);

    printf("======== Paquete #%d (%s) ========\n", *counter, time_str);
    printf("Longitud capturada: %u bytes\n", header->caplen);

    /* 1. Ethernet */
    if (header->caplen < ETHER_HDR_LEN) {
        printf("  Paquete demasiado corto para Ethernet\n\n");
        return;
    }
    const struct ethernet_header *eth = (const struct ethernet_header *)packet;
    char src_mac_s[18], dst_mac_s[18];
    mac_to_str(eth->src_mac, src_mac_s);
    mac_to_str(eth->dest_mac, dst_mac_s);
    u_short etype = ntohs(eth->ether_type);

    printf("[Ethernet] %s -> %s | EtherType: 0x%04x\n",
           src_mac_s, dst_mac_s, etype);

    /* 2. Si no es IPv4, salimos por ahora */
    if (etype != ETHERTYPE_IP) {
        if (etype == ETHERTYPE_ARP)       printf("  (ARP - no parseado)\n");
        else if (etype == ETHERTYPE_IPV6) printf("  (IPv6 - no parseado)\n");
        else                              printf("  (Otro protocolo)\n");
        printf("\n");
        return;
    }

    /* 3. IPv4 */
    const struct ip_header *ip =
        (const struct ip_header *)(packet + ETHER_HDR_LEN);
    int ip_hdr_len = IP_IHL(ip) * 4;     /* IHL viene en palabras de 32 bits */

    if (ip_hdr_len < 20) {
        printf("  Cabecera IP inválida (IHL=%d)\n\n", ip_hdr_len);
        return;
    }

    char src_ip[INET_ADDRSTRLEN], dst_ip[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &ip->src_ip,  src_ip, sizeof(src_ip));
    inet_ntop(AF_INET, &ip->dest_ip, dst_ip, sizeof(dst_ip));

    printf("[IP]       %s -> %s | TTL: %u | Protocolo: %u\n",
           src_ip, dst_ip, ip->ttl, ip->protocol);

    /* 4. Capa transporte */
    const u_char *transport = packet + ETHER_HDR_LEN + ip_hdr_len;

    switch (ip->protocol) {
    case IPPROTO_TCP_: {
        const struct tcp_header *tcp = (const struct tcp_header *)transport;
        int tcp_hdr_len = TCP_OFFSET(tcp) * 4;
        char flags_str[32];
        tcp_flags_to_str(tcp->flags, flags_str);
        printf("[TCP]      Puerto %u -> %u | Flags: %s| Hdr: %d bytes\n",
               ntohs(tcp->src_port), ntohs(tcp->dest_port),
               flags_str, tcp_hdr_len);
        break;
    }
    case IPPROTO_UDP_: {
        const struct udp_header *udp = (const struct udp_header *)transport;
        printf("[UDP]      Puerto %u -> %u | Longitud: %u\n",
               ntohs(udp->src_port), ntohs(udp->dest_port),
               ntohs(udp->length));
        break;
    }
    case IPPROTO_ICMP_:
        printf("[ICMP]     (tipo/código no parseados todavía)\n");
        break;
    default:
        printf("[?]        Protocolo %u no manejado\n", ip->protocol);
    }
    printf("\n");
}

int main(int argc, char *argv[]) {
    char errbuf[PCAP_ERRBUF_SIZE];
    int packet_count = 0;

    if (argc != 2) {
        fprintf(stderr, "Uso: sudo %s <interfaz>\n", argv[0]);
        return EXIT_FAILURE;
    }

    handle = pcap_open_live(argv[1], SNAP_LEN, PROMISC, TIMEOUT, errbuf);
    if (!handle) {
        fprintf(stderr, "Error al abrir %s: %s\n", argv[1], errbuf);
        return EXIT_FAILURE;
    }

    if (pcap_datalink(handle) != DLT_EN10MB) {
        fprintf(stderr, "Aviso: la interfaz no es Ethernet, el parseo "
                        "puede fallar.\n");
    }

    printf("Capturando en %s (Ctrl+C para detener)...\n\n", argv[1]);
    signal(SIGINT, handle_sigint);

    pcap_loop(handle, -1, packet_handler, (u_char *)&packet_count);

    printf("\nTotal capturado: %d paquetes\n", packet_count);
    pcap_close(handle);
    return EXIT_SUCCESS;
}