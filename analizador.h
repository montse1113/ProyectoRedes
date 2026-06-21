#ifndef ANALIZADOR_H
#define ANALIZADOR_H

#include <stdio.h>
#include <string.h>            // memcpy
#include <netinet/in.h>
#include <netinet/if_ether.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/ip_icmp.h>   // NUEVO: ICMP
#include <netinet/igmp.h>      // NUEVO: IGMP
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <arpa/inet.h>

// ============================================================
// HELPER: identificar protocolo de aplicación por puerto
// (TCP y UDP). Devuelve el nombre o NULL si no lo conoce.
// ============================================================
const char* identificar_app(uint16_t puerto_src, uint16_t puerto_dst, int es_tcp) {
    //ae evalúan los dos puertos porque cualquiera puede ser el "conocido"
    uint16_t p1 = puerto_src, p2 = puerto_dst;
    uint16_t pp[2] = {p1, p2};
    for (int i = 0; i < 2; i++) {
        uint16_t p = pp[i];
        if (es_tcp) {
            // --- Web ---
            if (p == 80)   return "HTTP";
            if (p == 443)  return "HTTPS/TLS";
            // --- Correo ---
            if (p == 25)   return "SMTP";
            if (p == 110)  return "POP3";
            if (p == 143)  return "IMAP";
            if (p == 587)  return "SMTP Submission";
            if (p == 993)  return "IMAPS";
            // --- Acceso remoto ---
            if (p == 22)   return "SSH/SFTP";
            if (p == 23)   return "Telnet";
            if (p == 3389) return "RDP";
            // --- Transferencia de archivos ---
            if (p == 20)   return "FTP-Data";
            if (p == 21)   return "FTP-Control";
            // --- Directorio / autenticación ---
            if (p == 389)  return "LDAP";
            if (p == 636)  return "LDAPS";
            // --- Compartición Windows ---
            if (p == 445)  return "SMB/CIFS";
            // --- Resolución / enrutamiento ---
            if (p == 53)   return "DNS (TCP)";
            if (p == 179)  return "BGP";
            // --- Bases de datos ---
            if (p == 3306) return "MySQL";
            if (p == 5432) return "PostgreSQL";
        } else {
            // --- Resolución ---
            if (p == 53)   return "DNS";
            if (p == 5353) return "mDNS";
            // --- Configuración / red ---
            if (p == 67 || p == 68) return "DHCP";
            if (p == 123)  return "NTP";
            if (p == 161 || p == 162) return "SNMP";
            if (p == 389)  return "LDAP (UDP)";
            // --- Logs ---
            if (p == 514)  return "Syslog";
            // --- Transferencia ligera ---
            if (p == 69)   return "TFTP";
            // --- Web moderno ---
            if (p == 443)  return "QUIC/HTTP3";
            // --- Descubrimiento ---
            if (p == 1900) return "SSDP";
            if (p == 137 || p == 138) return "NetBIOS";
            if (p == 22)  return "SSH (UDP)";
            if (p == 636) return "LDAPS (UDP)";
        }
    }
    return NULL;
}

// ============================================================
// CAPA 4: TCP
// ============================================================
void analizar_tcp(const u_char *paquete, int offset) {
    struct tcphdr *tcp = (struct tcphdr *)(paquete + offset);
    uint16_t src = ntohs(tcp->source);
    uint16_t dst = ntohs(tcp->dest);

    printf("   |- Protocolo:   TCP\n");
    printf("   |- Puerto Origen:  %d\n", src);
    printf("   |- Puerto Destino: %d\n", dst);

    //flags utiles para diagnostico (SYN/ACK/FIN/RST)
    printf("   |- Flags:       %s%s%s%s%s%s\n",
           (tcp->th_flags & TH_SYN) ? "SYN " : "",//TCP usa bits individuales (1 o 0) para decir si el
           (tcp->th_flags & TH_ACK) ? "ACK " : "",//paquete está abriendo una conexión (SYN), confirmando un dato (ACK) o cerrando
           (tcp->th_flags & TH_FIN) ? "FIN " : "",//a conexión (FIN)
           (tcp->th_flags & TH_RST) ? "RST " : "",//
           (tcp->th_flags & TH_PUSH) ? "PSH " : "",//
           (tcp->th_flags & TH_URG) ? "URG " : "");//

    const char *app = identificar_app(src, dst, 1);
    if (app) printf("   |- Aplicacion:  %s\n", app);
}

// ============================================================
// CAPA 4: UDP
// ============================================================
void analizar_udp(const u_char *paquete, int offset) {
    struct udphdr *udp = (struct udphdr *)(paquete + offset);
    uint16_t src = ntohs(udp->source);
    uint16_t dst = ntohs(udp->dest);

    printf("   |- Protocolo:   UDP\n");
    printf("   |- Puerto Origen:  %d\n", src);
    printf("   |- Puerto Destino: %d\n", dst);
    const char *app = identificar_app(src, dst, 0);
    if (app) printf("   |- Aplicacion:  %s\n", app);
}

// ============================================================
// CAPA 4: ICMP 
// ============================================================
void analizar_icmp(const u_char *paquete, int offset) {
    struct icmphdr *icmp = (struct icmphdr *)(paquete + offset);
    printf("   |- Protocolo:   ICMP\n");

    const char *tipo_str = "Desconocido";
    switch (icmp->type) {
        case ICMP_ECHOREPLY:      tipo_str = "Echo Reply (pong)"; break;
        case ICMP_ECHO:           tipo_str = "Echo Request (ping)"; break;
        case ICMP_DEST_UNREACH:   tipo_str = "Destination Unreachable"; break;
        case ICMP_TIME_EXCEEDED:  tipo_str = "Time Exceeded (TTL)"; break;
        case ICMP_REDIRECT:       tipo_str = "Redirect"; break;
        case ICMP_PARAMETERPROB:  tipo_str = "Parameter Problem"; break;
    }
    printf("   |- Tipo:        %d (%s)\n", icmp->type, tipo_str);
    printf("   |- Codigo:      %d\n", icmp->code);
}

// ============================================================
// CAPA 4: IGMP (Internet Group Management - multicast)
// ============================================================
void analizar_igmp(const u_char *paquete, int offset) {
    //formato común: tipo(1) + max_resp(1) + checksum(2) + group_addr(4)
    const u_char *p = paquete + offset;
    uint8_t tipo = p[0];
    struct in_addr grupo;
    memcpy(&grupo, p + 4, 4);

    printf("   |- Protocolo:   IGMP\n");
    const char *tipo_str = "Desconocido";
    switch (tipo) {
        case 0x11: tipo_str = "Membership Query"; break;
        case 0x12: tipo_str = "Membership Report v1"; break;
        case 0x16: tipo_str = "Membership Report v2"; break;
        case 0x17: tipo_str = "Leave Group"; break;
        case 0x22: tipo_str = "Membership Report v3"; break;
    }
    printf("   |- Tipo:        0x%02X (%s)\n", tipo, tipo_str);
    printf("   |- Grupo:       %s\n", inet_ntoa(grupo));
}

// ============================================================
// CAPA 3: IPv6
// ============================================================
void analizar_ipv6(const u_char *paquete, int offset) {
    struct ip6_hdr *ipv6 = (struct ip6_hdr *)(paquete + offset);
    char ip_str[INET6_ADDRSTRLEN];

    printf("   |- Capa de Red: IPv6\n");
    inet_ntop(AF_INET6, &(ipv6->ip6_src), ip_str, INET6_ADDRSTRLEN);
    printf("   |- IP Fuente:   %s\n", ip_str);
    inet_ntop(AF_INET6, &(ipv6->ip6_dst), ip_str, INET6_ADDRSTRLEN);
    printf("   |- IP Destino:  %s\n", ip_str);

    int nuevo_offset = offset + sizeof(struct ip6_hdr);
    uint8_t sig = ipv6->ip6_nxt;

    if (sig == IPPROTO_TCP)       analizar_tcp(paquete, nuevo_offset);
    else if (sig == IPPROTO_UDP)  analizar_udp(paquete, nuevo_offset);
    else if (sig == IPPROTO_ICMPV6) printf("   |- Protocolo:   ICMPv6\n");
    else printf("   |- Protocolo:   Otro (%d)\n", sig);
}

// ============================================================
// CAPA 3: IPv4
// ============================================================
void analizar_ipv4(const u_char *paquete, int offset) {
    //se posiciona en el byte 14 (paquete + offset) y ponemos la plantilla de IP
    struct ip *iph = (struct ip *)(paquete + offset);

    printf("   |- Capa de Red: IPv4\n");
    printf("   |- IP Fuente:   %s\n", inet_ntoa(iph->ip_src));//se convierte la ip de formato red a formato texto
    printf("   |- IP Destino:  %s\n", inet_ntoa(iph->ip_dst));
    printf("   |- TTL:         %d\n", iph->ip_ttl);

    //se calcula el nuevo offset 
    //ip_hl nos da la longitud en palabras de 32 bits, eso se multiplica por 4 
    //offset actual (14) + tamaño de la IP
    int nuevo_offset = offset + (iph->ip_hl * 4);
    switch (iph->ip_p) {//campo protocolo 
        case IPPROTO_TCP:  analizar_tcp(paquete, nuevo_offset);  break;//es 6
        case IPPROTO_UDP:  analizar_udp(paquete, nuevo_offset);  break;//es 17
        case IPPROTO_ICMP: analizar_icmp(paquete, nuevo_offset); break;//es 1
        case IPPROTO_IGMP: analizar_igmp(paquete, nuevo_offset); break;
        default:
            printf("   |- Protocolo:   Otro IP (%d)\n", iph->ip_p);
            break;
    }
}

// ============================================================
// CAPA 2.5: ARP (ampliado: muestra IPs y MACs del mensaje)
// ============================================================
void analizar_arp(const u_char *paquete, int offset) {
    const u_char *p = paquete + offset;

    // Cabecera ARP estándar (Ethernet/IPv4):
    //  htype(2) ptype(2) hlen(1) plen(1) op(2)
    //  sender_mac(6) sender_ip(4) target_mac(6) target_ip(4)
    uint16_t op = ntohs(*(uint16_t *)(p + 6));

    printf("   |- Capa de Red: ARP\n");

    printf("   |- MAC Sender:  %02X:%02X:%02X:%02X:%02X:%02X\n",
           p[8], p[9], p[10], p[11], p[12], p[13]);
    struct in_addr sip; memcpy(&sip, p + 14, 4);
    printf("   |- IP Sender:   %s\n", inet_ntoa(sip));

    printf("   |- MAC Target:  %02X:%02X:%02X:%02X:%02X:%02X\n",
           p[18], p[19], p[20], p[21], p[22], p[23]);
    struct in_addr tip; memcpy(&tip, p + 24, 4);
    printf("   |- IP Target:   %s\n", inet_ntoa(tip));
}

// ============================================================
// CAPA 2: Ethernet (los primeros 14 bytes)
// ============================================================
void analizar_ethernet(const u_char *paquete) {
    //Aqui ocurre el casting se toma el puntero 'paquete' (que apunta al byte 0) y le dice a C: 
    // "Trata estos primeros bytes como si fueran la estructura ether_header".
    struct ether_header *eth = (struct ether_header *)paquete;

    printf("   |- MAC Destino: %02X:%02X:%02X:%02X:%02X:%02X\n",
           eth->ether_dhost[0], eth->ether_dhost[1], eth->ether_dhost[2],
           eth->ether_dhost[3], eth->ether_dhost[4], eth->ether_dhost[5]);
    printf("   |- MAC Fuente:  %02X:%02X:%02X:%02X:%02X:%02X\n",
           eth->ether_shost[0], eth->ether_shost[1], eth->ether_shost[2],
           eth->ether_shost[3], eth->ether_shost[4], eth->ether_shost[5]);
    //Aqui ocurre el offset (desplazamiento), la cabecera de ethernet mide 14 bytes
    //se guarda este tamaño en 'offset' para saber donde inicia la siguiente capa
    int offset = sizeof(struct ether_header);
    //se lee el tipo para saber a quien pasarle el resto del paquete 
    uint16_t tipo_ethernet = ntohs(eth->ether_type);//Network To Host Short (De Red a Host, Corto), toma los bytes y los boltea para que se puedan leer por el procesador 
    //se le pasa al correspondiente 
    if (tipo_ethernet == ETHERTYPE_IP) {
        analizar_ipv4(paquete, offset);
    } else if (tipo_ethernet == ETHERTYPE_IPV6) {
        analizar_ipv6(paquete, offset);
    } else if (tipo_ethernet == ETHERTYPE_ARP) {
        analizar_arp(paquete, offset);
    } else {
        printf("   |- Capa de Red: Protocolo Desconocido (0x%04X)\n", tipo_ethernet);
    }
}

#endif // ANALIZADOR_H