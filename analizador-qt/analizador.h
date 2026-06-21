#ifndef ANALIZADOR_H
#define ANALIZADOR_H


#include <string.h>
#include <netinet/in.h>
#include <netinet/if_ether.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/ip_icmp.h>
#include <netinet/igmp.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <arpa/inet.h>

#include "paquete_info.h"

// ============================================================
// HELPER: identificar protocolo de aplicación por puerto
// (idéntico al tuyo, no toca PaqueteInfo)
// ============================================================
inline const char* identificar_app(uint16_t puerto_src, uint16_t puerto_dst, int es_tcp) {
    uint16_t pp[2] = {puerto_src, puerto_dst};
    for (int i = 0; i < 2; i++) {
        uint16_t p = pp[i];
        if (es_tcp) {
            if (p == 80)   return "HTTP";
            if (p == 443)  return "HTTPS/TLS";
            if (p == 25)   return "SMTP";
            if (p == 110)  return "POP3";
            if (p == 143)  return "IMAP";
            if (p == 587)  return "SMTP Submission";
            if (p == 993)  return "IMAPS";
            if (p == 22)   return "SSH/SFTP";
            if (p == 23)   return "Telnet";
            if (p == 3389) return "RDP";
            if (p == 20)   return "FTP-Data";
            if (p == 21)   return "FTP-Control";
            if (p == 389)  return "LDAP";
            if (p == 636)  return "LDAPS";
            if (p == 445)  return "SMB/CIFS";
            if (p == 53)   return "DNS (TCP)";
            if (p == 179)  return "BGP";
            if (p == 3306) return "MySQL";
            if (p == 5432) return "PostgreSQL";
        } else {
            if (p == 53)   return "DNS";
            if (p == 5353) return "mDNS";
            if (p == 67 || p == 68) return "DHCP";
            if (p == 123)  return "NTP";
            if (p == 161 || p == 162) return "SNMP";
            if (p == 514)  return "Syslog";
            if (p == 69)   return "TFTP";
            if (p == 443)  return "QUIC/HTTP3";
            if (p == 1900) return "SSDP";
            if (p == 137 || p == 138) return "NetBIOS";
        }
    }
    return nullptr;
}

// ============================================================
// CAPA 4: TCP
// ============================================================
inline void analizar_tcp(const u_char *paquete, int offset, PaqueteInfo &info) {
    struct tcphdr *tcp = (struct tcphdr *)(paquete + offset);
    uint16_t src = ntohs(tcp->source);
    uint16_t dst = ntohs(tcp->dest);

    info.protocolo = "TCP";

    // Construir cadena de flags
    QString flags;
    if (tcp->th_flags & TH_SYN)  flags += "SYN ";
    if (tcp->th_flags & TH_ACK)  flags += "ACK ";
    if (tcp->th_flags & TH_FIN)  flags += "FIN ";
    if (tcp->th_flags & TH_RST)  flags += "RST ";
    if (tcp->th_flags & TH_PUSH) flags += "PSH ";
    if (tcp->th_flags & TH_URG)  flags += "URG ";

    const char *app = identificar_app(src, dst, 1);
    if (app) info.aplicacion = app;

    // Resumen tipo Wireshark para la columna "Info"
    info.resumenInfo = QString("%1 → %2 [%3]")
                           .arg(src).arg(dst).arg(flags.trimmed());

    // Detalles completos (lo que antes imprimías)
    info.detallesCompletos += "   |- Protocolo:      TCP\n";
    info.detallesCompletos += QString("   |- Puerto Origen:  %1\n").arg(src);
    info.detallesCompletos += QString("   |- Puerto Destino: %1\n").arg(dst);
    info.detallesCompletos += QString("   |- Flags:          %1\n").arg(flags);
    if (app)
        info.detallesCompletos += QString("   |- Aplicacion:     %1\n").arg(app);
}

// ============================================================
// CAPA 4: UDP
// ============================================================
inline void analizar_udp(const u_char *paquete, int offset, PaqueteInfo &info) {
    struct udphdr *udp = (struct udphdr *)(paquete + offset);
    uint16_t src = ntohs(udp->source);
    uint16_t dst = ntohs(udp->dest);

    info.protocolo = "UDP";

    const char *app = identificar_app(src, dst, 0);
    if (app) info.aplicacion = app;

    info.resumenInfo = QString("%1 → %2 Len=%3")
                           .arg(src).arg(dst).arg(ntohs(udp->len));

    info.detallesCompletos += "   |- Protocolo:      UDP\n";
    info.detallesCompletos += QString("   |- Puerto Origen:  %1\n").arg(src);
    info.detallesCompletos += QString("   |- Puerto Destino: %1\n").arg(dst);
    if (app)
        info.detallesCompletos += QString("   |- Aplicacion:     %1\n").arg(app);
}

// ============================================================
// CAPA 4: ICMP
// ============================================================
inline void analizar_icmp(const u_char *paquete, int offset, PaqueteInfo &info) {
    struct icmphdr *icmp = (struct icmphdr *)(paquete + offset);
    info.protocolo = "ICMP";

    const char *tipo_str = "Desconocido";
    switch (icmp->type) {
    case ICMP_ECHOREPLY:     tipo_str = "Echo Reply (pong)"; break;
    case ICMP_ECHO:          tipo_str = "Echo Request (ping)"; break;
    case ICMP_DEST_UNREACH:  tipo_str = "Destination Unreachable"; break;
    case ICMP_TIME_EXCEEDED: tipo_str = "Time Exceeded (TTL)"; break;
    case ICMP_REDIRECT:      tipo_str = "Redirect"; break;
    case ICMP_PARAMETERPROB: tipo_str = "Parameter Problem"; break;
    }

    info.resumenInfo = QString("Tipo %1: %2").arg(icmp->type).arg(tipo_str);

    info.detallesCompletos += "   |- Protocolo:   ICMP\n";
    info.detallesCompletos += QString("   |- Tipo:        %1 (%2)\n").arg(icmp->type).arg(tipo_str);
    info.detallesCompletos += QString("   |- Codigo:      %1\n").arg(icmp->code);
}

// ============================================================
// CAPA 4: IGMP
// ============================================================
inline void analizar_igmp(const u_char *paquete, int offset, PaqueteInfo &info) {
    const u_char *p = paquete + offset;
    uint8_t tipo = p[0];
    struct in_addr grupo;
    memcpy(&grupo, p + 4, 4);

    info.protocolo = "IGMP";

    const char *tipo_str = "Desconocido";
    switch (tipo) {
    case 0x11: tipo_str = "Membership Query"; break;
    case 0x12: tipo_str = "Membership Report v1"; break;
    case 0x16: tipo_str = "Membership Report v2"; break;
    case 0x17: tipo_str = "Leave Group"; break;
    case 0x22: tipo_str = "Membership Report v3"; break;
    }

    info.resumenInfo = QString("%1, grupo %2").arg(tipo_str).arg(inet_ntoa(grupo));

    info.detallesCompletos += "   |- Protocolo:   IGMP\n";
    info.detallesCompletos += QString("   |- Tipo:        0x%1 (%2)\n")
                                  .arg(tipo, 2, 16, QChar('0')).arg(tipo_str);
    info.detallesCompletos += QString("   |- Grupo:       %1\n").arg(inet_ntoa(grupo));
}

// ============================================================
// CAPA 3: IPv6
// ============================================================
inline void analizar_ipv6(const u_char *paquete, int offset, PaqueteInfo &info) {
    struct ip6_hdr *ipv6 = (struct ip6_hdr *)(paquete + offset);
    char ip_str[INET6_ADDRSTRLEN];

    inet_ntop(AF_INET6, &(ipv6->ip6_src), ip_str, INET6_ADDRSTRLEN);
    info.ipOrigen = ip_str;
    inet_ntop(AF_INET6, &(ipv6->ip6_dst), ip_str, INET6_ADDRSTRLEN);
    info.ipDestino = ip_str;

    info.detallesCompletos += "   |- Capa de Red: IPv6\n";
    info.detallesCompletos += QString("   |- IP Fuente:   %1\n").arg(info.ipOrigen);
    info.detallesCompletos += QString("   |- IP Destino:  %1\n").arg(info.ipDestino);

    int nuevo_offset = offset + sizeof(struct ip6_hdr);
    uint8_t sig = ipv6->ip6_nxt;

    if (sig == IPPROTO_TCP)         analizar_tcp(paquete, nuevo_offset, info);
    else if (sig == IPPROTO_UDP)    analizar_udp(paquete, nuevo_offset, info);
    else if (sig == IPPROTO_ICMPV6) {
        info.protocolo = "ICMPv6";
        info.detallesCompletos += "   |- Protocolo:   ICMPv6\n";
    } else {
        info.protocolo = QString("IPv6/%1").arg(sig);
        info.detallesCompletos += QString("   |- Protocolo:   Otro (%1)\n").arg(sig);
    }
}

// ============================================================
// CAPA 3: IPv4
// ============================================================
inline void analizar_ipv4(const u_char *paquete, int offset, PaqueteInfo &info) {
    struct ip *iph = (struct ip *)(paquete + offset);

    info.ipOrigen  = inet_ntoa(iph->ip_src);
    info.ipDestino = inet_ntoa(iph->ip_dst);

    info.detallesCompletos += "   |- Capa de Red: IPv4\n";
    info.detallesCompletos += QString("   |- IP Fuente:   %1\n").arg(info.ipOrigen);
    info.detallesCompletos += QString("   |- IP Destino:  %1\n").arg(info.ipDestino);
    info.detallesCompletos += QString("   |- TTL:         %1\n").arg(iph->ip_ttl);

    int nuevo_offset = offset + (iph->ip_hl * 4);
    switch (iph->ip_p) {
    case IPPROTO_TCP:  analizar_tcp(paquete, nuevo_offset, info);  break;
    case IPPROTO_UDP:  analizar_udp(paquete, nuevo_offset, info);  break;
    case IPPROTO_ICMP: analizar_icmp(paquete, nuevo_offset, info); break;
    case IPPROTO_IGMP: analizar_igmp(paquete, nuevo_offset, info); break;
    default:
        info.protocolo = QString("IP/%1").arg(iph->ip_p);
        info.detallesCompletos += QString("   |- Protocolo:   Otro IP (%1)\n").arg(iph->ip_p);
        break;
    }
}

// ============================================================
// CAPA 2.5: ARP
// ============================================================
inline void analizar_arp(const u_char *paquete, int offset, PaqueteInfo &info) {
    const u_char *p = paquete + offset;
    info.protocolo = "ARP";

    QString macSender = QString("%1:%2:%3:%4:%5:%6")
                            .arg(p[8],2,16,QChar('0')).arg(p[9],2,16,QChar('0'))
                            .arg(p[10],2,16,QChar('0')).arg(p[11],2,16,QChar('0'))
                            .arg(p[12],2,16,QChar('0')).arg(p[13],2,16,QChar('0')).toUpper();

    QString macTarget = QString("%1:%2:%3:%4:%5:%6")
                            .arg(p[18],2,16,QChar('0')).arg(p[19],2,16,QChar('0'))
                            .arg(p[20],2,16,QChar('0')).arg(p[21],2,16,QChar('0'))
                            .arg(p[22],2,16,QChar('0')).arg(p[23],2,16,QChar('0')).toUpper();

    struct in_addr sip; memcpy(&sip, p + 14, 4);
    struct in_addr tip; memcpy(&tip, p + 24, 4);

    info.ipOrigen  = inet_ntoa(sip);
    info.ipDestino = inet_ntoa(tip);

    info.resumenInfo = QString("Who has %1? Tell %2").arg(info.ipDestino, info.ipOrigen);

    info.detallesCompletos += "   |- Capa de Red: ARP\n";
    info.detallesCompletos += QString("   |- MAC Sender:  %1\n").arg(macSender);
    info.detallesCompletos += QString("   |- IP Sender:   %1\n").arg(info.ipOrigen);
    info.detallesCompletos += QString("   |- MAC Target:  %1\n").arg(macTarget);
    info.detallesCompletos += QString("   |- IP Target:   %1\n").arg(info.ipDestino);
}

// ============================================================
// CAPA 2: Ethernet (punto de entrada)
// ============================================================
inline void analizar_ethernet(const u_char *paquete, PaqueteInfo &info) {
    struct ether_header *eth = (struct ether_header *)paquete;

    info.macDestino = QString("%1:%2:%3:%4:%5:%6")
                          .arg(eth->ether_dhost[0],2,16,QChar('0')).arg(eth->ether_dhost[1],2,16,QChar('0'))
                          .arg(eth->ether_dhost[2],2,16,QChar('0')).arg(eth->ether_dhost[3],2,16,QChar('0'))
                          .arg(eth->ether_dhost[4],2,16,QChar('0')).arg(eth->ether_dhost[5],2,16,QChar('0')).toUpper();

    info.macOrigen = QString("%1:%2:%3:%4:%5:%6")
                         .arg(eth->ether_shost[0],2,16,QChar('0')).arg(eth->ether_shost[1],2,16,QChar('0'))
                         .arg(eth->ether_shost[2],2,16,QChar('0')).arg(eth->ether_shost[3],2,16,QChar('0'))
                         .arg(eth->ether_shost[4],2,16,QChar('0')).arg(eth->ether_shost[5],2,16,QChar('0')).toUpper();

    info.detallesCompletos += QString("   |- MAC Destino: %1\n").arg(info.macDestino);
    info.detallesCompletos += QString("   |- MAC Fuente:  %1\n").arg(info.macOrigen);

    int offset = sizeof(struct ether_header);
    uint16_t tipo_ethernet = ntohs(eth->ether_type);

    if (tipo_ethernet == ETHERTYPE_IP) {
        analizar_ipv4(paquete, offset, info);
    } else if (tipo_ethernet == ETHERTYPE_IPV6) {
        analizar_ipv6(paquete, offset, info);
    } else if (tipo_ethernet == ETHERTYPE_ARP) {
        analizar_arp(paquete, offset, info);
    } else {
        info.protocolo = QString("0x%1").arg(tipo_ethernet, 4, 16, QChar('0'));
        info.detallesCompletos += QString("   |- Capa de Red: Protocolo Desconocido (0x%1)\n")
                                      .arg(tipo_ethernet, 4, 16, QChar('0'));
    }
}

#endif // ANALIZADOR_H
