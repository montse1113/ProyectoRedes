/*
 * Fase 1: Listar interfaces de red disponibles
 * Proyecto Packet Sniffer - Redes I
 *
 * Compilar: gcc list_interfaces.c -o list_interfaces -lpcap
 * Ejecutar: sudo ./list_interfaces
 *
 */

#include <stdio.h>
#include <stdlib.h>
#include <pcap.h>
#include <arpa/inet.h>   /* para inet_ntoa */
#include <sys/socket.h>  /* para struct sockaddr_in */
#include <netinet/in.h>

int main(void) {
    pcap_if_t *alldevs;          /* cabeza de la lista enlazada */
    pcap_if_t *dev;              /* iterador */
    char errbuf[PCAP_ERRBUF_SIZE];
    int i = 0;

    /* 1. Pedirle a libpcap la lista de interfaces */
    if (pcap_findalldevs(&alldevs, errbuf) == -1) {
        fprintf(stderr, "Error en pcap_findalldevs: %s\n", errbuf);
        return EXIT_FAILURE;
    }

    /* 2. Si la lista está vacía, probablemente faltan permisos */
    if (alldevs == NULL) {
        fprintf(stderr, "No se encontraron interfaces. "
                        "¿Estás ejecutando con sudo?\n");
        return EXIT_FAILURE;
    }

    /* 3. Recorrer la lista enlazada e imprimir cada interfaz */
    printf("Interfaces de red disponibles:\n");
    printf("==============================\n\n");

    for (dev = alldevs; dev != NULL; dev = dev->next) {
        i++;
        printf("[%d] %s\n", i, dev->name);

        if (dev->description) {
            printf("    Descripción: %s\n", dev->description);
        } else {
            printf("    Descripción: (sin descripción)\n");
        }

        /* Mostrar las direcciones IP asociadas a la interfaz */
        for (pcap_addr_t *a = dev->addresses; a != NULL; a = a->next) {
            if (a->addr && a->addr->sa_family == AF_INET) {
                struct sockaddr_in *ipv4 = (struct sockaddr_in *)a->addr;
                printf("    IPv4: %s\n", inet_ntoa(ipv4->sin_addr));
            }
        }

        /* Banderas: loopback, activa, etc. */
        if (dev->flags & PCAP_IF_LOOPBACK) {
            printf("    [LOOPBACK]\n");
        }
        if (dev->flags & PCAP_IF_UP) {
            printf("    [UP]\n");
        }
        if (dev->flags & PCAP_IF_RUNNING) {
            printf("    [RUNNING]\n");
        }
        printf("\n");
    }

    /* 4. Liberar la memoria. SIEMPRE. */
    pcap_freealldevs(alldevs);

    printf("Total de interfaces encontradas: %d\n", i);
    return EXIT_SUCCESS;
}