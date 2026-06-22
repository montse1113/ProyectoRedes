/*
 * Fase 2: Capturar paquetes en una interfaz
 * Proyecto Packet Sniffer - Redes I
 *
 * Compilar: gcc capture_basic.c -o capture_basic -lpcap
 * Ejecutar: sudo ./capture_basic wlo1
 *
 * Detener con Ctrl+C.
 *
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <time.h>
#include <pcap.h>

#define SNAP_LEN  65535   /* capturar el paquete completo */
#define PROMISC   1       /* modo promiscuo activado */
#define TIMEOUT   1000    /* milisegundos */

/* Handle global para poder cerrarlo desde el manejador de señal */
static pcap_t *handle = NULL;

/*
 * Manejador de Ctrl+C: rompe el loop de pcap_loop limpiamente.
 */
static void handle_sigint(int sig) {
    (void)sig;
    if (handle) {
        pcap_breakloop(handle);
    }
}

/*
 * Callback que pcap_loop invocará por cada paquete capturado.
 *
 * user   -> puntero que nosotros pasamos (aquí: contador de paquetes)
 * header -> metadatos (timestamp, longitud capturada, longitud original)
 * packet -> bytes crudos del paquete
 */
static void packet_handler(u_char *user,
                           const struct pcap_pkthdr *header,
                           const u_char *packet) {
    int *counter = (int *)user;
    (*counter)++;

    /* Convertir timestamp a algo legible */
    char time_str[64];
    struct tm *ltime = localtime(&header->ts.tv_sec);
    strftime(time_str, sizeof(time_str), "%H:%M:%S", ltime);

    printf("[#%d] %s.%06ld | capturados: %u bytes | reales: %u bytes\n",
           *counter,
           time_str,
           (long)header->ts.tv_usec,
           header->caplen,
           header->len);

    /* Imprimir los primeros 16 bytes en hexadecimal */
    printf("       Bytes: ");
    int to_show = header->caplen < 16 ? header->caplen : 16;
    for (int i = 0; i < to_show; i++) {
        printf("%02x ", packet[i]);
    }
    printf("...\n\n");
}

int main(int argc, char *argv[]) {
    char errbuf[PCAP_ERRBUF_SIZE];
    int packet_count = 0;

    /* 1. Validar argumentos */
    if (argc != 2) {
        fprintf(stderr, "Uso: sudo %s <interfaz>\n", argv[0]);
        fprintf(stderr, "Ejemplo: sudo %s wlo1\n", argv[0]);
        return EXIT_FAILURE;
    }
    const char *device = argv[1];

    /* 2. Abrir la interfaz */
    handle = pcap_open_live(device, SNAP_LEN, PROMISC, TIMEOUT, errbuf);
    if (handle == NULL) {
        fprintf(stderr, "No se pudo abrir %s: %s\n", device, errbuf);
        return EXIT_FAILURE;
    }

    /* 3. Verificar que la interfaz use Ethernet (DLT_EN10MB).
     *    Esto es importante para Fase 3, cuando empecemos a parsear.
     *    Si capturas en 'any' o WiFi en modo monitor, el datalink es otro.
     */
    int datalink = pcap_datalink(handle);
    printf("Interfaz: %s\n", device);
    printf("Tipo de enlace: %s (%s)\n",
           pcap_datalink_val_to_name(datalink),
           pcap_datalink_val_to_description(datalink));
    printf("Iniciando captura... (Ctrl+C para detener)\n\n");

    /* 4. Instalar manejador de Ctrl+C */
    signal(SIGINT, handle_sigint);

    /* 5. Loop de captura.
     *    Primer parámetro: cuántos paquetes capturar. -1 = infinito.
     *    Último: lo que reciba el callback en 'user'.
     */
    pcap_loop(handle, -1, packet_handler, (u_char *)&packet_count);

    /* 6. Limpieza */
    printf("\nCaptura detenida. Total de paquetes: %d\n", packet_count);
    pcap_close(handle);
    return EXIT_SUCCESS;
}