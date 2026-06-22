#include <stdio.h>
#include <stdlib.h>            // malloc, free, atoi
#include <string.h>           // strcpy, strstr, memset, memcpy
#include <strings.h>          // strcasecmp (compara sin importar mayusculas)
#include <signal.h>           // signal (para capturar ctrl+c)
#include <time.h>             // localtime, strftime (hora del paquete)
#include <pcap/pcap.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <netinet/if_ether.h>
#include <netinet/ip.h>
#include "analizador.h"

// cantidad maxima de paquetes que se guardan en memoria
#define MAX_PAQUETES 50000

// ============================================================
// guarda una copia de cada paquete capturado. los punteros que
// entrega libpcap no sirven despues del callback, por eso se copia
// el contenido con memcpy y se conserva aqui para filtrarlo luego.
// ============================================================
struct paquete_guardado {
    u_char *datos;           // copia de los bytes del paquete (malloc)
    int     longitud;        // cuantos bytes se capturaron
    char    tiempo[16];      // hora a la que llego, ej "21:35:54"
};

// almacen global de los paquetes capturados y su conteo
static struct paquete_guardado g_capturados[MAX_PAQUETES];
static int g_total = 0;

// ============================================================
// datos minimos que se sacan de un paquete solo para poder
// filtrar y exportar. no se imprimen: solo se comparan.
// ============================================================
struct info_paquete {
    char protocolo[16];      // "TCP", "UDP", "ICMP", "ARP"...
    char ip_origen[64];
    char ip_destino[64];
    int  puerto_origen;      // -1 si el paquete no tiene puertos
    int  puerto_destino;
};

// ============================================================
// filtros que elige el usuario en el menu posterior a la captura.
// un campo vacio significa "no filtrar por eso".
// ============================================================
struct filtros {
    char protocolo[16];
    char ip_origen[64];
    char ip_destino[64];
    char puerto[16];         // se guarda como texto para saber si esta vacio
};

// puntero global a la sesion, necesario porque el manejador de
// ctrl+c no puede recibir parametros propios.
static pcap_t *sesion_global = NULL;

// ============================================================
// se ejecuta cuando el usuario presiona ctrl+c. le pide a
// pcap_loop que termine de forma ordenada para pasar al menu.
// ============================================================
void manejar_ctrlc(int sig) {
    (void)sig;  // el parametro no se usa, pero la firma lo exige
    if (sesion_global != NULL) pcap_breakloop(sesion_global);
}

// ============================================================
// lee una linea desde el teclado y le quita el salto de linea.
// si el usuario solo presiona enter, la cadena queda vacia.
// ============================================================
void leer_linea(char *buffer, int tam) {
    if (fgets(buffer, tam, stdin) != NULL) {
        buffer[strcspn(buffer, "\n")] = '\0';
    } else {
        buffer[0] = '\0';
    }
}

// ============================================================
// examina un paquete lo justo para sacar protocolo, ips y puertos.
// no imprime nada; el analisis completo lo hace analizar_ethernet.
// ============================================================
void extraer_info(const u_char *paquete, struct info_paquete *info) {
    // se ponen valores por defecto por si algun campo no aplica
    strcpy(info->protocolo, "Otro");
    info->ip_origen[0] = '\0';
    info->ip_destino[0] = '\0';
    info->puerto_origen = -1;
    info->puerto_destino = -1;

    // se lee el tipo de la capa ethernet para saber que viene despues
    struct ether_header *eth = (struct ether_header *)paquete;
    uint16_t tipo = ntohs(eth->ether_type);
    int offset = sizeof(struct ether_header);   // 14 bytes

    if (tipo == ETHERTYPE_IP) {
        // ---- ipv4 ----
        struct ip *iph = (struct ip *)(paquete + offset);
        // inet_ntoa usa un buffer interno, por eso se copia de inmediato
        strncpy(info->ip_origen,  inet_ntoa(iph->ip_src), 63);
        strncpy(info->ip_destino, inet_ntoa(iph->ip_dst), 63);

        int off4 = offset + (iph->ip_hl * 4);   // donde empieza la capa 4
        if (iph->ip_p == IPPROTO_TCP) {
            strcpy(info->protocolo, "TCP");
            struct tcphdr *tcp = (struct tcphdr *)(paquete + off4);
            info->puerto_origen  = ntohs(tcp->source);
            info->puerto_destino = ntohs(tcp->dest);
        } else if (iph->ip_p == IPPROTO_UDP) {
            strcpy(info->protocolo, "UDP");
            struct udphdr *udp = (struct udphdr *)(paquete + off4);
            info->puerto_origen  = ntohs(udp->source);
            info->puerto_destino = ntohs(udp->dest);
        } else if (iph->ip_p == IPPROTO_ICMP) {
            strcpy(info->protocolo, "ICMP");
        } else if (iph->ip_p == IPPROTO_IGMP) {
            strcpy(info->protocolo, "IGMP");
        }
    } else if (tipo == ETHERTYPE_IPV6) {
        // ---- ipv6 ----
        struct ip6_hdr *ipv6 = (struct ip6_hdr *)(paquete + offset);
        inet_ntop(AF_INET6, &(ipv6->ip6_src), info->ip_origen, 63);
        inet_ntop(AF_INET6, &(ipv6->ip6_dst), info->ip_destino, 63);

        uint8_t sig = ipv6->ip6_nxt;
        int off4 = offset + sizeof(struct ip6_hdr);
        if (sig == IPPROTO_TCP) {
            strcpy(info->protocolo, "TCP");
            struct tcphdr *tcp = (struct tcphdr *)(paquete + off4);
            info->puerto_origen  = ntohs(tcp->source);
            info->puerto_destino = ntohs(tcp->dest);
        } else if (sig == IPPROTO_UDP) {
            strcpy(info->protocolo, "UDP");
            struct udphdr *udp = (struct udphdr *)(paquete + off4);
            info->puerto_origen  = ntohs(udp->source);
            info->puerto_destino = ntohs(udp->dest);
        } else if (sig == IPPROTO_ICMPV6) {
            strcpy(info->protocolo, "ICMPv6");
        } else {
            strcpy(info->protocolo, "IPv6");
        }
    } else if (tipo == ETHERTYPE_ARP) {
        // ---- arp ----
        strcpy(info->protocolo, "ARP");
        const u_char *p = paquete + offset;
        struct in_addr sip; memcpy(&sip, p + 14, 4);
        strncpy(info->ip_origen, inet_ntoa(sip), 63);
        struct in_addr tip; memcpy(&tip, p + 24, 4);
        strncpy(info->ip_destino, inet_ntoa(tip), 63);
    }
}

// ============================================================
// decide si un paquete cumple con los filtros elegidos.
// devuelve 1 si pasa o 0 si no. los filtros se combinan con "y":
// si uno falla, el paquete no pasa.
// ============================================================
int pasa_filtro(const struct info_paquete *info, const struct filtros *f) {
    // filtro por protocolo (vacio o "TODOS" = no filtra)
    if (strlen(f->protocolo) > 0 && strcasecmp(f->protocolo, "TODOS") != 0) {
        if (strcasecmp(info->protocolo, f->protocolo) != 0) return 0;
    }
    // filtro por ip de origen (coincidencia parcial: "192.168" basta)
    if (strlen(f->ip_origen) > 0) {
        if (strstr(info->ip_origen, f->ip_origen) == NULL) return 0;
    }
    // filtro por ip de destino
    if (strlen(f->ip_destino) > 0) {
        if (strstr(info->ip_destino, f->ip_destino) == NULL) return 0;
    }
    // filtro por puerto (coincide si es el de origen o el de destino)
    if (strlen(f->puerto) > 0) {
        int p = atoi(f->puerto);
        if (info->puerto_origen != p && info->puerto_destino != p) return 0;
    }
    return 1;
}

// ============================================================
// se ejecuta por cada paquete durante la captura. copia el
// paquete a memoria y guarda su hora. solo muestra un contador
// en vivo; el detalle se vera despues en el menu.
// ============================================================
void procesar_paquete(u_char *args, const struct pcap_pkthdr *encabezado, const u_char *paquete) {
    (void)args;
    // si se llego al limite, se ignora el resto para no desbordar
    if (g_total >= MAX_PAQUETES) return;

    // se reserva memoria y se copia el paquete (los punteros de pcap
    // no son estables fuera de esta funcion, por eso el memcpy)
    u_char *copia = (u_char *)malloc(encabezado->caplen);
    if (copia == NULL) return;
    memcpy(copia, paquete, encabezado->caplen);

    g_capturados[g_total].datos    = copia;
    g_capturados[g_total].longitud = encabezado->caplen;

    // se guarda la hora a la que llego el paquete
    time_t segundos = encabezado->ts.tv_sec;
    struct tm *t = localtime(&segundos);
    strftime(g_capturados[g_total].tiempo, 16, "%H:%M:%S", t);

    g_total++;

    // contador en vivo sobre la misma linea (\r regresa al inicio)
    printf("\rpaquetes capturados: %d", g_total);
    fflush(stdout);
}

// ============================================================
// imprime un paquete guardado: su analisis completo por capas y
// su contenido crudo en hexadecimal.
// ============================================================
void mostrar_paquete(int indice, int numero) {
    const u_char *paquete = g_capturados[indice].datos;
    int longitud = g_capturados[indice].longitud;

    printf("\n======================================================\n");
    printf("%d | hora: %s | longitud: %d bytes\n",
           numero, g_capturados[indice].tiempo, longitud);

    printf("\ndetalles del paquete:\n");
    analizar_ethernet(paquete);   // reutiliza el analizador (imprime)

    printf("\ndata hexadecimal (raw):\n");
    for (int i = 0; i < longitud; i++) {
        printf("%02X ", paquete[i]);
        if ((i + 1) % 16 == 0) printf("\n");
    }
    printf("\n======================================================\n");
}

// ============================================================
// recorre los paquetes guardados y muestra solo los que cumplen
// los filtros actuales. al final dice cuantos se mostraron.
// ============================================================
void mostrar_filtrados(const struct filtros *f) {
    int mostrados = 0;
    for (int i = 0; i < g_total; i++) {
        struct info_paquete info;
        extraer_info(g_capturados[i].datos, &info);
        if (!pasa_filtro(&info, f)) continue;
        mostrados++;
        mostrar_paquete(i, mostrados);
    }
    printf("\nse mostraron %d de %d paquetes capturados\n", mostrados, g_total);
}

// ============================================================
// pregunta uno por uno los filtros. enter deja el filtro vacio.
// ============================================================
void configurar_filtros(struct filtros *f) {
    printf("\n--- configurar filtros (enter = sin ese filtro) ---\n");
    printf("protocolo (TCP, UDP, ICMP, IGMP, ARP) [TODOS]: ");
    leer_linea(f->protocolo, sizeof(f->protocolo));
    printf("ip de origen [todas]: ");
    leer_linea(f->ip_origen, sizeof(f->ip_origen));
    printf("ip de destino [todas]: ");
    leer_linea(f->ip_destino, sizeof(f->ip_destino));
    printf("puerto, origen o destino [todos]: ");
    leer_linea(f->puerto, sizeof(f->puerto));
}

// ============================================================
// exporta a csv los paquetes que cumplen los filtros actuales.
// ============================================================
void exportar_csv(const struct filtros *f) {
    char nombre[128];
    printf("nombre del archivo csv (vacio = cancelar): ");
    leer_linea(nombre, sizeof(nombre));
    if (strlen(nombre) == 0) { printf("exportacion cancelada\n"); return; }

    // si el nombre no termina en .csv, se le agrega la extension
    if (strstr(nombre, ".csv") == NULL) strcat(nombre, ".csv");

    FILE *csv = fopen(nombre, "w");
    if (csv == NULL) { printf("no se pudo crear el archivo\n"); return; }

    // primera fila: los encabezados de columna
    fprintf(csv, "No,Tiempo,Origen,Destino,Protocolo,PuertoOrigen,PuertoDestino,Longitud\n");

    int guardados = 0;
    for (int i = 0; i < g_total; i++) {
        struct info_paquete info;
        extraer_info(g_capturados[i].datos, &info);
        if (!pasa_filtro(&info, f)) continue;   // solo los que pasan el filtro
        guardados++;
        fprintf(csv, "%d,%s,%s,%s,%s,%d,%d,%d\n",
                guardados, g_capturados[i].tiempo,
                info.ip_origen, info.ip_destino, info.protocolo,
                info.puerto_origen, info.puerto_destino,
                g_capturados[i].longitud);
    }
    fclose(csv);
    printf("se guardaron %d paquetes en %s\n", guardados, nombre);
}

int main(){
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_if_t *alldevs;
    pcap_if_t *dispositivo;
    pcap_addr_t *direccion;

    // se obtiene la lista de interfaces de red disponibles
    if(pcap_findalldevs(&alldevs,errbuf)==-1){
        printf("error: %s\n", errbuf);
        return 1;
    }

    printf("=== interfaces de red disponibles ===\n\n");
    int contador=1;

    // se recorre la lista y se imprime cada interfaz con su ip
    dispositivo=alldevs;
    while(dispositivo!=NULL){
        printf("%d-interfaz: %s\n", contador, dispositivo->name);
        if(dispositivo->flags & PCAP_IF_UP){
            printf("    estado: encendida\n");
        }
        direccion= dispositivo->addresses;
        while(direccion != NULL){
            if(direccion->addr != NULL && direccion->addr->sa_family == AF_INET){
                struct sockaddr_in *ipv4 = (struct sockaddr_in *)direccion->addr;
                printf("    ip: %s\n", inet_ntoa(ipv4->sin_addr));
            }
            direccion=direccion->next;
        }
        printf("\n");
        dispositivo=dispositivo->next;
        contador++;
    }

    // se pide el numero de interfaz (se lee como texto y se convierte)
    char entrada[16];
    printf("selecciona el numero de la interfaz para iniciar la captura (1-%d): ", contador-1);
    leer_linea(entrada, sizeof(entrada));
    int opcion = atoi(entrada);

    if(opcion <1 || opcion >= contador){
        printf("error: opcion no valida\n");
        pcap_freealldevs(alldevs);
        return 1;
    }

    // se avanza por la lista hasta la interfaz elegida
    dispositivo=alldevs;
    for(int i=1; i<opcion; i++){
        dispositivo=dispositivo->next;
    }

    printf("\niniciando captura en la interfaz: %s\n", dispositivo->name);
    printf("se captura todo y se presiona ctrl+c para detener y filtrar\n\n");

    // se abre la interfaz en modo de captura
    pcap_t *sesion= pcap_open_live(dispositivo->name, BUFSIZ, 1, 1000, errbuf);
    if(sesion==NULL){
        printf("no se pudo abrir el dispositivo %s: %s\n", dispositivo->name, errbuf);
        pcap_freealldevs(alldevs);
        return 1;
    }

    // ya no se necesita la lista de interfaces, se libera
    pcap_freealldevs(alldevs);

    // se guarda la sesion en la global y se instala el manejador de ctrl+c
    sesion_global = sesion;
    signal(SIGINT, manejar_ctrlc);

    // ====== fase de captura: guarda todos los paquetes en memoria ======
    pcap_loop(sesion, 0, procesar_paquete, NULL);

    // al detener, se cierra la sesion y se restaura el ctrl+c normal
    pcap_close(sesion);
    sesion_global = NULL;
    signal(SIGINT, SIG_DFL);   // ahora ctrl+c vuelve a cerrar el programa
    printf("\n\ncaptura finalizada. total capturado: %d paquetes\n", g_total);

    // ====== fase de filtrado: menu sobre los paquetes capturados ======
    struct filtros f;
    memset(&f, 0, sizeof(f));   // sin filtros al inicio (muestra todo)

    int op = -1;
    while (op != 0) {
        printf("\n=== menu (paquetes capturados: %d) ===\n", g_total);
        printf("filtros actuales -> protocolo:[%s] origen:[%s] destino:[%s] puerto:[%s]\n",
               f.protocolo, f.ip_origen, f.ip_destino, f.puerto);
        printf("1. mostrar paquetes (aplica filtros)\n");
        printf("2. configurar / cambiar filtros\n");
        printf("3. limpiar filtros\n");
        printf("4. exportar a csv (aplica filtros)\n");
        printf("0. salir\n");
        printf("opcion: ");

        char e[16];
        leer_linea(e, sizeof(e));
        op = atoi(e);

        switch (op) {
            case 1: mostrar_filtrados(&f); break;
            case 2: configurar_filtros(&f); break;
            case 3: memset(&f, 0, sizeof(f)); printf("filtros limpiados\n"); break;
            case 4: exportar_csv(&f); break;
            case 0: break;
            default: printf("opcion no valida\n"); break;
        }
    }

    // se libera la memoria reservada para cada paquete copiado
    for (int i = 0; i < g_total; i++) free(g_capturados[i].datos);

    printf("programa terminado\n");
    return 0;
}