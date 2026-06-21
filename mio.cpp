#include <stdio.h>
#include <pcap/pcap.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <netinet/if_ether.h>
#include <netinet/ip.h>
#include "analizador.h"



void procesar_paquete(u_char *args, const struct pcap_pkthdr *encabezado, const u_char *paquete) {
    printf("\n======================================================\n");
    static int contador=1;
    // 'encabezado' contiene meta-información de libpcap (como a qué hora llego y cuanto mide).
    // 'paquete' es un puntero al primer byte de los datos reales del paquete.
    printf("%d | Paquete capturado | Longitud total: %d bytes\n",contador++, encabezado->len);

    //le pasamos el puntero del inicio del paquete a nuestra funcion raiz.
    //todos los paquetes de red local empiezan con la capa Ethernet.
    printf("\nDetalles del paquete:\n");
    analizar_ethernet(paquete); //

    printf("\nData Hexadecimal (RAW):\n");
    for (int i = 0; i < encabezado->len; i++) {
        printf("%02X ", paquete[i]);
        if ((i + 1) % 16 == 0) printf("\n");
    }
    printf("\n======================================================\n");
}

int main(){
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_if_t *alldevs;
    pcap_if_t *dispositivo;
    pcap_addr_t *direccion;

    if(pcap_findalldevs(&alldevs,errbuf)==-1){
        printf("Error: %s\n", errbuf);
        return 1;
    }

    printf("=== INTERFACES DE RED DISPONIBLES ===\n\n");
    int contador=1;

    dispositivo=alldevs;
    while(dispositivo!=NULL){
        printf("%d-Interfaz: %s\n", contador, dispositivo->name);

        if(dispositivo->flags & PCAP_IF_UP){
            printf("    Estado: ENCENDIDA\n");
        }

        direccion= dispositivo->addresses;
        while(direccion != NULL){
            if(direccion->addr != NULL && direccion->addr->sa_family == AF_INET){
                struct sockaddr_in *ipv4 = (struct sockaddr_in *)direccion->addr;
                printf("    IP: %s\n", inet_ntoa(ipv4->sin_addr));
            }
            direccion=direccion->next;
        }
        printf("\n");
        dispositivo=dispositivo->next;
        contador++;
        
    }


    int opcion=0;
    printf("Selecciona el numero de la interfaz para iniciar la captura (1-%d): ", contador-1);
    scanf("%d", &opcion);

    if(opcion <1 || opcion >= contador){
        printf("Error: Opcion no valida\n");
        pcap_freealldevs(alldevs);
        return 1;
    }

    dispositivo=alldevs;
    for(int i=1; i<opcion; i++){
        dispositivo=dispositivo->next;
    }

    printf("\nIniciando captura en la interfaz: %s\n", dispositivo->name);
    printf("Presiona Ctrl+C para detener \n\n");

    pcap_t *sesion= pcap_open_live(dispositivo->name, BUFSIZ, 1, 1000, errbuf);
    if(sesion==NULL){
        printf("No se pudo abrir el dispositivo %s: %s\n", dispositivo->name, errbuf);
        pcap_freealldevs(alldevs);
        return 1;
    }
    
    pcap_freealldevs(alldevs);

    pcap_loop(sesion, 0, procesar_paquete, NULL);//esta funcion pone a la interfaz a escuchar 
    pcap_close(sesion);                         //Cada vez que llega un paquete, libpcap llama a procesar_paquete
                                            //y le pasa los datos crudos
   return 0;
}