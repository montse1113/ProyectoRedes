#include "pcapworker.h"
#include "analizador.h"

#include <QDateTime>
#include <QDebug>

PcapWorker::PcapWorker(QObject *parent) : QObject(parent) {}

PcapWorker::~PcapWorker() {
    //por si el objeto se destruye con la captura aun viva, se para
    detener();
}

void PcapWorker::setInterfaz(const QString &nombre) {
    //se llama antes de iniciar, desde el hilo principal
    //solo guarda el nombre, no abre nada aun
    m_nombreInterfaz = nombre;
}

//iniciar() este es el cuerpo del hilo de captura
//se dispara por la señal QThread
//y todo lo de aqui se ejecuta en el hilo nuevo, no en la de la interfaz
void PcapWorker::iniciar() {
    if (m_nombreInterfaz.isEmpty()) {
        emit errorCaptura("No se ha seleccionado interfaz");
        emit capturaTerminada();
        return;
    }

    char errbuf[PCAP_ERRBUF_SIZE];

    //abre la tarjeta de red en modo promiscuo
    //si falla por permisos avisa a la interfaz por señal y termina
    m_sesion = pcap_open_live(m_nombreInterfaz.toUtf8().constData(),
                              BUFSIZ, 1, 1000, errbuf);
    if (m_sesion == nullptr) {
        emit errorCaptura(QString("No se pudo abrir %1: %2")
                              .arg(m_nombreInterfaz).arg(errbuf));
        emit capturaTerminada();
        return;
    }

    m_corriendo = true;
    m_contador = 0;

    //pcap_loop se queda aqui bloqueado, no avanca a la linea de abajo hasta que detener() llame a pcap_breakloop
    //por cada paquete que llega, libpcap invoca a callBackPcap y le pasa
    //this para que el callback pueda emitir
    pcap_loop(m_sesion, 0, &PcapWorker::callbackPcap,
              reinterpret_cast<u_char*>(this));
    //se llega aqui solo cuando se rompe el bucle
    pcap_close(m_sesion);
    m_sesion = nullptr;
    m_corriendo = false;

    emit capturaTerminada();//cuando onCapturaTerminada
}

//detener() se llama desde el hilo principal
//pero actua sobre la sesion viva en el hilo de captura
//pcap_breakloop esta diseñado para ser seguro entre hilos
void PcapWorker::detener() {
    if (m_sesion && m_corriendo) {
        //Le dice a pcap_loop que termine. Funciona desde otro hilo.
        pcap_breakloop(m_sesion);
    }
}

//se eejcuta una vex por paquete en el hilo de captura
// es estatica por que libpcap necesita un puntero a funcion normal, no a un metodo de objeto
void PcapWorker::callbackPcap(u_char *user, const struct pcap_pkthdr *cabecera,
                              const u_char *paquete) {
    // Recuperamos el puntero al worker desde 'user'
    PcapWorker *self = reinterpret_cast<PcapWorker*>(user);

    // Llenamos la estructura PaqueteInfo
    PaqueteInfo info;
    info.numero    = ++self->m_contador;
    info.tiempo    = QDateTime::currentDateTime().toString("HH:mm:ss.zzz");
    info.longitud  = cabecera->len;
    info.rawBytes  = QByteArray(reinterpret_cast<const char*>(paquete),
                               cabecera->caplen);

    //Se analiza las capas llama en cascada a
    //IPv4/IPv6/ARP y esos a TCP/UDP/ICMP para rellenar info
    analizar_ethernet(paquete, info);

    // i no se llenó protocolo, ponemos "Unknown"
    if (info.protocolo.isEmpty())
        info.protocolo = "Unknown";

    //se emite la señal como emisor y receptor estan en hilos distintos
    //Qt encola el info y lo entrega a onPaqueteCapturado en el hilo principal
    //por eso se registra PaqueteInfo con qRegisterMetaType en main.cpp
    emit self->paqueteCapturado(info);
}
