#include "pcapworker.h"
#include "analizador.h"

#include <QDateTime>
#include <QDebug>

PcapWorker::PcapWorker(QObject *parent) : QObject(parent) {}

PcapWorker::~PcapWorker() {
    detener();
}

void PcapWorker::setInterfaz(const QString &nombre) {
    m_nombreInterfaz = nombre;
}

void PcapWorker::iniciar() {
    if (m_nombreInterfaz.isEmpty()) {
        emit errorCaptura("No se ha seleccionado interfaz");
        emit capturaTerminada();
        return;
    }

    char errbuf[PCAP_ERRBUF_SIZE];

    // Abrir la interfaz en modo promiscuo (1), timeout 1000ms
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

    // pcap_loop bloquea aquí hasta que llamen a pcap_breakloop() en detener().
    // El callback recibe 'this' como parámetro 'user' para poder emitir señales.
    pcap_loop(m_sesion, 0, &PcapWorker::callbackPcap,
              reinterpret_cast<u_char*>(this));

    pcap_close(m_sesion);
    m_sesion = nullptr;
    m_corriendo = false;

    emit capturaTerminada();
}

void PcapWorker::detener() {
    if (m_sesion && m_corriendo) {
        // Le dice a pcap_loop que termine. Funciona desde otro hilo.
        pcap_breakloop(m_sesion);
    }
}

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

    // Llama a tu analizador refactorizado
    analizar_ethernet(paquete, info);

    // Si no se llenó protocolo, ponemos "Unknown"
    if (info.protocolo.isEmpty())
        info.protocolo = "Unknown";

    // Emite la señal: Qt automáticamente la traslada al hilo UI
    emit self->paqueteCapturado(info);
}
