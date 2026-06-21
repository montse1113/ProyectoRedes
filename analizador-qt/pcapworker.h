#ifndef PCAPWORKER_H
#define PCAPWORKER_H

#include <QObject>
#include <QString>
#include <atomic>
#include <pcap/pcap.h>

#include "paquete_info.h"

// PcapWorker corre en su propio hilo (QThread).
// Cuando llega un paquete, lo analiza y emite la señal paqueteCapturado().
// La UI escucha esa señal y agrega una fila a la tabla.
class PcapWorker : public QObject {
    Q_OBJECT

public:
    explicit PcapWorker(QObject *parent = nullptr);
    ~PcapWorker();

    void setInterfaz(const QString &nombre);

public slots:
    void iniciar();
    void detener();

signals:
    void paqueteCapturado(PaqueteInfo info);
    void errorCaptura(QString mensaje);
    void capturaTerminada();

private:
    // Solo DECLARACIÓN del callback (termina en ; no en {})
    static void callbackPcap(u_char *user,
                             const struct pcap_pkthdr *cabecera,
                             const u_char *paquete);

    // Variables MIEMBRO de la clase (no locales, no dentro de ninguna función)
    QString               m_nombreInterfaz;
    pcap_t               *m_sesion = nullptr;
    std::atomic<int>      m_contador{0};
    std::atomic<bool>     m_corriendo{false};
};

#endif // PCAPWORKER_H
