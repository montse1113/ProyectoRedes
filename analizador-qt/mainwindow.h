#ifndef MAINWINDOW_H
#define MAINWINDOW_H

#include <QMainWindow>
#include <QThread>
#include <QList>

#include "paquete_info.h"
#include "pcapworker.h"

QT_BEGIN_NAMESPACE
namespace Ui { class MainWindow; }
QT_END_NAMESPACE

class MainWindow : public QMainWindow
{
    Q_OBJECT

public:
    MainWindow(QWidget *parent = nullptr);
    ~MainWindow();

private slots:
    void onIniciarClicked();
    void onDetenerClicked();

    void onPaqueteCapturado(PaqueteInfo info);
    void onErrorCaptura(QString mensaje);
    void onCapturaTerminada();

    void onFilaSeleccionada();

    void onFiltroChanged();
    void onLimpiarFiltro();
    void onExportarClicked();

private:
    void configurarUI();          // ajustes que el .ui no cubre
    void llenarComboInterfaces();
    bool paqueteCumpleFiltro(const PaqueteInfo &info) const;
    QString formatearHexDump(const QByteArray &datos) const;
    QString escaparCSV(const QString &campo) const;

    // Worker corriendo en su propio hilo
    QThread    *m_hiloCaptura = nullptr;
    PcapWorker *m_worker      = nullptr;

    // Guardamos cada PaqueteInfo recibido para mostrarlo al hacer click
    QList<PaqueteInfo> m_paquetes;

    Ui::MainWindow *ui = nullptr;
};
#endif // MAINWINDOW_H
