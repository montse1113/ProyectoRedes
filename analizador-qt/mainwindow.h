#ifndef MAINWINDOW_H
#define MAINWINDOW_H

#include <QMainWindow>
#include <QThread>

#include "paquete_info.h"
#include "pcapworker.h"

QT_BEGIN_NAMESPACE
namespace Ui { class MainWindow; }
QT_END_NAMESPACE

// Adelanto de clases para no incluir headers pesados aquí
class QComboBox;
class QPushButton;
class QTableWidget;
class QTextEdit;
class QLabel;
class QLineEdit;

class MainWindow : public QMainWindow
{
    Q_OBJECT

public:
    MainWindow(QWidget *parent = nullptr);
    ~MainWindow();

private slots:
    // Botones
    void onIniciarClicked();
    void onDetenerClicked();

    // Eventos del worker (llegan por señal desde el otro hilo)
    void onPaqueteCapturado(PaqueteInfo info);
    void onErrorCaptura(QString mensaje);
    void onCapturaTerminada();

    // Click en una fila de la tabla
    void onFilaSeleccionada();

    void onFiltroChanged();
    void onLimpiarFiltro();

private:
    // Métodos privados
    void construirUI();
    void llenarComboInterfaces();

    bool paqueteCumpleFiltro(const PaqueteInfo &info) const;

    // Widgets que construimos por código
    QComboBox    *m_comboInterfaces = nullptr;
    QPushButton  *m_btnIniciar      = nullptr;
    QPushButton  *m_btnDetener      = nullptr;
    QTableWidget *m_tabla           = nullptr;
    QTextEdit    *m_detalles        = nullptr;
    QLabel       *m_lblEstado       = nullptr;

    QComboBox    *m_comboProtocolo  = nullptr;
    QLineEdit    *m_filtroIp        = nullptr;
    QLineEdit    *m_filtroPuerto    = nullptr;
    QPushButton  *m_btnLimpiar      = nullptr;

    // Worker corriendo en su propio hilo
    QThread      *m_hiloCaptura     = nullptr;
    PcapWorker   *m_worker          = nullptr;

    // Guardamos cada PaqueteInfo recibido para mostrarlo al hacer click
    QList<PaqueteInfo> m_paquetes;

    Ui::MainWindow *ui = nullptr;  // se mantiene aunque no lo usemos
};
#endif // MAINWINDOW_H
