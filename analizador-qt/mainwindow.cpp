
#include "mainwindow.h"
#include "ui_mainwindow.h"

#include <QComboBox>
#include <QPushButton>
#include <QTableWidget>
#include <QTableWidgetItem>
#include <QTextEdit>
#include <QLabel>
#include <QHBoxLayout>
#include <QVBoxLayout>
#include <QSplitter>
#include <QHeaderView>
#include <QMessageBox>
#include <QFont>
#include <QLineEdit>

#include <pcap/pcap.h>

MainWindow::MainWindow(QWidget *parent)
    : QMainWindow(parent)
    , ui(new Ui::MainWindow)
{
    ui->setupUi(this);
    setWindowTitle("Analizador de paquetes biker");
    resize(1100, 700);

    construirUI();
    llenarComboInterfaces();
}

MainWindow::~MainWindow()
{
    // Si la captura sigue corriendo, paramos limpiamente
    if (m_hiloCaptura && m_hiloCaptura->isRunning()) {
        if (m_worker) m_worker->detener();
        m_hiloCaptura->quit();
        m_hiloCaptura->wait();
    }
    delete ui;
}

// ============================================================
// Construcción de la interfaz por código
// ============================================================
void MainWindow::construirUI()
{
    // ----- Barra superior: combo + botones -----
    m_comboInterfaces = new QComboBox(this);
    m_comboInterfaces->setMinimumWidth(220);

    m_btnIniciar = new QPushButton("    Iniciar", this);
    m_btnDetener = new QPushButton("Detener", this);
    m_btnDetener->setEnabled(false);

    m_lblEstado = new QLabel("Listo", this);

    QHBoxLayout *barra = new QHBoxLayout();
    barra->addWidget(new QLabel("Interfaz:", this));
    barra->addWidget(m_comboInterfaces);
    barra->addWidget(m_btnIniciar);
    barra->addWidget(m_btnDetener);
    barra->addStretch();
    barra->addWidget(m_lblEstado);

    // ----- Fila de filtros -----
    m_comboProtocolo = new QComboBox(this);
    m_comboProtocolo->addItems({"TODOS", "TCP", "UDP", "ICMP", "ICMPv6",
                                "IGMP", "ARP"});

    m_filtroIp = new QLineEdit(this);
    m_filtroIp->setPlaceholderText("ej: 192.168.1");
    m_filtroIp->setMaximumWidth(200);

    m_filtroPuerto = new QLineEdit(this);
    m_filtroPuerto->setPlaceholderText("ej: 443");
    m_filtroPuerto->setMaximumWidth(100);

    m_btnLimpiar = new QPushButton("Limpiar", this);

    QHBoxLayout *filtros = new QHBoxLayout();
    filtros->addWidget(new QLabel("Protocolo:", this));
    filtros->addWidget(m_comboProtocolo);
    filtros->addWidget(new QLabel("IP:", this));
    filtros->addWidget(m_filtroIp);
    filtros->addWidget(new QLabel("Puerto:", this));
    filtros->addWidget(m_filtroPuerto);
    filtros->addWidget(m_btnLimpiar);
    filtros->addStretch();

    // ----- Tabla de paquetes -----
    m_tabla = new QTableWidget(this);
    m_tabla->setColumnCount(6);
    m_tabla->setHorizontalHeaderLabels(
        {"#", "Tiempo", "Origen", "Destino", "Protocolo", "Info"});
    m_tabla->setSelectionBehavior(QAbstractItemView::SelectRows);
    m_tabla->setSelectionMode(QAbstractItemView::SingleSelection);
    m_tabla->setEditTriggers(QAbstractItemView::NoEditTriggers);
    m_tabla->verticalHeader()->setVisible(false);
    m_tabla->horizontalHeader()->setStretchLastSection(true);
    m_tabla->setColumnWidth(0, 50);
    m_tabla->setColumnWidth(1, 110);
    m_tabla->setColumnWidth(2, 160);
    m_tabla->setColumnWidth(3, 160);
    m_tabla->setColumnWidth(4, 100);

    // ----- Panel de detalles -----
    m_detalles = new QTextEdit(this);
    m_detalles->setReadOnly(true);
    QFont monoFont("Monospace");
    monoFont.setStyleHint(QFont::TypeWriter);
    m_detalles->setFont(monoFont);
    m_detalles->setPlaceholderText("Haz click en un paquete para ver sus detalles");

    // ----- Splitter vertical: tabla arriba, detalles abajo -----
    QSplitter *splitter = new QSplitter(Qt::Vertical, this);
    splitter->addWidget(m_tabla);
    splitter->addWidget(m_detalles);
    splitter->setStretchFactor(0, 3);
    splitter->setStretchFactor(1, 2);

    // ----- Layout principal -----
    QWidget *central = new QWidget(this);
    QVBoxLayout *layoutPrincipal = new QVBoxLayout(central);
    layoutPrincipal->addLayout(barra);
    layoutPrincipal->addLayout(filtros);
    layoutPrincipal->addWidget(splitter);
    setCentralWidget(central);

    // ----- Conexiones de botones y tabla -----
    connect(m_btnIniciar, &QPushButton::clicked,
            this, &MainWindow::onIniciarClicked);
    connect(m_btnDetener, &QPushButton::clicked,
            this, &MainWindow::onDetenerClicked);
    connect(m_tabla, &QTableWidget::itemSelectionChanged,
            this, &MainWindow::onFilaSeleccionada);
    // Conexiones de filtros
    connect(m_comboProtocolo, &QComboBox::currentTextChanged,
            this, &MainWindow::onFiltroChanged);
    connect(m_filtroIp, &QLineEdit::textChanged,
            this, &MainWindow::onFiltroChanged);
    connect(m_filtroPuerto, &QLineEdit::textChanged,
            this, &MainWindow::onFiltroChanged);
    connect(m_btnLimpiar, &QPushButton::clicked,
            this, &MainWindow::onLimpiarFiltro);
}

// ============================================================
// Llenar el combo con las interfaces de red disponibles
// (lo mismo que hacías en tu main.c original)
// ============================================================
void MainWindow::llenarComboInterfaces()
{
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_if_t *alldevs = nullptr;

    if (pcap_findalldevs(&alldevs, errbuf) == -1) {
        QMessageBox::critical(this, "Error",
                              QString("No se pudieron listar interfaces: %1").arg(errbuf));
        return;
    }

    for (pcap_if_t *d = alldevs; d != nullptr; d = d->next) {
        QString nombre = d->name;
        QString descripcion = d->description ? d->description : "";
        QString textoCombo = descripcion.isEmpty()
                                 ? nombre
                                 : QString("%1 (%2)").arg(nombre, descripcion);
        // Guardamos el nombre real como dato del item
        m_comboInterfaces->addItem(textoCombo, nombre);
    }

    pcap_freealldevs(alldevs);
}

// ============================================================
// Botón Iniciar
// ============================================================
void MainWindow::onIniciarClicked()
{
    if (m_comboInterfaces->count() == 0) {
        QMessageBox::warning(this, "Aviso", "No hay interfaces disponibles");
        return;
    }

    QString nombreInterfaz = m_comboInterfaces->currentData().toString();

    // Limpiamos resultados previos
    m_tabla->setRowCount(0);
    m_detalles->clear();
    m_paquetes.clear();

    // Creamos el worker y su hilo
    m_hiloCaptura = new QThread(this);
    m_worker = new PcapWorker();           // sin parent: lo manejamos manual
    m_worker->setInterfaz(nombreInterfaz);
    m_worker->moveToThread(m_hiloCaptura); // el worker vivirá en ese hilo

    // Cuando el hilo arranque, llama a iniciar() del worker
    connect(m_hiloCaptura, &QThread::started,
            m_worker, &PcapWorker::iniciar);

    // Señales del worker -> slots de la UI
    connect(m_worker, &PcapWorker::paqueteCapturado,
            this, &MainWindow::onPaqueteCapturado);
    connect(m_worker, &PcapWorker::errorCaptura,
            this, &MainWindow::onErrorCaptura);
    connect(m_worker, &PcapWorker::capturaTerminada,
            this, &MainWindow::onCapturaTerminada);

    // Limpieza cuando termina
    connect(m_worker, &PcapWorker::capturaTerminada,
            m_hiloCaptura, &QThread::quit);
    connect(m_hiloCaptura, &QThread::finished,
            m_worker, &QObject::deleteLater);
    connect(m_hiloCaptura, &QThread::finished,
            m_hiloCaptura, &QObject::deleteLater);

    m_hiloCaptura->start();

    m_btnIniciar->setEnabled(false);
    m_btnDetener->setEnabled(true);
    m_comboInterfaces->setEnabled(false);
    m_lblEstado->setText("Capturando...");
}

// ============================================================
// Botón Detener
// ============================================================
void MainWindow::onDetenerClicked()
{
    if (m_worker) m_worker->detener();
    m_lblEstado->setText("Deteniendo...");
    m_btnDetener->setEnabled(false);
}

// ============================================================
// Llegó un paquete (señal del worker)
// ============================================================
void MainWindow::onPaqueteCapturado(PaqueteInfo info)
{
    // Guardamos el paquete completo
    m_paquetes.append(info);

    // Agregamos una fila a la tabla
    int fila = m_tabla->rowCount();
    m_tabla->insertRow(fila);

    m_tabla->setItem(fila, 0, new QTableWidgetItem(QString::number(info.numero)));
    m_tabla->setItem(fila, 1, new QTableWidgetItem(info.tiempo));
    m_tabla->setItem(fila, 2, new QTableWidgetItem(info.ipOrigen.isEmpty()
                                                       ? info.macOrigen
                                                       : info.ipOrigen));
    m_tabla->setItem(fila, 3, new QTableWidgetItem(info.ipDestino.isEmpty()
                                                       ? info.macDestino
                                                       : info.ipDestino));
    m_tabla->setItem(fila, 4, new QTableWidgetItem(info.protocolo));
    m_tabla->setItem(fila, 5, new QTableWidgetItem(info.resumenInfo));

    if (!paqueteCumpleFiltro(info)) {
        m_tabla->setRowHidden(fila, true);
    }

    // Auto-scroll a la última fila
    m_tabla->scrollToBottom();
}

// ============================================================
// Error del worker
// ============================================================
void MainWindow::onErrorCaptura(QString mensaje)
{
    QMessageBox::critical(this, "Error de captura", mensaje);
    m_lblEstado->setText("Error");
}

// ============================================================
// Captura terminó (el hilo va a morir)
// ============================================================
void MainWindow::onCapturaTerminada()
{
    m_btnIniciar->setEnabled(true);
    m_btnDetener->setEnabled(false);
    m_comboInterfaces->setEnabled(true);
    m_lblEstado->setText(QString("Listo (%1 paquetes)").arg(m_paquetes.size()));

    // El worker y el hilo se autodestruyen por los connects con deleteLater
    m_worker = nullptr;
    m_hiloCaptura = nullptr;
}

// ============================================================
// Click en una fila de la tabla
// ============================================================
void MainWindow::onFilaSeleccionada()
{
    int fila = m_tabla->currentRow();
    if (fila < 0 || fila >= m_paquetes.size()) return;

    const PaqueteInfo &info = m_paquetes[fila];

    QString texto;
    texto += QString("Paquete #%1\n").arg(info.numero);
    texto += QString("Tiempo: %1\n").arg(info.tiempo);
    texto += QString("Longitud: %1 bytes\n").arg(info.longitud);
    texto += "─────────────────────────────────────\n";
    texto += info.detallesCompletos;

    m_detalles->setPlainText(texto);
}

// ============================================================
// Decide si un paquete cumple con los filtros actuales
// ============================================================
bool MainWindow::paqueteCumpleFiltro(const PaqueteInfo &info) const
{
    // Filtro de protocolo
    QString protoFiltro = m_comboProtocolo->currentText();
    if (protoFiltro != "TODOS" && info.protocolo != protoFiltro) {
        return false;
    }

    // Filtro de IP (busca subcadena en origen o destino, case-insensitive)
    QString ipFiltro = m_filtroIp->text().trimmed();
    if (!ipFiltro.isEmpty()) {
        bool coincide =
            info.ipOrigen.contains(ipFiltro, Qt::CaseInsensitive) ||
            info.ipDestino.contains(ipFiltro, Qt::CaseInsensitive);
        if (!coincide) return false;
    }

    // Filtro de puerto (busca el número en el resumenInfo,
    // que tiene formato tipo "443 → 51234 [ACK]")
    QString puertoFiltro = m_filtroPuerto->text().trimmed();
    if (!puertoFiltro.isEmpty()) {
        if (!info.resumenInfo.contains(puertoFiltro)) {
            return false;
        }
    }

    return true;
}

// ============================================================
// Reaplica el filtro: oculta/muestra filas según el criterio actual
// ============================================================
void MainWindow::onFiltroChanged()
{
    int visibles = 0;
    for (int fila = 0; fila < m_tabla->rowCount(); ++fila) {
        // m_paquetes[fila] tiene el PaqueteInfo correspondiente a esa fila
        bool mostrar = paqueteCumpleFiltro(m_paquetes[fila]);
        m_tabla->setRowHidden(fila, !mostrar);
        if (mostrar) ++visibles;
    }
    m_lblEstado->setText(QString("Mostrando %1 / %2 paquetes")
                             .arg(visibles).arg(m_paquetes.size()));
}

// ============================================================
// Limpiar todos los filtros
// ============================================================
void MainWindow::onLimpiarFiltro()
{
    m_comboProtocolo->setCurrentIndex(0);  // "TODOS"
    m_filtroIp->clear();
    m_filtroPuerto->clear();
    // onFiltroChanged se va a disparar solo por los cambios anteriores
}
