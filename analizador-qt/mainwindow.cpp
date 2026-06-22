#include "mainwindow.h"
#include "ui_mainwindow.h"

#include <QTableWidgetItem>
#include <QHeaderView>
#include <QMessageBox>
#include <QFont>
#include <QFileDialog>
#include <QTextStream>
#include <QFile>

#include <pcap/pcap.h>

MainWindow::MainWindow(QWidget *parent)
    : QMainWindow(parent)
    , ui(new Ui::MainWindow)
{
    ui->setupUi(this);
    setWindowTitle("Sniffer - Redes I");
    resize(1100, 700);

    configurarUI();
    llenarComboInterfaces();

    // ----- Conexiones de botones y tabla -----
    connect(ui->btnIniciar, &QPushButton::clicked,
            this, &MainWindow::onIniciarClicked);
    connect(ui->btnDetener, &QPushButton::clicked,
            this, &MainWindow::onDetenerClicked);
    connect(ui->tabla, &QTableWidget::itemSelectionChanged,
            this, &MainWindow::onFilaSeleccionada);

    // ----- Conexiones de filtros -----
    connect(ui->comboProtocolo, &QComboBox::currentTextChanged,
            this, &MainWindow::onFiltroChanged);
    connect(ui->filtroIp, &QLineEdit::textChanged,
            this, &MainWindow::onFiltroChanged);
    connect(ui->filtroIpDst, &QLineEdit::textChanged,
            this, &MainWindow::onFiltroChanged);
    connect(ui->filtroPuerto, &QLineEdit::textChanged,
            this, &MainWindow::onFiltroChanged);
    connect(ui->btnLimpiar, &QPushButton::clicked,
            this, &MainWindow::onLimpiarFiltro);
    connect(ui->btnExportar, &QPushButton::clicked,
            this, &MainWindow::onExportarClicked);
}

MainWindow::~MainWindow()
{
    if (m_hiloCaptura && m_hiloCaptura->isRunning()) {
        if (m_worker) m_worker->detener();
        m_hiloCaptura->quit();
        m_hiloCaptura->wait();
    }
    delete ui;
}

// ============================================================
// Ajustes de la UI que no se pueden hacer (o no hiciste) en el .ui
// ============================================================
void MainWindow::configurarUI()
{
    // Configuración de la tabla
    ui->tabla->setColumnCount(6);
    ui->tabla->setHorizontalHeaderLabels(
        {"#", "Tiempo", "Origen", "Destino", "Protocolo", "Info"});
    ui->tabla->horizontalHeader()->setVisible(true);
    ui->tabla->setSelectionBehavior(QAbstractItemView::SelectRows);
    ui->tabla->setSelectionMode(QAbstractItemView::SingleSelection);
    ui->tabla->setEditTriggers(QAbstractItemView::NoEditTriggers);
    ui->tabla->verticalHeader()->setVisible(false);
    ui->tabla->horizontalHeader()->setStretchLastSection(true);
    ui->tabla->setColumnWidth(0, 50);
    ui->tabla->setColumnWidth(1, 110);
    ui->tabla->setColumnWidth(2, 160);
    ui->tabla->setColumnWidth(3, 160);
    ui->tabla->setColumnWidth(4, 100);

    // Panel de detalles con fuente monoespaciada
    ui->detalles->setReadOnly(true);
    QFont monoFont("Monospace");
    monoFont.setStyleHint(QFont::TypeWriter);
    ui->detalles->setFont(monoFont);

    //panel hex tambien con fuente mono
    ui->hexView->setReadOnly(true);
    ui->hexView->setFont(monoFont);

    // Estado inicial de botones
    ui->btnDetener->setEnabled(false);

    // ----- se reacomodan las areas: tabla arriba, detalles, hex abajo -----
    ui->splitter->insertWidget(0, ui->tabla);     // la tabla pasa al tope
    ui->splitter->insertWidget(1, ui->detalles);  // detalles al medio
    // hexView queda solo al final
    ui->splitter->setStretchFactor(0, 5);  // la tabla se lleva la mayor parte
    ui->splitter->setStretchFactor(1, 3);  // detalles
    ui->splitter->setStretchFactor(2, 2);  // hex

    // se da mas aire a las filas
    ui->tabla->verticalHeader()->setDefaultSectionSize(26);

    // ----- lavado de cara general -----
    this->setStyleSheet(R"(
        QPushButton {
            padding: 6px 14px;
            border: 1px solid #bdbdbd;
            border-radius: 6px;
            background: #f5f5f5;
        }
        QPushButton:hover { background: #e9e9e9; }
        QPushButton:disabled { color: #9e9e9e; background: #fafafa; }
        QLineEdit, QComboBox {
            padding: 4px 6px;
            border: 1px solid #cfcfcf;
            border-radius: 6px;
            background: white;
        }
        QHeaderView::section {
            background: #455a64;
            color: white;
            padding: 6px;
            border: none;
            font-weight: bold;
        }
        QTableWidget {
            gridline-color: #e0e0e0;
            selection-background-color: #90caf9;
            selection-color: black;
        }
        QTextEdit { border: 1px solid #cfcfcf; border-radius: 6px; }
    )");
}

// ============================================================
// Llenar el combo con las interfaces de red disponibles
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
        ui->comboInterfaces->addItem(textoCombo, nombre);
    }

    pcap_freealldevs(alldevs);
}

// ============================================================
// Boton Iniciar
//  Corre en el hilo principal su trabajo es montar el hilo captura y dejar unir las señales
// para que todo se comunique solo. no captura nada por si mismo solo prepara y arranca al worker
// ============================================================
void MainWindow::onIniciarClicked()
{
    if (ui->comboInterfaces->count() == 0) {
        QMessageBox::warning(this, "Aviso", "No hay interfaces disponibles");
        return;
    }
    //se saca el nombre real de la interfaz
    QString nombreInterfaz = ui->comboInterfaces->currentData().toString();
    //se limpia los resultados de la captura anterior
    ui->tabla->setRowCount(0);
    ui->detalles->clear();
    ui->hexView->clear();
    m_paquetes.clear();
    //aqui nace el segundo hilo
    m_hiloCaptura = new QThread(this); //el hilo (vacio aun)
    m_worker = new PcapWorker();
    m_worker->setInterfaz(nombreInterfaz);
    //aqui se le dice a Qt "este worker le pertenece al hilo de captura"
    //sin esto se congelaria
    m_worker->moveToThread(m_hiloCaptura);


    //cuando el hilo arranque, llama a iniciar() del worker
    connect(m_hiloCaptura, &QThread::started,
            m_worker, &PcapWorker::iniciar);


    //señales del worker (emitidas en el hilo en captura
    //ui ejecutados en el hilo principal, Qt hace el cruce solo
    connect(m_worker, &PcapWorker::paqueteCapturado,
            this, &MainWindow::onPaqueteCapturado);
    connect(m_worker, &PcapWorker::errorCaptura,
            this, &MainWindow::onErrorCaptura);
    connect(m_worker, &PcapWorker::capturaTerminada,
            this, &MainWindow::onCapturaTerminada);

    //la cadena de auto-destruccion
    //cuando la captura termina, el hilo se detiene, cuando el hilo termina
    //se borran solos el worker y el hilo, deleteLater espera a que sea seguro borrar
    connect(m_worker, &PcapWorker::capturaTerminada,
            m_hiloCaptura, &QThread::quit);
    connect(m_hiloCaptura, &QThread::finished,
            m_worker, &QObject::deleteLater);
    connect(m_hiloCaptura, &QThread::finished,
            m_hiloCaptura, &QObject::deleteLater);
    //arranca el hilo esto dispara la señal started-> iniciar()
    m_hiloCaptura->start();
    //se ajusta la interfaz al estado capturando...
    ui->btnIniciar->setEnabled(false);
    ui->btnDetener->setEnabled(true);
    ui->comboInterfaces->setEnabled(false);
    ui->lblEstado->setText("Capturando...");
}

// ============================================================
// Botón Detener
// ============================================================
void MainWindow::onDetenerClicked()
{
    if (m_worker) m_worker->detener();
    ui->lblEstado->setText("Deteniendo...");
    ui->btnDetener->setEnabled(false);
}

// ============================================================
// Llegó un paquete (señal del worker)
// ============================================================
void MainWindow::onPaqueteCapturado(PaqueteInfo info)
{
    m_paquetes.append(info);

    int fila = ui->tabla->rowCount();
    ui->tabla->insertRow(fila);

    ui->tabla->setItem(fila, 0, new QTableWidgetItem(QString::number(info.numero)));
    ui->tabla->setItem(fila, 1, new QTableWidgetItem(info.tiempo));
    ui->tabla->setItem(fila, 2, new QTableWidgetItem(info.ipOrigen.isEmpty()
                                                         ? info.macOrigen
                                                         : info.ipOrigen));
    ui->tabla->setItem(fila, 3, new QTableWidgetItem(info.ipDestino.isEmpty()
                                                         ? info.macDestino
                                                         : info.ipDestino));
    ui->tabla->setItem(fila, 4, new QTableWidgetItem(info.protocolo));
    ui->tabla->setItem(fila, 5, new QTableWidgetItem(info.resumenInfo));

    QColor color = colorPorProtocolo(info.protocolo);
    for (int c = 0; c < ui->tabla->columnCount(); ++c) {
        ui->tabla->item(fila, c)->setBackground(color);
    }

    if (!paqueteCumpleFiltro(info)) {
        ui->tabla->setRowHidden(fila, true);
    }

    ui->tabla->scrollToBottom();
}

// ============================================================
// Error del worker
// ============================================================
void MainWindow::onErrorCaptura(QString mensaje)
{
    QMessageBox::critical(this, "Error de captura", mensaje);
    ui->lblEstado->setText("Error");
}

// ============================================================
// Captura terminó
// ============================================================
void MainWindow::onCapturaTerminada()
{
    ui->btnIniciar->setEnabled(true);
    ui->btnDetener->setEnabled(false);
    ui->comboInterfaces->setEnabled(true);
    ui->lblEstado->setText(QString("Listo (%1 paquetes)").arg(m_paquetes.size()));

    m_worker = nullptr;
    m_hiloCaptura = nullptr;
}

// ============================================================
// Click en una fila de la tabla
// se dispara cuando el usuario hace clic en una fila de la tabla
// rellena el panel de detalles y el panel hex con la info del paquete eligido
// ============================================================
void MainWindow::onFilaSeleccionada()
{
    int fila = ui->tabla->currentRow();
    //guarda de seguridad si no hay fila valida, salimos. evita leer
    // fuera dle rango de m_paquetes
    if (fila < 0 || fila >= m_paquetes.size()) return;
    // el numero de fila coincida con el indice en m_pquetes
    const PaqueteInfo &info = m_paquetes[fila];
    //area de detalles estructurados
    //se pega el arbol de capas que se construyo durante el analisis (info.detallesCompletos)
    QString texto;
    texto += QString("Paquete #%1\n").arg(info.numero);
    texto += QString("Tiempo: %1\n").arg(info.tiempo);
    texto += QString("Longitud: %1 bytes\n").arg(info.longitud);
    texto += "─────────────────────────────────────\n";
    texto += info.detallesCompletos;

    ui->detalles->setPlainText(texto);
    //info.rawBytes guarda los paquetes tal cual llegaron y formatearHexDump los convierte a texto legible

    ui->hexView->setPlainText(formatearHexDump(info.rawBytes));
}

// ============================================================
// Filtros
// decide si un paquete debe verse con los filtros actuales. devuelkve true (mostrar) false (ocultar)
// ============================================================
bool MainWindow::paqueteCumpleFiltro(const PaqueteInfo &info) const
{
    //filtro protocolo
    QString protoFiltro = ui->comboProtocolo->currentText().trimmed();
    //trimmed() quita espacios sobrantes , caseInsensative ignora mayusculas
    if (protoFiltro != "TODOS" && info.protocolo.compare(protoFiltro, Qt::CaseInsensitive) != 0) {
        return false;
    }
    //filtro ip origen
    QString ipOrigenFiltro = ui->filtroIp->text().trimmed();
    if (!ipOrigenFiltro.isEmpty()) {
        if (!info.ipOrigen.contains(ipOrigenFiltro, Qt::CaseInsensitive))
            return false;
    }
    //filtro ip DESTINO
    QString ipDestinoFiltro = ui->filtroIpDst->text().trimmed();
    if (!ipDestinoFiltro.isEmpty()) {
        if (!info.ipDestino.contains(ipDestinoFiltro, Qt::CaseInsensitive))
            return false;
    }
    //filtro PUERTO
    QString puertoFiltro = ui->filtroPuerto->text().trimmed();
    if (!puertoFiltro.isEmpty()) {
        if (!info.resumenInfo.contains(puertoFiltro)) {
            return false;
        }
    }
    //si paso todos los filtro activos se muestra
    return true;
}

// ============================================================
    // Genera un hex dump estilo Wireshark/hexdump:
    //   offset    bytes en hexadecimal              ASCII
    // ============================================================
QString MainWindow::formatearHexDump(const QByteArray &datos) const
{
    QString resultado;
    const int bytesPorLinea = 16;//16 bytes por renglon
    //se avanza de 16 en 16 bytes. cada linea es una linea del dump.
    for (int i = 0; i < datos.size(); i += bytesPorLinea) {
        // 1) Offset (posición) en hex, 4 dígitos
        resultado += QString("%1   ").arg(i, 4, 16, QChar('0'));

        // 2) Los bytes en hexadecimal
        QString ascii;
        for (int j = 0; j < bytesPorLinea; ++j) {
            if (i + j < datos.size()) {
                unsigned char byte = static_cast<unsigned char>(datos[i + j]);
                resultado += QString("%1 ").arg(byte, 2, 16, QChar('0'));

                // Construimos el ASCII: imprimible o un punto
                if (byte >= 32 && byte < 127)
                    ascii += QChar(byte);
                else
                    ascii += '.';
            } else {
                // Relleno para alinear cuando la última línea es incompleta
                resultado += "   ";
            }

            // Espacio extra a la mitad (separador visual de 8 bytes)
            if (j == 7) resultado += " ";
        }

        // 3) La columna ASCII al final
        resultado += "  " + ascii + "\n";
    }

    return resultado;
}

void MainWindow::onFiltroChanged()
{
    int visibles = 0;
    for (int fila = 0; fila < ui->tabla->rowCount(); ++fila) {
        bool mostrar = paqueteCumpleFiltro(m_paquetes[fila]);
        ui->tabla->setRowHidden(fila, !mostrar);
        if (mostrar) ++visibles;
    }
    ui->lblEstado->setText(QString("Mostrando %1 / %2 paquetes")
                               .arg(visibles).arg(m_paquetes.size()));
}

void MainWindow::onLimpiarFiltro()
{
    ui->comboProtocolo->setCurrentIndex(0);
    ui->filtroIp->clear();
    ui->filtroIpDst->clear();
    ui->filtroPuerto->clear();
}

void MainWindow::onExportarClicked()
{
    // Si no hay nada que exportar, avisamos
    if (m_paquetes.isEmpty()) {
        QMessageBox::information(this, "Exportar",
                                 "No hay paquetes capturados para exportar.");
        return;
    }

    // Dialogo para elegir dónde guardar
    QString rutaArchivo = QFileDialog::getSaveFileName(
        this,
        "Guardar captura como CSV",
        "captura.csv",
        "Archivos CSV (*.csv)");

    // Si el usuario cancelo, rutaArchivo queda vacío
    if (rutaArchivo.isEmpty()) return;

    // Si no escribió la extension, se la agregamos
    if (!rutaArchivo.endsWith(".csv", Qt::CaseInsensitive))
        rutaArchivo += ".csv";

    // Abrir el archivo para escritura
    QFile archivo(rutaArchivo);
    if (!archivo.open(QIODevice::WriteOnly | QIODevice::Text)) {
        QMessageBox::critical(this, "Error",
                              QString("No se pudo crear el archivo:\n%1").arg(rutaArchivo));
        return;
    }

    QTextStream out(&archivo);

    // Encabezados (primera fila del CSV)
    out << "No,Tiempo,Origen,Destino,Protocolo,Aplicacion,Longitud,Info\n";

    // Una fila por cada paquete
    for (const PaqueteInfo &info : m_paquetes) {
        QString origen  = info.ipOrigen.isEmpty()  ? info.macOrigen  : info.ipOrigen;
        QString destino = info.ipDestino.isEmpty() ? info.macDestino : info.ipDestino;

        out << info.numero << ","
            << escaparCSV(info.tiempo) << ","
            << escaparCSV(origen) << ","
            << escaparCSV(destino) << ","
            << escaparCSV(info.protocolo) << ","
            << escaparCSV(info.aplicacion) << ","
            << info.longitud << ","
            << escaparCSV(info.resumenInfo) << "\n";
    }

    archivo.close();

    QMessageBox::information(this, "Exportar",
                             QString("Se exportaron %1 paquetes a:\n%2")
                                 .arg(m_paquetes.size()).arg(rutaArchivo));
}

QString MainWindow::escaparCSV(const QString &campo) const
{
    if (campo.contains(',') || campo.contains('"') || campo.contains('\n')) {
        QString copia = campo;
        copia.replace("\"", "\"\"");   // las comillas internas se duplican
        return "\"" + copia + "\"";
    }
    return campo;
}

// ============================================================
// se devuelve un color de fondo suave segun el protocolo
// del paquete, al estilo de wireshark
// ============================================================
QColor MainWindow::colorPorProtocolo(const QString &proto)
{
    // se normaliza a mayusculas para comparar sin importar el caso
    const QString p = proto.toUpper();

    if (p.contains("ARP"))                      return QColor(0xFA, 0xF0, 0xD7); // amarillo suave
    if (p.contains("ICMP"))                     return QColor(0xFD, 0xD8, 0xD8); // rojo/rosa suave
    if (p.contains("IGMP"))                     return QColor(0xFF, 0xE8, 0xCC); // naranja suave
    if (p.contains("DNS"))                      return QColor(0xCF, 0xE8, 0xD4); // verde-azulado
    if (p.contains("HTTP"))                     return QColor(0xC8, 0xF7, 0xC8); // verde claro
    if (p.contains("TLS") || p.contains("SSL")) return QColor(0xD7, 0xF0, 0xE0); // verde menta
    if (p.contains("QUIC"))                     return QColor(0xE0, 0xD8, 0xF7); // lila
    if (p.contains("UDP"))                      return QColor(0xDA, 0xEE, 0xFF); // azul claro
    if (p.contains("TCP"))                      return QColor(0xE7, 0xE6, 0xFF); // lavanda suave

    return QColor(Qt::white); // blanco por defecto para lo desconocido
}
