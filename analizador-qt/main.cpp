#include "mainwindow.h"
#include "paquete_info.h"

#include <QApplication>
#include <cstdlib>

int main(int argc, char *argv[])
{
    qputenv("QT_QPA_PLATFORM", "xcb");
    QApplication a(argc, argv);

    // Registrar PaqueteInfo para señales/slots entre hilos
    qRegisterMetaType<PaqueteInfo>("PaqueteInfo");

    MainWindow w;
    w.show();
    return a.exec();
}
