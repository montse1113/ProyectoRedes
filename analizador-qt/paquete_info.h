#ifndef PAQUETE_INFO_H
#define PAQUETE_INFO_H

#include <QString>
#include <QByteArray>
#include <QMetaType>


//Estructura que guarda toda la informacion de un paquete capturado

struct PaqueteInfo {
    int numero=0;
    QString tiempo;
    int longitud=0;

    //capa 2 Ethernet
    QString macOrigen;
    QString macDestino;

    //capa 3 Red (ipv2, ipv6, arp)
    QString ipOrigen;
    QString ipDestino;

    //capa 4 Transporte / identificacion
    QString protocolo;
    QString aplicacion;

    //para la columna de info
    QString resumenInfo;

    //Para paneles de detalles
    QString detallesCompletos;

    //Bytes crudos del paquete
    QByteArray rawBytes;


};

#endif // PAQUETE_INFO_H
