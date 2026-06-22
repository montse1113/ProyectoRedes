# Packet Sniffer — Redes I

Analizador de paquetes de red desarrollado en C/C++ con la librería
**libpcap**, como proyecto de la materia Redes I. Captura tráfico en
vivo, decodifica los protocolos por capas, permite filtrar e
inspeccionar cada paquete, y exportar la captura a CSV.

El proyecto incluye dos versiones:

- **Versión de terminal** (C): captura el tráfico y, al detener con
  Ctrl+C, ofrece un menú para filtrar, mostrar y exportar los paquetes.
- **Versión gráfica** (C++ / Qt 6): interfaz tipo Wireshark con tabla
  de paquetes, panel de detalles estructurados y vista hexadecimal.

---

## Plataforma

- Sistema operativo: Linux (probado en Ubuntu)
- Lenguaje: C / C++
- Librería de captura: libpcap

---

## Características

- Captura de paquetes en vivo (inicio / parada con Ctrl+C).
- Decodificación por capas: Ethernet, IPv4, IPv6, ARP, TCP, UDP,
  ICMP, IGMP, e identificación de protocolos de aplicación por puerto.
- Tres áreas de visualización (versión gráfica):
  - Lista del tráfico capturado.
  - Detalles estructurados del paquete seleccionado.
  - Contenido crudo en hexadecimal (hex dump).
- Cuatro filtros: IP origen, IP destino, puerto y protocolo.
- Exportación de la captura a archivo CSV.

---

## Requisitos previos

El proyecto tiene dos versiones con requisitos distintos.

### Para la versión de TERMINAL (mínimos)

Solo se necesita el compilador y libpcap:

    sudo apt update
    sudo apt install build-essential libpcap-dev

> Esta versión NO requiere Qt. Es la opción más rápida si solo se
> quiere probar la captura y el análisis.

### Para la versión GRÁFICA (Qt)

Además de lo anterior, se necesita Qt 6 y CMake:

    sudo apt install cmake qt6-base-dev

---

## Compilación y ejecución

### Versión gráfica — AppImage (sin compilar)

La forma más rápida de probar la versión gráfica. No requiere instalar Qt,
libpcap ni compilar nada: todo viene empaquetado dentro del AppImage. Funciona
en cualquier Linux x86_64 moderno.

1. Descargar la última versión desde la página de Releases:
   https://github.com/montse1113/ProyectoRedes/releases/latest

   O directo por terminal:

       wget https://github.com/montse1113/ProyectoRedes/releases/latest/download/Analizador_de_Paquetes-x86_64.AppImage

2. Dar permisos de ejecución:

       chmod +x Analizador_de_Paquetes-x86_64.AppImage

3. Ejecutar con sudo (la captura de paquetes en modo crudo requiere
   privilegios de root):

       export APPIMAGE_EXTRACT_AND_RUN=1
       sudo -E ./Analizador_de_Paquetes-x86_64.AppImage

> Notas:
> - `APPIMAGE_EXTRACT_AND_RUN=1` evita la dependencia de FUSE, que no todos
>   los sistemas traen instalado.
> - Si la ventana no aparece al usar sudo, ejecutar una sola vez
>   `xhost +SI:localuser:root` y volver a intentarlo.
> - El AppImage debe correr con sudo; el truco de `setcap` solo aplica a la
>   versión compilada localmente (ver más abajo).

### Versión de terminal (C)

Desde la raíz del proyecto:

    g++ mio.cpp -o sniffer -lpcap
    sudo setcap cap_net_raw,cap_net_admin=eip ./sniffer
    ./sniffer

Flujo de uso: se elige la interfaz, se captura todo el tráfico, y al
presionar Ctrl+C aparece un menú para configurar filtros, mostrar los
paquetes que cumplen y exportarlos a CSV.

### Versión gráfica (Qt) — compilar desde el código

Desde la carpeta de la versión gráfica:

    cd analizador-qt
    make run

El comando `make run` compila, aplica los permisos de captura
(pedirá la contraseña) y ejecuta el programa.

Otros comandos del Makefile:

    make          # solo compila
    make permisos # aplica setcap al binario
    make clean    # borra los archivos compilados
    make rebuild  # limpia y recompila desde cero

---

## Nota sobre permisos

La captura de paquetes requiere privilegios especiales en Linux. En
lugar de ejecutar como root, se le otorgan al binario las
*capabilities* mínimas necesarias:

    sudo setcap cap_net_raw,cap_net_admin=eip <binario>

Esto debe reaplicarse cada vez que se recompila (el `make run` de la
versión gráfica ya lo hace automáticamente).

---

## Repositorio

https://github.com/montse1113/ProyectoRedes

## Autores

- Cristofer Guadalupe Herrera Ramirez
- Andrea Montserrat Ramirez Martinez
- Angel Edoardo Hernandez de Carlo
- Oswaldo Emmanuel Muñoz Romo
