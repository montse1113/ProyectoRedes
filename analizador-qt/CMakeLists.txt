cmake_minimum_required(VERSION 3.19)
project(analizadorQt LANGUAGES CXX)

find_package(Qt6 6.5 REQUIRED COMPONENTS Core Widgets)
find_library(PCAP_LIBRARY pcap REQUIRED)

message(STATUS ">>> PCAP_LIBRARY encontrada en: ${PCAP_LIBRARY}")

qt_standard_project_setup()

qt_add_executable(analizadorQt
    WIN32 MACOSX_BUNDLE
    main.cpp
    mainwindow.cpp
    mainwindow.h
    mainwindow.ui
    paquete_info.h
    analizador.h
    pcapworker.h pcapworker.cpp


)

target_link_libraries(analizadorQt
    PRIVATE
        Qt::Core
        Qt::Widgets
        ${PCAP_LIBRARY}
)

include(GNUInstallDirs)
install(TARGETS analizadorQt
    BUNDLE  DESTINATION .
    RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
    LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
)

qt_generate_deploy_app_script(
    TARGET analizadorQt
    OUTPUT_SCRIPT deploy_script
    NO_UNSUPPORTED_PLATFORM_ERROR
)
install(SCRIPT ${deploy_script})
