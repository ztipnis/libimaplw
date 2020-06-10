include(ExternalProject)
message(STATUS "Will fetch LibreSSL as part of build")
ExternalProject_Add(Project_LibreSSL
    URL https://ftp.openbsd.org/pub/OpenBSD/LibreSSL/libressl-3.0.2.tar.gz 
    BINARY_DIR ${CMAKE_CURRENT_BINARY_DIR}/libressl-3.0.2
    PREFIX ${CMAKE_CURRENT_BINARY_DIR}/libressl-3.0.2
    CMAKE_ARGS -DCMAKE_INSTALL_PREFIX=${CMAKE_CURRENT_BINARY_DIR}/libressl-3.0.2 -G${CMAKE_GENERATOR}
    BUILD_BYPRODUCTS ${CMAKE_CURRENT_BINARY_DIR}/libressl-3.0.2/lib/libcrypto.a
    BUILD_BYPRODUCTS ${CMAKE_CURRENT_BINARY_DIR}/libressl-3.0.2/lib/libssl.a
    BUILD_BYPRODUCTS ${CMAKE_CURRENT_BINARY_DIR}/libressl-3.0.2/lib/libtls.a
)
ExternalProject_Get_Property(Project_LibreSSL INSTALL_DIR)
set(LIBRESSL_INCLUDE_DIR ${INSTALL_DIR}/include)
set(LIBRESSL_CRYPTO_LIBRARY ${INSTALL_DIR}/lib/libcrypto.a CACHE INTERNAL "LibreSSL CRYTO Library Path")
set(LIBRESSL_SSL_LIBRARY ${INSTALL_DIR}/lib/libssl.a CACHE INTERNAL "LibreSSL SSL Library Path")
set(LIBRESSL_TLS_LIBRARY ${INSTALL_DIR}/lib/libtls.a CACHE INTERNAL "LibreSSL TLS Library Path")
# Set LibreSSL::Crypto
if(NOT TARGET LibreSSL::Crypto)
    # Add Library
    add_library(LibreSSL::Crypto STATIC IMPORTED)
    # Set Properties
    set_target_properties(
        LibreSSL::Crypto
        PROPERTIES
            IMPORTED_LINK_INTERFACE_LANGUAGES "C"
            IMPORTED_LOCATION "${LIBRESSL_CRYPTO_LIBRARY}"
    )
    add_dependencies(LibreSSL::Crypto Project_LibreSSL)
endif() # LibreSSL::Crypto

# Set LibreSSL::SSL
if(NOT TARGET LibreSSL::SSL)
    # Add Library
    add_library(LibreSSL::SSL STATIC IMPORTED)
    # Set Properties
    set_target_properties(
        LibreSSL::SSL
        PROPERTIES
            IMPORTED_LINK_INTERFACE_LANGUAGES "C"
            IMPORTED_LOCATION "${LIBRESSL_SSL_LIBRARY}"
            INTERFACE_LINK_LIBRARIES LibreSSL::Crypto
    )
    add_dependencies(LibreSSL::SSL Project_LibreSSL)
endif() # LibreSSL::SSL
# Set LibreSSL::TLS
if(NOT TARGET LibreSSL::TLS)
    add_library(LibreSSL::TLS STATIC IMPORTED)
    set_target_properties(
        LibreSSL::TLS
        PROPERTIES
            IMPORTED_LINK_INTERFACE_LANGUAGES "C"
            IMPORTED_LOCATION "${LIBRESSL_TLS_LIBRARY}"
            INTERFACE_LINK_LIBRARIES LibreSSL::SSL
    )
    add_dependencies(LibreSSL::TLS Project_LibreSSL)
endif() # LibreSSL::TLS
set(LIBRESSL_LIBRARIES LibreSSL::Crypto LibreSSL::SSL LibreSSL::TLS)
mark_as_advanced(LIBRESSL_INCLUDE_DIR LIBRESSL_LIBRARIES LIBRESSL_CRYPTO_LIBRARY LIBRESSL_SSL_LIBRARY LIBRESSL_TLS_LIBRARY)