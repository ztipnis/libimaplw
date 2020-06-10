cmake_minimum_required(VERSION 3.10)
if ( ${CMAKE_SOURCE_DIR} STREQUAL ${CMAKE_BINARY_DIR} )
    message( FATAL_ERROR "In-source builds not allowed. Please make a new directory and run CMake from there. You may need to remove CMakeCache.txt." )
endif()
set(PROJECT_NAME libIMAPlw)
set(VERSION_NUM 0.1)
project(${PROJECT_NAME} VERSION ${VERSION_NUM})

# specify the C++ standard
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED True)

#include cmake dir for includes
set(CMAKE_MODULE_PATH "${CMAKE_CURRENT_SOURCE_DIR}/CMake;${CMAKE_MODULE_PATH}")


#Boost Library build settings
set(Boost_USE_STATIC_LIBS OFF)
set(Boost_USE_MULTITHREADED ON)
set(Boost_USE_STATIC_RUNTIME OFF)
add_definitions(-DBOOST_ALL_DYN_LINK)


#find LibreSSL (LibTLS)
find_package(LibreSSL)
if(NOT LIBRESSL_FOUND)
    #Check whether to get LibreSSL
    if(FETCH_LIBRESSL)
        include(GetLibreSSL)
    else(FETCH_LIBRESSL)
        message(FATAL_ERROR "LibreSSL not found. If you would like to automagically download, try running CMake with \"-DFETCH_LIBRESSL=True\"")
    endif(FETCH_LIBRESSL)
endif(NOT LIBRESSL_FOUND)


#Find boost library to link
FIND_PACKAGE(Boost 1.54 COMPONENTS locale log log_setup REQUIRED)

#find LibUUID (for uuid generation)
#OSX (& BSD?) have LibUUID functionality built in, and do not require linking
#As such, for Linux-based libUuid is required, otherwise (in case of mistakes,)
#its optional
IF("${CMAKE_SYSTEM}" MATCHES "Linux")
    find_package(LibUuid REQUIRED)
else("${CMAKE_SYSTEM}" MATCHES "Linux")
    find_package(LibUuid)
endif("${CMAKE_SYSTEM}" MATCHES "Linux")


#download Miniz for compression
include(GetMiniz)

#setup target
add_library(libIMAPlw INTERFACE)


target_include_directories(libIMAPlw INTERFACE  ${Boost_INCLUDE_DIRS} ${LIBRESSL_INCLUDE_DIR})

IF(MINIZ_GOTTEN)
    target_include_directories(libIMAPlw INTERFACE ${MINIZ_INCLUDE_DIR})
endif(MINIZ_GOTTEN)


include(GetMimetic)
IF(MIMETIC_GOTTEN)
    target_include_directories(libIMAPlw INTERFACE ${MIMETIC_INCLUDE_DIR})
ENDIF(MIMETIC_GOTTEN)




IF(LIBUUID_FOUND)
    target_include_directories(libIMAPlw INTERFACE ${LIBUUID_INCLUDE_DIRS})
ENDIF(LIBUUID_FOUND)


target_link_libraries(libIMAPlw INTERFACE SocketPool LibreSSL::TLS ${Boost_LIBRARIES})


#Link LibUUID if found otherwise don't
IF(LIBUUID_FOUND)
target_link_libraries(libIMAPlw INTERFACE ${LIBUUID_LIBRARIES})
ENDIF(LIBUUID_FOUND)


IF(MINIZ_GOTTEN)
    target_link_libraries(libIMAPlw INTERFACE ${MINIZ_LIBRARIES})
    target_include_directories(libIMAPlw INTERFACE ${MINIZ_INCLUDE_DIR})
ELSE(MINIZ_GOTTEN)
    message(STATUS "Miniz not found")
endif(MINIZ_GOTTEN)

IF(MIMETIC_GOTTEN)
    target_link_libraries(libIMAPlw INTERFACE ${MIMETIC_LIBRARIES} ${MINIZ_LIBRARIES})
    target_include_directories(libIMAPlw INTERFACE ${MIMETIC_INCLUDE_DIR})
ELSE(MIMETIC_GOTTEN)
    message(STATUS "Mimetic not found")
endif(MIMETIC_GOTTEN)

