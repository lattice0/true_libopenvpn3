cmake_minimum_required(VERSION 3.5)
project(libopenvpn)
#TODO: take it off
add_compile_options(-Wno-unused-variable)

#OpenVPN definitiions
set(CMAKE_MODULE_PATH "${CMAKE_CURRENT_SOURCE_DIR}/openvpn3/cmake;${CMAKE_MODULE_PATH}")
#include(../openvpn3/openvpn3/cmake/findcoredeps)
set(KOVPN_SOURCE "${CORE_DIR}/../kovpn" CACHE PATH "ovpn-dco kernel module source tree")

#------------libtins----------------
option(LIBTINS_ENABLE_DOT11 OFF)
option(LIBTINS_ENABLE_WPA2 OFF)
set(LIBTINS_ENABLE_DOT11 OFF)
set(LIBTINS_ENABLE_WPA2 OFF)
set(LIBTINS_BUILD_SHARED OFF CACHE BOOL "enable X functionality" FORCE)
set(LIBTINS_ENABLE_PCAP OFF CACHE BOOL "enable X functionality" FORCE)
set(OPENVPN3OSSL ON)
set(PCAP_INCLUDE_DIR "")
set(PCAP_LIBRARY "")
add_subdirectory(libtins)
#-----------------------------------
if (DEFINED ANDROID_ABI)
    add_subdirectory(proton_android_app/openvpn/src/main/cpp)
else()
    add_subdirectory(openvpn3)
endif()

#todo: delete OpenVpnClient.cpp but NOT .h
add_library(libopenvpn3 STATIC OpenVpnInstance.cpp)
target_compile_definitions(libopenvpn3 PRIVATE
      -DHAVE_CONFIG_H
      -DHAVE_LZO
      -DHAVE_LZ4
      -DASIO_STANDALONE
      -DUSE_ASIO
      -DGIT_VERSION_STRING=\"${OPENVPN3_GIT}\"
      -DNO_ROUTE_EXCLUDE_EMULATION
      -DOPENVPN_SHOW_SESSION_TOKEN
      )

if (DEFINED ANDROID_ABI)
    set(OPENVPN3_DIR ${CMAKE_CURRENT_SOURCE_DIR}/proton_android_app/openvpn/src/main/cpp)
    target_include_directories(libopenvpn3 PUBLIC 
    ${OPENVPN3_DIR}/openvpn3/ ${CMAKE_CURRENT_SOURCE_DIR}/libtins/include
    ${CMAKE_CURRENT_SOURCE_DIR}/proton_android_app/openvpn/src/main/cpp/openssl/include/)

    add_dependencies(libopenvpn3 openvpn crypto lzo lz4 tins)
else()
    set(OPENVPN3_DIR ${CMAKE_CURRENT_SOURCE_DIR}/openvpn3)
    target_include_directories(libopenvpn3 PUBLIC 
    ${OPENVPN3_DIR} ${CMAKE_CURRENT_SOURCE_DIR}/libtins/include)

    add_dependencies(libopenvpn3 tins)
endif()
#target_link_libraries(libopenvpn3 openvpn crypto lzo lz4 tins)

target_include_directories(libopenvpn3 PUBLIC
    ${OPENVPN3_DIR}
    ${OPENVPN3_DIR}/lzo/include
    ${OPENVPN3_DIR}/lz4/lib
    ${OPENVPN3_DIR}/asio/asio/include
    ${OPENVPN3_DIR}/openvpn3
    ${OPENVPN3_DIR}/mbdetls/include
)

if (${OPENVPN3OSSL})
    target_compile_definitions(libopenvpn3 PRIVATE -DUSE_OPENSSL)
    #took off pthread from openvpn_lib
    if (${ANDROID_ABI})
        add_dependencies(libopenvpn3 ssl)
        target_link_libraries(libopenvpn3 crypto ssl lzo lz4 tins)
    else()
        find_library(SSL_LIB
            NAMES ssl openssl
        )
        #add_dependencies(libopenvpn3 openssl)
        target_link_libraries(libopenvpn3 tins SSL_LIB)
    endif()
else()
    #TODO: untested
    add_dependencies(libopenvpn3 mbedtls)
    target_compile_definitions(ovpn3 PRIVATE -DUSE_MBEDTLS)
    target_link_libraries(libopenvpn3 mbedtls mbedx509 mbedcrypto pthread lzo lz4 tins)
endif()

set_property(TARGET libopenvpn3 PROPERTY CXX_STANDARD 17)

if (DEFINED ANDROID_ABI)
    install(TARGETS libopenvpn3 crypto ssl lzo lz4 tins DESTINATION .)
else()
    install(TARGETS libopenvpn3 tins DESTINATION .)
endif()