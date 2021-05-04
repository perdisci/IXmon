cmake_minimum_required (VERSION 2.8)

# cmake versions:
# Debian 6 - 2.8.2
# Debian 7 - 2.8.9
# CentOS 6 - 2.8.12

# set(ENABLE_GOBGP_SUPPORT "yes")


# XXX(Roberto): Added flag for enabling C++11
set (CMAKE_CXX_STANDARD 11)

# We should set compiler before project() call 
if (ENABLE_BUILD_IN_CPP_11_CUSTOM_ENVIRONMENT)
    # We use custom compiler too
    set(CMAKE_C_COMPILER "/opt/gcc520/bin/gcc")
    set(CMAKE_CXX_COMPILER "/opt/gcc520/bin/g++")
    set (CMAKE_CXX_STANDARD 11)
endif()

project(FastNetMon)

# Unfortunately, Debian Squeeze haven't support for this feature
# It added in 2.8.5 release: http://www.cmake.org/cmake/help/v2.8.5/cmake.html
# Get convinient paths for all system folders: http://www.cmake.org/gitweb?p=cmake.git;a=commitdiff;h=a262fe09
# include(GNUInstallDirs)

# Enable it and fix all warnigns!
# add_definitions ("-Wall")

set (FASTNETMON_VERSION_MAJOR 1)
set (FASTNETMON_VERSION_MINOR 1)

set(CMAKE_INSTALL_SYSTEMD_SERVICEDIR "/lib/systemd/system"
  CACHE PATH "Location for systemd service files")

set(CMAKE_CXX_FLAGS_DEBUG "${CMAKE_CXX_FLAGS_DEBUG} -std=c++11")
set(CMAKE_CXX_FLAGS_RELEASE "${CMAKE_CXX_FLAGS_RELEASE} -std=c++11")

set(BOOST_INCLUDEDIR "/opt/boost_1_58_0")
set(BOOST_LIBRARYDIR "/opt/boost_1_58_0/stage/lib")

# cmake -DENABLE_BUILD_IN_CPP_11_CUSTOM_ENVIRONMENT=ON .. 
if (ENABLE_BUILD_IN_CPP_11_CUSTOM_ENVIRONMENT)
    set(BOOST_INCLUDEDIR "/opt/boost_1_58_0")
    set(BOOST_LIBRARYDIR "/opt/boost_1_58_0/stage/lib/")

    # It's really nice part of this custom build process :)
    set(CMAKE_CXX_FLAGS_RELEASE "${CMAKE_CXX_FLAGS_RELEASE} -std=c++11")
    set(CMAKE_CXX_FLAGS_DEBUG "${CMAKE_CXX_FLAGS_DEBUG} -std=c++11")

    # Disable warning from Boost when compiling with gcc 5.2
    set(CMAKE_CXX_FLAGS_RELEASE "${CMAKE_CXX_FLAGS_RELEASE} -Wno-deprecated-declarations")

    set(CMAKE_INSTALL_RPATH "${CMAKE_INSTALL_RPATH};/opt/gcc520/lib64;/opt/boost_1_58_0/stage/lib")
endif()
 
# Specify full RPATH for build tree
SET(CMAKE_SKIP_BUILD_RPATH  FALSE)

# Create builds in current folder with install RPATH
SET(CMAKE_BUILD_WITH_INSTALL_RPATH TRUE)

# /opt/libgobgp_1_0_0/lib should be mentioned here explicitly!!!! We link it in runtime
SET(CMAKE_INSTALL_RPATH "${CMAKE_INSTALL_RPATH};/opt/libhiredis_0_13/lib;/opt/log4cpp1.1.1/lib;/opt/luajit_2.0.4/lib;/opt/ndpi/lib;/opt/pf_ring_6.0.3/lib;/opt/json-c-0.12/lib;/opt/mongo_c_driver_1_1_9/lib;/opt/libgobgp_1_0_0/lib;/opt/grpc_0_11_1_7a94236d698477636dd06282f12f706cad527029/lib;/opt/protobuf_3.0.0_alpha4/lib")

message(STATUS "C++ compilation flags: ${CMAKE_CXX_FLAGS_RELEASE}")

set(HIREDIS_CUSTOM_INSTALL_PATH "/opt/libhiredis_0_13")
set(LOG4CPP_CUSTOM_INSTALL_PATH "/opt/log4cpp1.1.1")
set(JSONC_CUSTOM_INSTALL_PATH "/opt/json-c-0.12")
set(PFRING_CUSTOM_INSTALL_PATH "/opt/pf_ring_6.0.3")
set(LIBPCAP_CUSTOM_INSTALL_PATH "/opt/libpcap_1.7.4")
set(MONGO_C_CUSTOM_INSTALL_PATH "/opt/mongo_c_driver_1_1_9")

set(FASTNETMON_PROFILER OFF)

set(FASTNETMON_PROFILE_FLAGS "-g -pg")

if (NOT CMAKE_BUILD_TYPE) 
    message(STATUS "Setting build type to Release as none was specified.")
    set(CMAKE_BUILD_TYPE Release)
endif()

if (FASTNETMON_PROFILER) 
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} ${FASTNETMON_PROFILE_FLAGS}")
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} ${FASTNETMON_PROFILE_FLAGS}")
    set(CMAKE_EXE_LINKER_FLAGS  "${CMAKE_EXE_LINKER_FLAGS} ${FASTNETMON_PROFILE_FLAGS}")
endif()

execute_process(COMMAND sh -c ". /etc/os-release; echo $ID" OUTPUT_VARIABLE OS_ID ERROR_QUIET)

### Executables definition 

# Main tool
add_executable(ixmon ixmon.cpp)

# Get last commit hash
execute_process(COMMAND git rev-list HEAD COMMAND head -n 1 OUTPUT_VARIABLE GIT_LAST_COMMIT_HASH OUTPUT_STRIP_TRAILING_WHITESPACE)

set(IXMON_APPLICATION_VERSION "0.1 roberto git-${GIT_LAST_COMMIT_HASH}")
configure_file(fast_platform.h.template "${PROJECT_SOURCE_DIR}/fast_platform.h")

# Our LPM library
add_library(patricia STATIC libpatricia/patricia.c)

# NOTE(Roberto): added to allow for fast IP-to-ASN lookups
add_library(patricia_ip_asn STATIC libpatricia/patricia_ip_asn.cpp)

add_library(fastnetmon_pcap_format STATIC fastnetmon_pcap_format.cpp)

# Our tools library
add_library(fast_library STATIC fast_library.cpp)

# Our parser
add_library(unified_parser STATIC unified_parser.cpp)
target_link_libraries(unified_parser fastnetmon_packet_parser)

# Our ipfix database library
add_library(ipfix_rfc STATIC ipfix_rfc.cpp)

# Our packet parser
add_library(fastnetmon_packet_parser STATIC fastnetmon_packet_parser.c)

if (${CMAKE_SYSTEM_NAME} STREQUAL "Linux")
    execute_process(COMMAND uname -r OUTPUT_VARIABLE LINUX_KERNEL_VERSION OUTPUT_STRIP_TRAILING_WHITESPACE)
    
    # Extract major version number from Linux Kernel Version
    string(REGEX MATCH "^[0-9]+\\.[0-9]+" KERNEL_VERSION_MATCHES ${LINUX_KERNEL_VERSION})
endif()

# sFLOW plugin
add_library(sflow_plugin STATIC sflow_plugin/sflow_collector.cpp) 

# netflow plugin
add_library(netflow_plugin STATIC netflow_plugin/netflow_collector.cpp)
target_link_libraries(netflow_plugin ipfix_rfc)

# pcap plugin
add_library(pcap_plugin STATIC pcap_plugin/pcap_collector.cpp)
target_link_libraries(pcap_plugin pcap)

find_package(Threads)

if (ENABLE_PFRING_SUPPORT) 
    add_library(pfring_plugin STATIC pfring_plugin/pfring_collector.cpp)
    target_link_libraries(pfring_plugin ${PFRING_LIBRARIES})
    target_link_libraries(pfring_plugin numa)
    target_link_libraries(pfring_plugin ${CMAKE_THREAD_LIBS_INIT})

    # Add action for hardware filetring
    add_library(pfring_hardware_filter_action STATIC actions/pfring_hardware_filter_action.cpp)
endif()

if (ENABLE_GOBGP_SUPPORT)
    set(GOBGP_CUSTOM_INSTALL_PATH "/opt/libgobgp_1_0_0")
    set(GRPC_CUSTOM_INSTALL_PATH "/opt/grpc_0_11_1_7a94236d698477636dd06282f12f706cad527029")
    set(PROTOCOL_BUFFERS_CUSTOM_INSTALL_PATH "/opt/protobuf_3.0.0_alpha4")

    add_definitions(-DENABLE_GOBGP)
    add_library(gobgp_action STATIC actions/gobgp_action.cpp)

    find_path(GOBGP_INCLUDES_FOLDER NAMES libgobgp.h PATHS "${GOBGP_CUSTOM_INSTALL_PATH}/include" NO_DEFAULT_PATH)
    find_library(GOBGP_LIBRARY_PATH NAMES gobgp PATHS "${GOBGP_CUSTOM_INSTALL_PATH}/lib" NO_DEFAULT_PATH)

    if (GOBGP_INCLUDES_FOLDER AND GOBGP_LIBRARY_PATH)
        message(STATUS "We found libgobgp and will link it: ${GOBGP_INCLUDES_FOLDER} ${GOBGP_LIBRARY_PATH}")
    
        ### We do not link with it in compilation time because it broke daemonization code and pope
        ### So we use runtime dynamic linking
        ### target_link_libraries(gobgp_action ${GOBGP_LIBRARY_PATH})
        target_link_libraries(gobgp_action dl)
        include_directories(${GOBGP_INCLUDES_FOLDER})
    else()
        message(FATAL_ERROR "Could not find libgobgp")
    endif()

    find_path(GRPC_INCLUDES_FOLDER NAMES grpc/grpc.h PATHS "${GRPC_CUSTOM_INSTALL_PATH}/include" NO_DEFAULT_PATH)
    find_library(GRPC_LIBRARY_GRPC_PATH NAMES grpc PATHS "${GRPC_CUSTOM_INSTALL_PATH}/lib" NO_DEFAULT_PATH)
    find_library(GRPC_LIBRARY_GPR_PATH NAMES gpr PATHS "${GRPC_CUSTOM_INSTALL_PATH}/lib" NO_DEFAULT_PATH)
    find_library(GRPC_LIBRARY_GRPC_CPP_UNSECURE_PATH NAMES grpc++_unsecure PATHS "${GRPC_CUSTOM_INSTALL_PATH}/lib" NO_DEFAULT_PATH) 

    if (GRPC_INCLUDES_FOLDER AND GRPC_LIBRARY_GRPC_PATH AND GRPC_LIBRARY_GPR_PATH AND GRPC_LIBRARY_GRPC_CPP_UNSECURE_PATH)
        include_directories(${GRPC_INCLUDES_FOLDER})
        target_link_libraries(gobgp_action ${GRPC_LIBRARY_GRPC_PATH})
        target_link_libraries(gobgp_action ${GRPC_LIBRARY_GPR_PATH})
        target_link_libraries(gobgp_action ${GRPC_LIBRARY_GRPC_CPP_UNSECURE_PATH})
    else()
        message(FATAL_ERROR "Could not find gRPC library")
    endif()

    find_path(PROTOCOL_BUFFERS_INCLUDE_FOLDER NAMES "google/protobuf/stubs/common.h" PATHS "${PROTOCOL_BUFFERS_CUSTOM_INSTALL_PATH}/include")

    find_library(PROTOCOL_BUFFERS_LIBRARY_PATH NAMES protobuf PATHS "${PROTOCOL_BUFFERS_CUSTOM_INSTALL_PATH}/lib") 

    if (PROTOCOL_BUFFERS_INCLUDE_FOLDER AND PROTOCOL_BUFFERS_LIBRARY_PATH)
        include_directories(${PROTOCOL_BUFFERS_INCLUDE_FOLDER}) 
        target_link_libraries(gobgp_action ${PROTOCOL_BUFFERS_LIBRARY_PATH}) 
    else()
        message(FATAL_ERROR "Could not find protocol buffers")
    endif()


    # message(STATUS "grpc: ${GRPC_INCLUDES_FOLDER} ${GRPC_LIBRARY_GRPC_PATH} ${GRPC_LIBRARY_GPR_PATH}")
    # message(STATUS ${PROJECT_BINARY_DIR})

    find_program(PROTOC_BINARY protoc PATHS "${PROTOCOL_BUFFERS_CUSTOM_INSTALL_PATH}/bin" NO_DEFAULT_PATH)

    if (PROTOC_BINARY)
        message(STATUS "Found protoc protobuf compiler: ${PROTOC_BINARY}")
    else()
        message(FATAL_ERROR "Can't find protoc compiler")
    endif()

    set(GRPC_CPP_PLUGIN "${GRPC_CUSTOM_INSTALL_PATH}/bin/grpc_cpp_plugin")

    execute_process(COMMAND ${PROTOC_BINARY} -I ${PROJECT_BINARY_DIR}/../actions --grpc_out=${PROJECT_BINARY_DIR}/../actions --plugin=protoc-gen-grpc=${GRPC_CPP_PLUGIN} ${PROJECT_BINARY_DIR}/../actions/gobgp_api_client.proto ERROR_VARIABLE PROTOC_STDERR RESULT_VARIABLE PROTOC_RETURN_CODE OUTPUT_STRIP_TRAILING_WHITESPACE)

    message(STATUS "Protoc return code: ${PROTOC_RETURN_CODE} std err: ${PROTOC_STDERR}")

    execute_process(COMMAND ${PROTOC_BINARY} -I  ${PROJECT_BINARY_DIR}/../actions --cpp_out=${PROJECT_BINARY_DIR}/../actions ${PROJECT_BINARY_DIR}/../actions/gobgp_api_client.proto ERROR_VARIABLE PROTOC_STDERR RESULT_VARIABLE PROTOC_RETURN_CODE OUTPUT_STRIP_TRAILING_WHITESPACE)

    message(STATUS "Protoc return code: ${PROTOC_RETURN_CODE} std err: ${PROTOC_STDERR}")

    # Build gRPC and protocol bufffers libraries and link they to gobgp_action
    add_library(gobgp_api_client_pb_cc STATIC actions/gobgp_api_client.pb.cc)
    add_library(gobgp_api_client_grpc_pb_cc STATIC actions/gobgp_api_client.grpc.pb.cc)

    target_link_libraries(gobgp_action gobgp_api_client_pb_cc)
    target_link_libraries(gobgp_action gobgp_api_client_grpc_pb_cc)

    # FastNetMon API
    add_definitions(-DFASTNETMON_API)    

    execute_process(COMMAND ${PROTOC_BINARY} -I ${PROJECT_BINARY_DIR}/.. --grpc_out=${PROJECT_BINARY_DIR}/.. --plugin=protoc-gen-grpc=${GRPC_CPP_PLUGIN} ${PROJECT_BINARY_DIR}/../fastnetmon.proto ERROR_VARIABLE PROTOC_STDERR RESULT_VARIABLE PROTOC_RETURN_CODE OUTPUT_STRIP_TRAILING_WHITESPACE)

    message(STATUS "Protoc return code: ${PROTOC_RETURN_CODE} std err: ${PROTOC_STDERR}")

    execute_process(COMMAND ${PROTOC_BINARY} -I  ${PROJECT_BINARY_DIR}/.. --cpp_out=${PROJECT_BINARY_DIR}/.. ${PROJECT_BINARY_DIR}/../fastnetmon.proto ERROR_VARIABLE PROTOC_STDERR RESULT_VARIABLE PROTOC_RETURN_CODE OUTPUT_STRIP_TRAILING_WHITESPACE) 

    message(STATUS "Protoc return code: ${PROTOC_RETURN_CODE} std err: ${PROTOC_STDERR}")

    add_library(fastnetmon_grpc_pb_cc STATIC fastnetmon.grpc.pb.cc)
    add_library(fastnetmon_pb_cc STATIC fastnetmon.pb.cc)

    add_executable(fastnetmon_api_client fastnetmon_api_client.cpp)

    target_link_libraries(fastnetmon_api_client ${GRPC_LIBRARY_GPR_PATH})
    target_link_libraries(fastnetmon_api_client ${GRPC_LIBRARY_GRPC_CPP_UNSECURE_PATH})
    target_link_libraries(fastnetmon_api_client ${GRPC_LIBRARY_GRPC_PATH})
    target_link_libraries(fastnetmon_api_client fastnetmon_grpc_pb_cc)
    target_link_libraries(fastnetmon_api_client fastnetmon_pb_cc)
    target_link_libraries(fastnetmon_api_client ${PROTOCOL_BUFFERS_LIBRARY_PATH}) 

    target_link_libraries(ixmon ${GRPC_LIBRARY_GPR_PATH})
    target_link_libraries(ixmon ${GRPC_LIBRARY_GRPC_CPP_UNSECURE_PATH})
    target_link_libraries(ixmon ${GRPC_LIBRARY_GRPC_PATH})
    target_link_libraries(ixmon fastnetmon_grpc_pb_cc)
    target_link_libraries(ixmon fastnetmon_pb_cc)
    target_link_libraries(ixmon ${PROTOCOL_BUFFERS_LIBRARY_PATH}) 
endif()

# example plugin
# add_library(example_plugin STATIC example_plugin/example_collector.cpp)

# Client tool
add_executable(ixmon_client ixmon_client.cpp)

# Find boost: http://www.cmake.org/cmake/help/v3.0/module/FindBoost.html

# Enable detailed errors
set(Boost_DETAILED_FAILURE_MSG ON)

# find_package(Boost COMPONENTS thread regex program_options system REQUIRED)

# if(Boost_FOUND)
#     include_directories(${Boost_INCLUDE_DIRS})
#     target_link_libraries(ixmon ${Boost_LIBRARIES})
#     target_link_libraries(fast_library ${Boost_LIBRARIES})
# endif()

# Adding Boost libraries manually because find_package(Boost) failed
target_link_libraries(ixmon /opt/boost_1_58_0/stage/lib/libboost_thread.so /opt/boost_1_58_0/stage/lib/libboost_system.so /opt/boost_1_58_0/stage/lib/libboost_program_options.so /opt/boost_1_58_0/stage/lib/libboost_regex.so)
target_link_libraries(fast_library /opt/boost_1_58_0/stage/lib/libboost_thread.so)
#####

target_link_libraries(fast_library patricia)
target_link_libraries(fast_library fastnetmon_pcap_format)

# Try to find ncurses librreary
find_package(Curses REQUIRED)

if(CURSES_FOUND) 
    include_directories(${CURSES_INCLUDE_DIRS})
    target_link_libraries(ixmon_client ${CURSES_LIBRARIES})
endif()

### Look for libpcap

#find_path(LIBPCAP_INCLUDES_FOLDER NAMES pcap.h PATHS "${LIBPCAP_CUSTOM_INSTALL_PATH}/include" NO_DEFAULT_PATH)

#find_library(LIBPCAP_LIBRARY_PATH NAMES pcap PATHS "${LIBPCAP_CUSTOM_INSTALL_PATH}/lib" NO_DEFAULT_PATH)

#if (LIBPCAP_INCLUDES_FOLDER AND LIBPCAP_LIBRARY_PATH) 
#    message(STATUS "We found pcap library ${LIBPCAP_LIBRARY_PATH}")

#    include_directories(${LIBPCAP_INCLUDES_FOLDER})
#else()
#    message(FATAL_ERROR "We can't find pcap library")    
#endif()

### Look for log4cpp

# Try to find log4cpp includes path
find_path(LOG4CPP_INCLUDES_FOLDER NAMES log4cpp/Appender.hh PATHS "${LOG4CPP_CUSTOM_INSTALL_PATH}/include" NO_DEFAULT_PATH)

# Try to find log4cpp library path
find_library(LOG4CPP_LIBRARY_PATH NAMES log4cpp PATHS "${LOG4CPP_CUSTOM_INSTALL_PATH}/lib" NO_DEFAULT_PATH)

if (LOG4CPP_INCLUDES_FOLDER AND LOG4CPP_LIBRARY_PATH)
    include_directories(${LOG4CPP_INCLUDES_FOLDER})
    message(STATUS "We have found log4cpp and will build project")
else()
    message(FATAL_ERROR "We can't find log4cpp. We can't build project")
endif()

### Look for jsonc

find_path(JSONC_INCLUDES_FOLDER NAMES json-c/json.h PATHS "${JSONC_CUSTOM_INSTALL_PATH}/include" NO_DEFAULT_PATH)
find_library(JSONC_LIBRARY_PATH NAMES json-c PATHS "${JSONC_CUSTOM_INSTALL_PATH}/lib" NO_DEFAULT_PATH)

if (JSONC_INCLUDES_FOLDER AND JSONC_LIBRARY_PATH)
    include_directories(${JSONC_INCLUDES_FOLDER}) 
    message(STATUS "We have found json-c library correctly: ${JSONC_LIBRARY_PATH}")
else()
    message(FATAL_ERROR "We can't find json-c library! Can't build project")
endif()

target_link_libraries(fast_library ${JSONC_LIBRARY_PATH})

if (ENABLE_DPI_SUPPORT)
    target_link_libraries(ixmon fast_dpi)
endif()

target_link_libraries(ixmon ${LOG4CPP_LIBRARY_PATH})

target_link_libraries(ixmon ${CMAKE_THREAD_LIBS_INIT})

# Our libs
target_link_libraries(ixmon patricia)
target_link_libraries(ixmon fastnetmon_pcap_format)

# NOTE(Roberto): needed for IP-to-ASN tree
target_link_libraries(ixmon patricia_ip_asn)

target_link_libraries(ixmon ipfix_rfc)

# Link to our functions
target_link_libraries(ixmon fast_library)

# link to our unified parser
target_link_libraries(ixmon unified_parser)

# target_link_libraries(ixmon sflow_plugin netflow_plugin pcap_plugin example_plugin)
target_link_libraries(ixmon sflow_plugin netflow_plugin pcap_plugin)

# cmake .. -DBUILD_PLUGIN_RUNNER=ON
if (BUILD_PLUGIN_RUNNER)
    add_executable(fastnetmon_plugin_runner plugin_runner.cpp)

#     if (ENABLE_SNABBSWITCH_SUPPORT) 
#         target_link_libraries(fastnetmon_plugin_runner snabbswitch_plugin)
#     endif()
# 
#     if (ENABLE_AFPACKET_SUPPORT) 
#         target_link_libraries(fastnetmon_plugin_runner afpacket_plugin)
#     endif()

    target_link_libraries(fastnetmon_plugin_runner ${CMAKE_THREAD_LIBS_INIT})
    target_link_libraries(fastnetmon_plugin_runner patricia)
    target_link_libraries(fastnetmon_plugin_runner fastnetmon_pcap_format)
    target_link_libraries(fastnetmon_plugin_runner ${LOG4CPP_LIBRARY_PATH})
    target_link_libraries(fastnetmon_plugin_runner fast_library)

    # Add all plugins
#     target_link_libraries(fastnetmon_plugin_runner sflow_plugin netflow_plugin pcap_plugin example_plugin)
    target_link_libraries(fastnetmon_plugin_runner sflow_plugin netflow_plugin pcap_plugin)

    if (ENABLE_PFRING_SUPPORT)
        target_link_libraries(fastnetmon_plugin_runner ${PFRING_LIBRARIES})
        target_link_libraries(fastnetmon_plugin_runner pfring_plugin)
    endif()
endif()

# cmake .. -DBUILD_PCAP_READER=ON
if (BUILD_PCAP_READER)
    add_executable(fastnetmon_pcap_reader pcap_reader.cpp)

    target_link_libraries(fastnetmon_pcap_reader fastnetmon_packet_parser)
    target_link_libraries(fastnetmon_pcap_reader patricia)
    target_link_libraries(fastnetmon_pcap_reader fastnetmon_pcap_format)
    target_link_libraries(fastnetmon_pcap_reader unified_parser)

    target_link_libraries(fastnetmon_pcap_reader fast_library)
    target_link_libraries(fastnetmon_pcap_reader ${LOG4CPP_LIBRARY_PATH})
    target_link_libraries(fastnetmon_pcap_reader netflow_plugin)   
    target_link_libraries(fastnetmon_pcap_reader sflow_plugin)

    if (ENABLE_DPI_SUPPORT)
        target_link_libraries(fastnetmon_pcap_reader fast_dpi)
    endif()
endif()

# cmake -DBUILD_TESTS=ON ..
if (BUILD_TESTS) 
    add_executable(fastnetmon_tests fastnetmon_tests.cpp)
    target_link_libraries(fastnetmon_tests fast_library)
    target_link_libraries(fastnetmon_tests ${CMAKE_THREAD_LIBS_INIT})
    target_link_libraries(fastnetmon_tests ${Boost_LIBRARIES})
    target_link_libraries(fastnetmon_tests ${LOG4CPP_LIBRARY_PATH})

    set(GOOGLE_TEST_INCLUDE_DIRS /opt/gtest/include)
    set(GOOGLE_TEST_LIBRARIES /opt/gtest/lib/libgtest.a /opt/gtest/lib/libgtest_main.a)

    # Compiled Google Library
    include_directories(${GOOGLE_TEST_INCLUDE_DIRS})
    target_link_libraries(fastnetmon_tests ${GOOGLE_TEST_LIBRARIES})
endif()

if (${CMAKE_SYSTEM_NAME} STREQUAL "FreeBSD" OR ${CMAKE_SYSTEM_NAME} STREQUAL "DragonFly")
    set(CMAKE_INSTALL_BINDIR "bin")
    set(CMAKE_INSTALL_SBINDIR "bin")
    set(CMAKE_INSTALL_SYSCONFDIR "etc")
else()
    set(CMAKE_INSTALL_BINDIR "/usr/bin")
    set(CMAKE_INSTALL_SBINDIR "/usr/sbin")
    set(CMAKE_INSTALL_SYSCONFDIR "/etc")
endif()

install(TARGETS ixmon DESTINATION "${CMAKE_INSTALL_SBINDIR}")
install(TARGETS ixmon_client DESTINATION "${CMAKE_INSTALL_BINDIR}")

install(FILES ixmon.conf DESTINATION "${CMAKE_INSTALL_SYSCONFDIR}")

# Install blank files for networks list and whitelist
install(FILES networks_list DESTINATION "${CMAKE_INSTALL_SYSCONFDIR}")
install(FILES networks_whitelist DESTINATION "${CMAKE_INSTALL_SYSCONFDIR}")

# man pages
install(FILES man/fastnetmon.1 DESTINATION /usr/share/man/man1)
install(FILES man/fastnetmon_client.1 DESTINATION /usr/share/man/man1)

# service files
# configure_file(fastnetmon.service.in "${CMAKE_CURRENT_BINARY_DIR}/fastnetmon.service" @ONLY)
# install(FILES "${CMAKE_CURRENT_BINARY_DIR}/fastnetmon.service" DESTINATION ${CMAKE_INSTALL_SYSTEMD_SERVICEDIR})

if (${OS_ID} MATCHES debian|ubuntu)
install(FILES fastnetmon_init_script_debian_6_7 DESTINATION ${CMAKE_INSTALL_SYSCONFDIR}/init.d RENAME fastnetmon)
endif()

# Configure cpack package builder
# Run it with: cd build; cpack -G DEB ..
# set(CPACK_PACKAGE_NAME "fastnetmon")
# set(CPACK_PACKAGE_VENDOR "vps2fast.com")
# set(CPACK_PACKAGE_CONTACT "pavel.odintsov@gmail.com")
# set(CPACK_PACKAGE_DESCRIPTION_SUMMARY "FastNetMon - very fast DDoS analyzer with sflow/netflow/mirror support")
# set(CPACK_PACKAGE_VERSION "1.1.2")
# set(CPACK_PACKAGE_VERSION_MAJOR "1")
# set(CPACK_PACKAGE_VERSION_MINOR "1")
# set(CPACK_PACKAGE_VERSION_PATCH "2")
# set(CPACK_DEBIAN_PACKAGE_DEPENDS "")
# set(CPACK_PACKAGE_INSTALL_DIRECTORY "CPack Component Example")

# Specify config for deb package
# http://www.cmake.org/Wiki/CMake:CPackPackageGenerators#DEB_.28UNIX_only.29
# set(CPACK_DEBIAN_PACKAGE_DEPENDS "libboost-thread-dev, libboost-system-dev, libboost-regex-dev, libpcap-dev, libnuma-dev, liblog4cpp5-dev")

# This must always be last!
# include(CPack)
