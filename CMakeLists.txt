cmake_minimum_required(VERSION 3.28)
project(aldbg)

set(CMAKE_CXX_STANDARD 20)

include_directories(.)

find_package(PkgConfig)
pkg_check_modules(GTKMM gtkmm-3.0)

include_directories(${GTKMM_INCLUDE_DIRS})
link_directories(${GTKMM_LIBRARY_DIRS})

add_executable(aldbg
        main.cpp cpu/cpu.cpp core/attach.cpp core/core.cpp log/log.cpp)

target_link_libraries(aldbg ${GTKMM_LIBRARIES})