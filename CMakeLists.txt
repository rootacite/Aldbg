cmake_minimum_required(VERSION 3.28)
project(aldbg)

set(CMAKE_CXX_STANDARD 23)

include_directories(.)

add_compile_options(-Og)

find_package(PkgConfig)
pkg_check_modules(GTKMM gtkmm-4.0)

include_directories(${GTKMM_INCLUDE_DIRS})
link_directories(${GTKMM_LIBRARY_DIRS})
add_definitions(${GTKMM_CFLAGS_OTHER})

pkg_check_modules(CAPSTONE capstone)

include_directories(${CAPSTONE_INCLUDE_DIRS})
link_directories(${CAPSTONE_LIBRARY_DIRS})
add_definitions(${CAPSTONE_CFLAGS_OTHER})

pkg_check_modules(ELFPP libelf++)
include_directories(${ELFPP_INCLUDE_DIRS})
link_directories(${ELFPP_LIBRARY_DIRS})
add_definitions(${ELFPP_CFLAGS_OTHER})

add_executable(aldbg main.cpp)

target_link_libraries(aldbg ${GTKMM_LIBRARIES} ${CAPSTONE_LIBRARIES} ${ELFPP_LIBRARIES})