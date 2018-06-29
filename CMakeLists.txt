cmake_minimum_required(VERSION 3.5)

project(fa-fw-update)

set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin)
set(CMAKE_CXX_STANDARD 14)
set(CMAKE_CXX_STANDARD_REQUIRED TRUE)
set(CMAKE_CXX_EXTENSIONS OFF)

add_compile_options(-Werror -Wall -Wextra -Wno-unused-parameter -Wempty-body -Wformat-security -Winit-self -Warray-bounds -Wcast-align -fPIC)

find_package(ALSA REQUIRED)

add_executable(fa-fw-update fa-fw-update.cpp)
target_link_libraries(fa-fw-update ${ALSA_LIBRARIES})

install(TARGETS fa-fw-update
  DESTINATION bin
  COMPONENT fa-fw-update)