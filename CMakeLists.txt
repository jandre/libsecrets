CMAKE_MINIMUM_REQUIRED(VERSION 2.8 FATAL_ERROR)
project(libsecrets)
set(CMAKE_MODULE_PATH ${PROJECT_SOURCE_DIR}/cmake)

find_package(KeyUtils)
find_package(MCrypt)
add_subdirectory(src)

