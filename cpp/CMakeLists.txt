cmake_minimum_required(VERSION 3.10.2)
project("native_proxy")

add_library(
        native_proxy
        SHARED
        native_proxy.cpp
)

find_library(
        log-lib
        log
)

target_link_libraries(
        native_proxy
        ${log-lib}
)
