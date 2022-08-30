cmake_minimum_required(VERSION 3.24)
project(rsasl C)

set(CMAKE_C_STANDARD 23)

add_executable(gsasl-client main.c)
target_link_libraries(gsasl-client gsasl)