cmake_minimum_required(VERSION 3.0)
project(use_openssl)

set(OPENSSL_ROOT_DIR "/home/zhoulei/.local/ssl/lib64/")

add_subdirectory(client)
add_subdirectory(server)
