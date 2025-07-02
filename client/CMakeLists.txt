cmake_minimum_required(VERSION 3.22)
project(client)

find_package(OpenSSL REQUIRED)

aux_source_directory(${CMAKE_CURRENT_LIST_DIR}/ SRC)
aux_source_directory(${CMAKE_CURRENT_LIST_DIR}/../data/ SRC)
aux_source_directory(${CMAKE_CURRENT_LIST_DIR}/../common/ SRC)

add_executable(${PROJECT_NAME} ${SRC})

target_include_directories(${PROJECT_NAME} PUBLIC
        ${CMAKE_CURRENT_LIST_DIR}/../data/
        ${CMAKE_CURRENT_LIST_DIR}/../common/
        ${CMAKE_CURRENT_LIST_DIR}/
        ${OPENSSL_INCLUDE_DIR}/
)

target_compile_features(${PROJECT_NAME} PUBLIC cxx_std_11)

target_link_libraries(${PROJECT_NAME}
        /usr/lib/x86_64-linux-gnu/libprotobuf.a
        OpenSSL::Crypto
        OpenSSL::SSL
)