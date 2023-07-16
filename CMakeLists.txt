cmake_minimum_required(VERSION 3.14)

# set(CMAKE_CXX_STANDARD 17)
# set(CMAKE_CXX_STANDARD_REQUIRED ON)

project(winsock2-playground)

SET(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} -static")

add_executable(${PROJECT_NAME}
    "src/main.cpp")

target_link_libraries(${PROJECT_NAME} gdi32 user32 ws2_32 secur32)