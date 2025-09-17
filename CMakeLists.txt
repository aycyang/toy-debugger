cmake_minimum_required(VERSION 3.15)
project(MyDebugger VERSION 0.1)

set(CMAKE_C_STANDARD 11)
set(CMAKE_BUILD_TYPE Debug)

add_subdirectory(dependencies/zydis)

add_executable(MyDebugger tracer.c)

target_compile_options(MyDebugger PRIVATE -Wall -Wextra -Wpedantic -g)

target_link_libraries(MyDebugger PRIVATE Zydis)

