cmake_minimum_required(VERSION 3.15)
project(ToyDebugger VERSION 0.1)

set(CMAKE_C_STANDARD 99)
set(CMAKE_CXX_STANDARD 20)
set(CMAKE_BUILD_TYPE Debug)

find_package(Curses REQUIRED)

add_subdirectory(dependencies/zydis)

add_executable(ToyDebugger main.cc)
add_executable(TestProgram test_program.c)

target_compile_options(ToyDebugger PRIVATE -Wall -Werror -Wpedantic -g)

target_include_directories(ToyDebugger PRIVATE ${CURSES_INCLUDE_DIR})
target_link_libraries(ToyDebugger PRIVATE Zydis ${CURSES_LIBRARIES})
