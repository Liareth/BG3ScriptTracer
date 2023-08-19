cmake_minimum_required(VERSION 3.23)
project(BG3ScriptTracer VERSION 0.0.1 LANGUAGES CXX)
set(CMAKE_CXX_STANDARD 23)
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin)

include_directories(ext/bg3se/BG3Extender)
include_directories(ext/bg3se/External/glm)
add_subdirectory(ext/minhook)

add_library(BG3ScriptTracer SHARED src/Main.cpp src/Memory.cpp src/Memory.hpp src/Osiris.hpp)
target_link_libraries(BG3ScriptTracer minhook)
