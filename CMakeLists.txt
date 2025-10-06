cmake_minimum_required(VERSION 3.21)
project(strips C)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

add_library(project_compiler_options INTERFACE)
target_compile_options(project_compiler_options INTERFACE
    $<$<CONFIG:Debug>:-Wall -Wextra -fno-omit-frame-pointer>
    $<$<CONFIG:Release>:-O2>
)

include_directories(src libs)

add_subdirectory(libs/strips)

set(MAIN_SOURCES 
    src/main.c)

set(DEPS
    striptizz)
    
add_executable(${PROJECT_NAME} ${MAIN_SOURCES})
# add target_link_options
target_link_libraries(${PROJECT_NAME} PUBLIC project_compiler_options 
    $<$<CONFIG:Debug>:>  
    $<$<CONFIG:Release>:-O2>
    ${DEPS})
