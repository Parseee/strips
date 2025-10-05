cmake_minimum_required(VERSION 3.21)
project(striptizz C)

set(CMAKE_CXX_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)

# add elfutils
# Manually specify elfutils include directory
find_path(ELFUTILS_INCLUDE_DIR NAMES libelf.h PATHS /usr/include /usr/local/include)
if(NOT ELFUTILS_INCLUDE_DIR)
    message(FATAL_ERROR "elfutils include directory not found!")
endif()

# Manually specify elfutils library directory
find_library(ELFUTILS_LIBRARY NAMES elf PATHS /usr/lib /usr/local/lib)
if(NOT ELFUTILS_LIBRARY)
    message(FATAL_ERROR "elfutils library not found!")
endif()

# Source files
set(SOURCES
    src/strips.c
    src/strips.h
    lib_strips.h
    )

# Create library
add_library(${PROJECT_NAME} ${SOURCES})
target_include_directories(${PROJECT_NAME} 
            PRIVATE ${ELFUTILS_INCLUDE_DIR})
target_link_libraries(${PROJECT_NAME}
            PUBLIC project_compiler_options
            PRIVATE ${ELFUTILS_LIBRARY})