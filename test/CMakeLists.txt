cmake_minimum_required(VERSION 3.14) # Проверка версии CMake.
# Если версия установленной программы
# старее указаной, произойдёт аварийный выход.


include(FindPkgConfig)
set(CMAKE_FIND_FRAMEWORK LAST)

#-----------------------------------------------------------------------
project(test)
set(TARGET_EXE ${PROJECT_NAME})
message("Cmake pro: " ${TARGET_EXE})

#set(CMAKE_BINARY_DIR ${CMAKE_CURRENT_SOURCE_DIR}/build)


# Specify the configuration file from which the header file will be generated
#configure_file (config.h.in ${CMAKE_CURRENT_SOURCE_DIR}/config.h @ONLY)

pkg_search_module(FUSE_LIB REQUIRED fuse3)

#libxcb-randr0-dev
# list(APPEND CMAKE_MODULE_PATH ${CMAKE_CURRENT_SOURCE_DIR}/cmake)
# message(${CMAKE_MODULE_PATH})

set (HPP_INCLUDES_DIR ../)
set (CPP_SOURCES ${TARGET_EXE}.c
)

#сначала add_executable
add_executable(${TARGET_EXE} ${CPP_SOURCES}) # Исполняемый файл

#затем опции
target_compile_options(${TARGET_EXE} PRIVATE
            ${FUSE_LIB_CFLAGS}
)

target_include_directories(${TARGET_EXE} PRIVATE ${HPP_INCLUDES_DIR})

target_link_libraries(${TARGET_EXE} 
${FUSE_LIB_LIBRARIES}
pthread
)
#-----------------------------------------------------------------------

