cmake_minimum_required(VERSION 2.6)

project(ecryptfs-simple)
set (VERSION_MAJOR "2016.11.14")

find_package(PkgConfig)

include (CheckLibraryExists)
include (GNUInstallDirs)

include_directories ("${PROJECT_SOURCE_DIR}/src")

set(SRC src/ecryptfs-simple.c)
add_definitions (-Wextra -Wall -pedantic -std=gnu99)
add_definitions (-D_DEFAULT_SOURCE -fstack-protector-all --param ssp-buffer-size=4)

option (WITH_DEBUG_MESSAGES "Enable debugging messages" OFF)
if (WITH_DEBUG_MESSAGES)
  add_definitions (
        -DDEBUG=1
        -finstrument-functions
        -finstrument-functions-exclude-file-list=include
        -finstrument-functions-exclude-function-list=main,fprintf,__cyg_profile_func_enter,__cyg_profile_func_exit
  )
endif ()

function (check_found variable name)
  if (NOT variable)
    message (FATAL_ERROR "could not find ${name}")
  else ()
    message (STATUS "found ${name}: ${variable}")
  endif ()
endfunction()

find_file (GCRYPT_HEADER gcrypt.h)
check_found ("${GCRYPT_HEADER}" "gcrypt header")

find_library (GCRYPT_LIB gcrypt)
check_found ("${GCRYPT_LIB}" "gcrypt lib")

find_library (ECRYPTFS_LIB ecryptfs)
check_found ("${ECRYPTFS_LIB}" "ecryptfs lib")

add_executable (ecryptfs-simple ${SRC})
target_link_libraries (
  ecryptfs-simple
  "${GCRYPT_LIB}"
  "${ECRYPTFS_LIB}"
  -lmount
  -lkeyutils
)

install (
  TARGETS ecryptfs-simple
  RUNTIME
  DESTINATION "${CMAKE_INSTALL_BINDIR}"
  PERMISSIONS
    OWNER_READ OWNER_WRITE OWNER_EXECUTE
    GROUP_READ GROUP_EXECUTE
    WORLD_READ WORLD_EXECUTE
  SETUID
)

# uninstall target
configure_file(
  "${CMAKE_CURRENT_SOURCE_DIR}/cmake_uninstall.cmake.in"
  "${CMAKE_CURRENT_BINARY_DIR}/cmake_uninstall.cmake"
  IMMEDIATE @ONLY )

add_custom_target( uninstall
COMMAND ${CMAKE_COMMAND} -P "${CMAKE_CURRENT_BINARY_DIR}/cmake_uninstall.cmake")
