cmake_minimum_required(VERSION 2.6)

project(ecryptfs-simple)
set(VERSION_MAJOR 2016)

find_package(PkgConfig)
include(CheckLibraryExists)

INCLUDE(GNUInstallDirs)

add_definitions( -Wextra -Wall -pedantic -std=c99 )
add_definitions( -D_BSD_SOURCE -fstack-protector-all --param ssp-buffer-size=4 )

include_directories( ${PROJECT_SOURCE_DIR}/src )

set(SRC src/ecryptfs-simple.c)

find_file( GCRYPT_INCLUDE_FILE gcrypt.h )

find_library( GCRYPT_LIB gcrypt )

find_library( ECRYPTFS_LIB ecryptfs )

if( NOT GCRYPT_INCLUDE_FILE )
	MESSAGE( FATAL_ERROR "could not find gcrypt header file" )
else()
	MESSAGE( STATUS "found gcrypt header file: ${GCRYPT_INCLUDE_FILE}" )
endif()

if( NOT GCRYPT_LIB )
	MESSAGE( FATAL_ERROR "could not find gcrypt library(libgcrypt.so)" )
else()
	MESSAGE( STATUS "found gcrypt library: ${GCRYPT_LIB}" )
endif()

if( NOT ECRYPTFS_LIB )
	MESSAGE( FATAL_ERROR "could not find ecryptfs library(ecryptfs.so)" )
else()
	MESSAGE( STATUS "found ecryptfs library: ${ECRYPTFS_LIB}" )
endif()

add_executable( ecryptfs-simple ${SRC} )

TARGET_LINK_LIBRARIES( ecryptfs-simple ${GCRYPT_LIB} ${ECRYPTFS_LIB} -lmount )

install( TARGETS ecryptfs-simple RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
	PERMISSIONS OWNER_READ OWNER_WRITE OWNER_EXECUTE GROUP_READ GROUP_EXECUTE WORLD_READ WORLD_EXECUTE SETUID
)

# uninstall target
configure_file(
	"${CMAKE_CURRENT_SOURCE_DIR}/cmake_uninstall.cmake.in"
	"${CMAKE_CURRENT_BINARY_DIR}/cmake_uninstall.cmake"
	IMMEDIATE @ONLY )

add_custom_target( uninstall
COMMAND ${CMAKE_COMMAND} -P ${CMAKE_CURRENT_BINARY_DIR}/cmake_uninstall.cmake )
