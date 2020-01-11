cmake_minimum_required (VERSION 2.8)
project (mal_unpack)
option(MU_BUILD_TESTING "enable testing for mal_unpack" ON)

set(CMAKE_CXX_FLAGS_RELEASE "${CMAKE_CXX_FLAGS_RELEASE} /MT")

# modules:
set ( M_PESIEVE "pe-sieve" )
set ( M_PARAMKIT "paramkit" )

# modules paths:
set (PESIEVE_DIR "${PROJECT_SOURCE_DIR}/${M_PESIEVE}" CACHE PATH "PE-sieve main path")
include_directories ( ${PESIEVE_DIR}/include )

set (PARAMKIT_DIR "${PROJECT_SOURCE_DIR}/${M_PARAMKIT}/${M_PARAMKIT}" CACHE PATH "ParamKit main path")
include_directories ( ${PARAMKIT_DIR}/include )

set (srcs
	main.cpp
	process_util.cpp
	unpack_scanner.cpp
	util.cpp
)

set (hdrs
	process_util.h
	unpack_scanner.h
	util.h
	params.h
)

# libs
add_subdirectory ( ${PARAMKIT_DIR} )

set ( PESIEVE_AS_DLL ON CACHE BOOL "Enable building PE-sieve as a DLL" FORCE)
add_subdirectory (pe-sieve)
set ( PESIEVE_LIB $<TARGET_FILE:pe-sieve> CACHE FILE "PE-sieve library path" )

cmake_policy(SET CMP0015 NEW)
LINK_DIRECTORIES ( ${PESIEVE_LIB} )
add_executable ( ${PROJECT_NAME} ${hdrs} ${srcs} main.cpp )
target_link_libraries ( ${PROJECT_NAME} ${M_PESIEVE} ${M_PARAMKIT} )

# dependencies
add_dependencies( ${PROJECT_NAME} ${M_PESIEVE} ${M_PARAMKIT} )

#install
INSTALL( TARGETS ${PROJECT_NAME} DESTINATION ${CMAKE_BINARY_DIR} COMPONENT ${PROJECT_NAME} )

# Setup testing
if(MU_BUILD_TESTING)
	enable_testing()

	# 0) does the application run
	add_test ( TestRuns ${PROJECT_NAME} )
endif()
