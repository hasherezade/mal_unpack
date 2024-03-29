cmake_minimum_required ( VERSION 3.12.4 )

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


set (util_srcs
	util/process_util.cpp
	util/file_util.cpp
	util/path_util.cpp
	util/rm_util.cpp
)

set (util_hdrs
	util/process_util.h
	util/file_util.h
	util/path_util.h
	util/rm_util.h
)

set (srcs
	main.cpp
	unpack_scanner.cpp
	driver_comm.cpp
	${util_srcs}
)

set (hdrs
	unpack_scanner.h
	driver_comm.h
	ntddk.h
	params.h
	${util_hdrs}
)

set (rsrc
	mal_unpack_ver.h
	mal_unpack_res.rc
)

# libs
add_subdirectory ( ${PARAMKIT_DIR} )

# libs
if (NOT PESIEVE_AS_DLL)
	set ( PESIEVE_AS_STATIC_LIB ON CACHE BOOL "Enable building PE-sieve as a static library" FORCE)
endif()

if (NOT PESIEVE_AS_STATIC_LIB)
	set ( PESIEVE_AS_DLL ON CACHE BOOL "Enable building PE-sieve as a DLL" FORCE)
endif()

add_subdirectory (pe-sieve)
set ( PESIEVE_LIB $<TARGET_FILE:pe-sieve> CACHE PATH "PE-sieve library path" )

cmake_policy(SET CMP0015 NEW)
LINK_DIRECTORIES ( ${PESIEVE_LIB} )
add_executable ( ${PROJECT_NAME} ${hdrs} ${srcs} ${rsrc} main.cpp )
target_link_libraries ( ${PROJECT_NAME} ${M_PESIEVE} ${M_PARAMKIT} )

# dependencies
add_dependencies( ${PROJECT_NAME} ${M_PESIEVE} ${M_PARAMKIT} )

#install
INSTALL( TARGETS ${PROJECT_NAME} DESTINATION ${CMAKE_INSTALL_PREFIX} COMPONENT ${PROJECT_NAME} )

# Setup testing
if(MU_BUILD_TESTING)
	enable_testing()

	# 0) does the application run?
	add_test ( TestRuns ${CMAKE_INSTALL_PREFIX}\\${PROJECT_NAME} --help )
	set_tests_properties(TestRuns PROPERTIES PASS_REGULAR_EXPRESSION "PE-sieve")
endif()
