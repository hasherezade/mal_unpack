cmake_minimum_required ( VERSION 3.12.4 )
cmake_policy(SET CMP0015 NEW)

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
set(MU_PESIEVE_LINK_MODE "STATIC" CACHE STRING "How MalUnpack should build and link PE-sieve")
set_property(CACHE MU_PESIEVE_LINK_MODE PROPERTY STRINGS STATIC DLL)

if(NOT MU_PESIEVE_LINK_MODE STREQUAL "STATIC" AND NOT MU_PESIEVE_LINK_MODE STREQUAL "DLL")
	message(FATAL_ERROR
	"Invalid MU_PESIEVE_LINK_MODE '${MU_PESIEVE_LINK_MODE}'. Choose: STATIC DLL"
	)
endif()

if(MU_PESIEVE_LINK_MODE STREQUAL "STATIC")
	set(PESIEVE_BUILD_MODE "STATIC" CACHE STRING "Build mode for PE-sieve" FORCE)
elseif(MU_PESIEVE_LINK_MODE STREQUAL "DLL")
	set(PESIEVE_BUILD_MODE "DLL" CACHE STRING "Build mode for PE-sieve" FORCE)
endif()

add_subdirectory (pe-sieve)
set ( PESIEVE_LIB $<TARGET_FILE:pe-sieve> CACHE PATH "PE-sieve library path" )

set (used_libs
	psapi.lib
	ntdll.lib
	shlwapi
	imagehlp
	rstrtmgr
)

add_executable ( ${PROJECT_NAME} ${hdrs} ${srcs} ${rsrc} main.cpp )
target_link_libraries ( ${PROJECT_NAME} ${M_PESIEVE} ${M_PARAMKIT} ${used_libs})

if(CMAKE_CXX_COMPILER_ID MATCHES "MSVC")
	target_link_options( ${PROJECT_NAME} PRIVATE "/MANIFEST:NO")
endif()

if (CMAKE_CXX_COMPILER_ID STREQUAL "GNU")

	option(LINK_STATICALLY "Link PE-Sieve with static versions of linked libraries" ON)

	enable_language(RC)
	set(CMAKE_RC_COMPILE_OBJECT
		"<CMAKE_RC_COMPILER> <FLAGS> -O coff <DEFINES> -i <SOURCE> -o <OBJECT>")
		
	add_compile_options(
		-fpermissive
	)

	add_compile_definitions(
		_WIN32_WINNT=1536 # 0x600 aka Windows Vista required
	)

	if(LINK_STATICALLY)
		add_link_options(
			-static
			-static-libgcc
			-static-libstdc++
		)
	endif()
endif()

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
