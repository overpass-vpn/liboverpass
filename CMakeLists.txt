cmake_minimum_required(VERSION 3.5)
project(overpass
	VERSION 0.0.0
	LANGUAGES CXX
)

configure_file(
	${PROJECT_SOURCE_DIR}/data/version.h.in
	${PROJECT_BINARY_DIR}/include/version.h
)

# Overpass uses boost for parsing command-line parameters.
find_package(Boost REQUIRED COMPONENTS
	program_options
	system
)

# Overpass uses libtins for packet processing. It may be findable already, but
# if not, try again using our custom finder.
find_package(libtins)
if (NOT libtins_FOUND)
	list(APPEND CMAKE_MODULE_PATH "${CMAKE_CURRENT_LIST_DIR}/cmake")
	find_package(libtins REQUIRED)
endif()

include_directories(
	${PROJECT_SOURCE_DIR}/include
	${PROJECT_BINARY_DIR}/include
	${Boost_INCLUDE_DIRS}
	${LIBTINS_INCLUDE_DIRS}
)

set(OVERPASS_HEADERS
	${PROJECT_SOURCE_DIR}/include/datagram_server.h
	${PROJECT_SOURCE_DIR}/include/internal/datagram_server_private.h
	${PROJECT_SOURCE_DIR}/include/internal/overpass_server_private.h
	${PROJECT_SOURCE_DIR}/include/overpass_server.h
	${PROJECT_SOURCE_DIR}/include/router.h
	${PROJECT_SOURCE_DIR}/include/stream_server.h
	${PROJECT_SOURCE_DIR}/include/types.h
	${PROJECT_SOURCE_DIR}/include/virtual_interface.h
)

set(OVERPASS_SOURCES
	${PROJECT_SOURCE_DIR}/src/internal/overpass_server_private.cpp
	${PROJECT_SOURCE_DIR}/src/overpass_server.cpp
	${PROJECT_SOURCE_DIR}/src/router.cpp
	${PROJECT_SOURCE_DIR}/src/version.cpp
	${PROJECT_SOURCE_DIR}/src/virtual_interface_implementations/linux.cpp
)

add_definitions("-std=c++11 -Wall -Wextra")

add_library(overpass
	${OVERPASS_HEADERS}
	${OVERPASS_SOURCES}
)

target_include_directories(overpass
	PUBLIC
		${PROJECT_SOURCE_DIR}/include
		${PROJECT_BINARY_DIR}/include
	PRIVATE
		${Boost_INCLUDE_DIRS}
		${LIBTINS_INCLUDE_DIRS}
)

target_link_libraries(overpass
	PRIVATE
		${LIBTINS_LIBRARIES}
)

add_executable(overpassd
	${PROJECT_SOURCE_DIR}/src/main.cpp
)

target_link_libraries(overpassd
	PRIVATE
		overpass
		${Boost_LIBRARIES}
		pthread
)

install(TARGETS overpass overpassd
	LIBRARY DESTINATION lib
	ARCHIVE DESTINATION lib
	RUNTIME DESTINATION bin
)

option(BUILD_TESTS "Whether or not to build the tests" ON)
if(BUILD_TESTS)
	set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -g -O0") # Debug, no optimization
	set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} --coverage") # Enable coverage
	add_subdirectory(tests)
endif()
