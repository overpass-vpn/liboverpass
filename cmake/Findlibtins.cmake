find_package(PkgConfig)
pkg_check_modules(LIBTINS REQUIRED libtins)
if (NOT TARGET libtins::libtins)
    add_library(libtins::libtins UNKNOWN IMPORTED)
    set_target_properties(libtins::libtins PROPERTIES
        IMPORTED_LINK_INTERFACE_LANGUAGES "CXX"
        IMPORTED_LOCATION "${LIBTINS_LIBRARIES}"
        INTERFACE_INCLUDE_DIRECTORIES "${LIBTINS_INCLUDE_DIRS}")
endif()
