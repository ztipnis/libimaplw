include(ExternalProject)
message(STATUS "Will fetch Mimetic as part of build")
find_package(Git)
ExternalProject_Add(Project_Mimetic
    GIT_REPOSITORY https://github.com/tat/mimetic
    GIT_PROGRESS 1
    UPDATE_COMMAND "" #${GIT_EXECUTABLE} stash && ${GIT_EXECUTABLE} pull && ${GIT_EXECUTABLE} stash apply || true
    SOURCE_DIR ${CMAKE_CURRENT_BINARY_DIR}/mimetic
    PATCH_COMMAND ${CMAKE_CURRENT_SOURCE_DIR}/mimetic-patches/patch.sh ${CMAKE_CURRENT_SOURCE_DIR}
    CONFIGURE_COMMAND ${CMAKE_CURRENT_BINARY_DIR}/mimetic/configure --prefix=${CMAKE_CURRENT_BINARY_DIR}/libmimetic --enable-fast-install=no --enable-static=yes --enable-shared=no
    BUILD_COMMAND ${MAKE}
    BUILD_ALWAYS 0
    BUILD_BYPRODUCTS ${CMAKE_CURRENT_BINARY_DIR}/libmimetic/lib/libmimetic.a
)
set(MIMETIC_INCLUDE_DIR ${CMAKE_CURRENT_BINARY_DIR}/libmimetic/include)
set(MIMETIC_LIBRARY ${CMAKE_CURRENT_BINARY_DIR}/libmimetic/lib/libmimetic.a CACHE INTERNAL "Mimetic Library Path")
add_library(Mimetic STATIC IMPORTED)
# Set Properties
set_target_properties(
    Mimetic
    PROPERTIES
        IMPORTED_LINK_INTERFACE_LANGUAGES "C"
        IMPORTED_LOCATION "${MIMETIC_LIBRARY}"
)
add_dependencies(Mimetic Project_Mimetic)
set(MIMETIC_LIBRARIES Mimetic)
mark_as_advanced(MIMETIC_INCLUDE_DIR MIMETIC_LIBRARIES MIMETIC_LIBRARY)
set(MIMETIC_GOTTEN True)