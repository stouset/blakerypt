# CMake build script for the blakerypt project
#
# Building (out of source build):
# > mkdir build && cd build
# > cmake .. [-DSETTINGS=VALUE]
# > cmake --build .
#
# Testing:
# > ctest -V
#
# Install:
# > cmake --build . --target install

CMAKE_MINIMUM_REQUIRED(VERSION 2.8)
PROJECT(blakerypt C)

OPTION(BUILD_SHARED_LIBS "Build as a shared library" ON)

IF(NOT CMAKE_BUILD_TYPE)
  SET(CMAKE_BUILD_TYPE "Debug")
ENDIF()

INCLUDE_DIRECTORIES(src include)
INCLUDE_DIRECTORIES(deps/blake2/sse)

FILE(GLOB SRC_BLAKERYPT src/*.c)
FILE(GLOB SRC_BLAKE2B   deps/blake2/sse/blake2b.c)

ADD_LIBRARY(blake2b_o    OBJECT ${SRC_BLAKE2B})
ADD_LIBRARY(blakerypt_so        ${SRC_BLAKERYPT} $<TARGET_OBJECTS:blake2b_o>)

SET_TARGET_PROPERTIES(blakerypt_so PROPERTIES OUTPUT_NAME blakerypt)

ADD_EXECUTABLE(blakerypt main.c)
TARGET_LINK_LIBRARIES(blakerypt blakerypt_so)

SET(CMAKE_C_WARNINGS
        "-Werror" "-Wall" "-Wextra" "-Wpedantic"
        "-Wformat=2" "-Wshadow" "-Wwrite-strings" "-Wstrict-prototypes"
        "-Wold-style-definition" "-Wredundant-decls" "-Wnested-externs"
        "-Wmissing-include-dirs"
)

SET(CMAKE_C_EXTRA
        "-std=c11" "-march=native" "-fvisibility=hidden"
)

STRING(REPLACE ";" " " CMAKE_C_WARNINGS "${CMAKE_C_WARNINGS}")
STRING(REPLACE ";" " " CMAKE_C_EXTRA    "${CMAKE_C_EXTRA}")

SET(CMAKE_C_FLAGS "${CMAKE_C_EXTRA} ${CMAKE_C_WARNINGS} ${CMAKE_C_FLAGS}")
