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

CMAKE_MINIMUM_REQUIRED(VERSION 2.6)
PROJECT(blakerypt C)

# Compilation Options
OPTION( BUILD_SHARED_LIBS "Build Shared Library (OFF for Static)" ON  )
OPTION( PROFILE           "Generate profiling information"        OFF )

INCLUDE_DIRECTORIES(src include)

FILE(GLOB SRC_H          include/*.h)
FILE(GLOB SRC_BLAKERYPT src/*.c src/*.h)

ADD_LIBRARY(blakerypt_so ${SRC_H} ${SRC_BLAKERYPT})
ADD_EXECUTABLE(blakerypt ${SRC_H} ${SRC_BLAKERYPT})

# Compile Flags
SET(CMAKE_C_FLAGS       "-Wall -Wextra -Wstrict-aliasing=2 -Wstrict-prototypes -pedantic -std=c99 ${CMAKE_C_FLAGS}")
SET(CMAKE_C_FLAGS_DEBUG "-g -O0")

IF (BUILD_SHARED_LIBS)
   SET(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -fvisibility=hidden -fPIC")
ENDIF ()

IF (PROFILE)
   SET(CMAKE_C_FLAGS          "-pg ${CMAKE_C_FLAGS}")
   SET(CMAKE_EXE_LINKER_FLAGS "-pg ${CMAKE_EXE_LINKER_FLAGS}")
ENDIF ()
