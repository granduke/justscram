cmake_minimum_required (VERSION 3.1.0)
include(CheckFunctionExists)

set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

check_function_exists(arc4random_buf HAVE_ARC4RANDOM_BUF)
if(HAVE_ARC4RANDOM_BUF)
    add_definitions(-DHAVE_ARC4RANDOM_BUF)
endif()

check_function_exists(explicit_bzero HAVE_EXPLICIT_BZERO)
if(HAVE_EXPLICIT_BZERO)
    add_definitions(-DHAVE_EXPLICIT_BZERO)
endif()

check_function_exists(memset_s HAVE_MEMSET_S)
if(HAVE_MEMSET_S)
    add_definitions(-DHAVE_MEMSET_S)
endif()

set(CRYPTO_SRC crypto/hmac_sha1.c crypto/pkcs5_pbkdf2.c crypto/sha1.c base64/base64.c compat/freezero.c)

if(NOT HAVE_ARC4RANDOM_BUF)
    set(CRYPTO_SRC ${CRYPTO_SRC} compat/arc4random.c)
    set(CRYPTO_SRC ${CRYPTO_SRC} compat/arc4random_uniform.c)
    set(EXTRA_EXPORT ${EXTRA_EXPORT} arc4random)
    set(EXTRA_EXPORT ${EXTRA_EXPORT} arc4random_buf)
    set(EXTRA_EXPORT ${EXTRA_EXPORT} arc4random_uniform)

    if(NOT HAVE_GETENTROPY)
        if(CMAKE_HOST_WIN32)
            set(CRYPTO_SRC ${CRYPTO_SRC} compat/getentropy_win.c)
        elseif(CMAKE_SYSTEM_NAME MATCHES "AIX")
            set(CRYPTO_SRC ${CRYPTO_SRC} compat/getentropy_aix.c)
        elseif(CMAKE_SYSTEM_NAME MATCHES "FreeBSD")
            set(CRYPTO_SRC ${CRYPTO_SRC} compat/getentropy_freebsd.c)
        elseif(CMAKE_SYSTEM_NAME MATCHES "HP-UX")
            set(CRYPTO_SRC ${CRYPTO_SRC} compat/getentropy_hpux.c)
        elseif(CMAKE_SYSTEM_NAME MATCHES "Linux")
            set(CRYPTO_SRC ${CRYPTO_SRC} compat/getentropy_linux.c)
        elseif(CMAKE_SYSTEM_NAME MATCHES "NetBSD")
            set(CRYPTO_SRC ${CRYPTO_SRC} compat/getentropy_netbsd.c)
        elseif(CMAKE_SYSTEM_NAME MATCHES "Darwin")
            set(CRYPTO_SRC ${CRYPTO_SRC} compat/getentropy_osx.c)
        elseif(CMAKE_SYSTEM_NAME MATCHES "SunOS")
            set(CRYPTO_SRC ${CRYPTO_SRC} compat/getentropy_solaris.c)
        endif()
        set(EXTRA_EXPORT ${EXTRA_EXPORT} getentropy)
    endif()
endif()

if(NOT HAVE_EXPLICIT_BZERO)
    if(CMAKE_HOST_WIN32)
        set(CRYPTO_SRC ${CRYPTO_SRC} compat/explicit_bzero_win.c)
    else()
        set(CRYPTO_SRC ${CRYPTO_SRC} compat/explicit_bzero.c)
        set_source_files_properties(compat/explicit_bzero.c PROPERTIES COMPILE_FLAGS -O0)
    endif()
    set(EXTRA_EXPORT ${EXTRA_EXPORT} explicit_bzero)
endif()

add_library(JustSCRAM scram.c messages.c passwords.c ${CRYPTO_SRC})

add_executable(testscram testscram.c)
target_link_libraries(testscram JustSCRAM)

# This section based on http://www.cmake.org/pipermail/cmake/2003-June/003953.html
IF (UNIX)
    ADD_CUSTOM_TARGET (distclean @echo cleaning for source distribution)
    SET(DISTCLEANED
        CMakeFiles
        cmake.depends
        cmake.check_depends
        CMakeCache.txt
        cmake.check_cache
        Makefile
        *.cmake
        */CMakeCache.txt
        */CMakeFiles
        */*.cmake
        */*/CMakeCache.txt
        */*/CMakeFiles
        */*/*.cmake
        core core.*
        gmon.out
        */*.o
        */*.a
        *.o
        *.a
        *~
        compile_commands.json
        testscram
        )

    ADD_CUSTOM_COMMAND(
        DEPENDS clean
        COMMENT "distribution clean"
        COMMAND rm
        ARGS    -Rf CMakeTmp ${DISTCLEANED}
        TARGET  distclean
        )
ENDIF(UNIX)
