cmake_minimum_required(VERSION 3.13)
set(CMAKE_C_COMPILER /home/twinturbo/Desktop/ExtraSpace/CheckCBox_Compiler/llvm/cmake-build-debug/bin/clang)
project(testBench)



add_compile_options(-g -fPIC -Wall -Wextra)
add_link_options(-ldl -lstdc++ -lcheck -lm)
add_executable(testBench "${CMAKE_SOURCE_DIR}/starter.c" starter.c)
target_include_directories(testBench PUBLIC "${CMAKE_SOURCE_DIR}/../../include"
        "${CMAKE_SOURCE_DIR}/../../")
target_link_libraries(testBench
        "${CMAKE_SOURCE_DIR}/../../lib/prbase.a"
        "${CMAKE_SOURCE_DIR}/../../lib/pr_fnmatch.o"
        "${CMAKE_SOURCE_DIR}/../../lib/openbsd-bcrypt.o"
        "${CMAKE_SOURCE_DIR}/../../lib/openbsd-blowfish.o"
        "${CMAKE_SOURCE_DIR}/../../lib/ccan-json.o"
        "${CMAKE_SOURCE_DIR}/../../lib/sstrncpy.o"
        "${CMAKE_SOURCE_DIR}/../../src/pool.o"
        "${CMAKE_SOURCE_DIR}/../../src/privs.o"
        "${CMAKE_SOURCE_DIR}/../../src/str.o"
        "${CMAKE_SOURCE_DIR}/../../src/sets.o"
        "${CMAKE_SOURCE_DIR}/../../src/version.o"
        "${CMAKE_SOURCE_DIR}/../../src/timers.o"
        "${CMAKE_SOURCE_DIR}/../../src/table.o"
        "${CMAKE_SOURCE_DIR}/../../src/support.o"
        "${CMAKE_SOURCE_DIR}/../../src/var.o"
        "${CMAKE_SOURCE_DIR}/../../src/event.o"
        "${CMAKE_SOURCE_DIR}/../../src/env.o"
        "${CMAKE_SOURCE_DIR}/../../src/random.o"
        "${CMAKE_SOURCE_DIR}/../../src/feat.o"
        "${CMAKE_SOURCE_DIR}/../../src/netaddr.o"

        "${CMAKE_SOURCE_DIR}/../../src/netacl.o"
        "${CMAKE_SOURCE_DIR}/../../src/class.o"
        "${CMAKE_SOURCE_DIR}/../../src/regexp.o"
        "${CMAKE_SOURCE_DIR}/../../src/expr.o"
        "${CMAKE_SOURCE_DIR}/../../src/scoreboard.o"
        "${CMAKE_SOURCE_DIR}/../../src/stash.o"

        "${CMAKE_SOURCE_DIR}/../../src/modules.o"
        "${CMAKE_SOURCE_DIR}/../../src/cmd.o"
        "${CMAKE_SOURCE_DIR}/../../src/response.o"
        "${CMAKE_SOURCE_DIR}/../../src/rlimit.o"
        "${CMAKE_SOURCE_DIR}/../../src/fsio.o"
        "${CMAKE_SOURCE_DIR}/../../src/netio.o"

        "${CMAKE_SOURCE_DIR}/../../src/encode.o"
        "${CMAKE_SOURCE_DIR}/../../src/trace.o"
        "${CMAKE_SOURCE_DIR}/../../src/parser.o"
        "${CMAKE_SOURCE_DIR}/../../src/pidfile.o"
        "${CMAKE_SOURCE_DIR}/../../src/configdb.o"
        "${CMAKE_SOURCE_DIR}/../../src/auth.o"

        "${CMAKE_SOURCE_DIR}/../../src/filter.o"
        "${CMAKE_SOURCE_DIR}/../../src/inet.o"
        "${CMAKE_SOURCE_DIR}/../../src/data.o"
        "${CMAKE_SOURCE_DIR}/../../src/ascii.o"
        "${CMAKE_SOURCE_DIR}/../../src/ctrls.o"
        "${CMAKE_SOURCE_DIR}/../../src/help.o"

        "${CMAKE_SOURCE_DIR}/../../src/display.o"
        "${CMAKE_SOURCE_DIR}/../../src/json.o"
        "${CMAKE_SOURCE_DIR}/../../src/jot.o"
        "${CMAKE_SOURCE_DIR}/../../src/redis.o"
        "${CMAKE_SOURCE_DIR}/../../src/error.o"


        "${CMAKE_SOURCE_DIR}/pool.o"
        "${CMAKE_SOURCE_DIR}/array.o"
        "${CMAKE_SOURCE_DIR}/str.o"
        "${CMAKE_SOURCE_DIR}/sets.o"

        "${CMAKE_SOURCE_DIR}/timers.o"
        "${CMAKE_SOURCE_DIR}/table.o"
        "${CMAKE_SOURCE_DIR}/var.o"
        "${CMAKE_SOURCE_DIR}/event.o"

        "${CMAKE_SOURCE_DIR}/env.o"
        "${CMAKE_SOURCE_DIR}/random.o"
        "${CMAKE_SOURCE_DIR}/version.o"
        "${CMAKE_SOURCE_DIR}/feat.o"

        "${CMAKE_SOURCE_DIR}/netaddr.o"
        "${CMAKE_SOURCE_DIR}/netacl.o"
        "${CMAKE_SOURCE_DIR}/class.o"
        "${CMAKE_SOURCE_DIR}/regexp.o"


        "${CMAKE_SOURCE_DIR}/expr.o"
        "${CMAKE_SOURCE_DIR}/scoreboard.o"
        "${CMAKE_SOURCE_DIR}/stash.o"
        "${CMAKE_SOURCE_DIR}/modules.o"


        "${CMAKE_SOURCE_DIR}/cmd.o"
        "${CMAKE_SOURCE_DIR}/response.o"
        "${CMAKE_SOURCE_DIR}/fsio.o"
        "${CMAKE_SOURCE_DIR}/netio.o"

        "${CMAKE_SOURCE_DIR}/trace.o"
        "${CMAKE_SOURCE_DIR}/parser.o"
        "${CMAKE_SOURCE_DIR}/pidfile.o"
        "${CMAKE_SOURCE_DIR}/configdb.o"


        "${CMAKE_SOURCE_DIR}/auth.o"
        "${CMAKE_SOURCE_DIR}/filter.o"
        "${CMAKE_SOURCE_DIR}/inet.o"
        "${CMAKE_SOURCE_DIR}/data.o"

        "${CMAKE_SOURCE_DIR}/ascii.o"
        "${CMAKE_SOURCE_DIR}/ctrls.o"
        "${CMAKE_SOURCE_DIR}/help.o"
        "${CMAKE_SOURCE_DIR}/rlimit.o"


        "${CMAKE_SOURCE_DIR}/encode.o"
        "${CMAKE_SOURCE_DIR}/privs.o"
        "${CMAKE_SOURCE_DIR}/display.o"
        "${CMAKE_SOURCE_DIR}/misc.o"

        "${CMAKE_SOURCE_DIR}/json.o"
        "${CMAKE_SOURCE_DIR}/jot.o"
        "${CMAKE_SOURCE_DIR}/redis.o"
        "${CMAKE_SOURCE_DIR}/error.o"

        "${CMAKE_SOURCE_DIR}/stubs.o"

        "/home/twinturbo/Desktop/ExtraSpace/checkcbox-proftpd/Checkcbox_LIBS/libisc_lib_final.so"
        "/home/twinturbo/Desktop/ExtraSpace/checkcbox-proftpd/Checkcbox_LIBS/libisc_lib_final.a"
        "/home/twinturbo/Desktop/ExtraSpace/checkcbox-proftpd/Checkcbox_LIBS/libSBX_CON_LIB.a"

        -fsanitize=address  -static-libsan
        dl)

#
#add_executable(SIMPLE "${CMAKE_SOURCE_DIR}/sbx_interface_def/simple_main.c")
#target_link_libraries(SIMPLE final)
