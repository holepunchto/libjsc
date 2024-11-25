cmake_minimum_required(VERSION 3.25)

find_package(cmake-fetch REQUIRED PATHS node_modules/cmake-fetch)

project(jsc C)

add_library(v8 INTERFACE)
add_library(c++ INTERFACE)

fetch_package("github:holepunchto/libjs" SOURCE_DIR js)

add_library(jsc OBJECT)

set_target_properties(
  jsc
  PROPERTIES
  C_STANDARD 99
  POSITION_INDEPENDENT_CODE ON
)

target_sources(
  jsc
  PRIVATE
    src/jsc.c
    src/jsc.h
    src/jsc/JSBasePrivate.h
    src/jsc/JSContextRefPrivate.h
    src/jsc/JSHeapFinalizerPrivate.h
    src/jsc/JSLockRefPrivate.h
    src/jsc/JSMarkingConstraintPrivate.h
    src/jsc/JSObjectRefPrivate.h
    src/jsc/JSScriptRefPrivate.h
    src/jsc/JSStringRefPrivate.h
    src/jsc/JSWeakObjectMapRefPrivate.h
    src/jsc/JSWeakPrivate.h
)

target_include_directories(
  jsc
  PUBLIC
    include
    $<TARGET_PROPERTY:js,INTERFACE_INCLUDE_DIRECTORIES>
    $<TARGET_PROPERTY:utf,INTERFACE_INCLUDE_DIRECTORIES>
)

target_link_libraries(
  jsc
  PUBLIC
    "-framework CoreFoundation"
    "-framework JavaScriptCore"
)

add_library(jsc_shared SHARED)

set_target_properties(
  jsc_shared
  PROPERTIES
  OUTPUT_NAME jsc
)

target_link_libraries(
  jsc_shared
  PUBLIC
    jsc
    uv
    utf_shared
)

add_library(jsc_static STATIC)

set_target_properties(
  jsc_static
  PROPERTIES
  OUTPUT_NAME jsc
  PREFIX lib
)

target_link_libraries(
  jsc_static
  PUBLIC
    jsc
    uv_a
    utf_static
)

install(TARGETS jsc_shared jsc_static)

if(PROJECT_IS_TOP_LEVEL)
  enable_testing()

  add_subdirectory(test)
endif()
