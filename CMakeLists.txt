cmake_minimum_required(VERSION 3.31)

find_package(cmake-fetch REQUIRED PATHS node_modules/cmake-fetch)

project(js C)

add_library(js OBJECT)

fetch_package("github:holepunchto/libjs" SOURCE_DIR js)
fetch_package("github:holepunchto/libintrusive")

set_target_properties(
  js
  PROPERTIES
  C_STANDARD 99
  POSITION_INDEPENDENT_CODE ON
)

target_sources(
  js
  PRIVATE
    src/js.c
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
  js
  INTERFACE
    include
  PUBLIC
    ${js}/include
  PRIVATE
    $<TARGET_PROPERTY:uv,INTERFACE_INCLUDE_DIRECTORIES>
    $<TARGET_PROPERTY:utf,INTERFACE_INCLUDE_DIRECTORIES>
    $<TARGET_PROPERTY:intrusive,INTERFACE_INCLUDE_DIRECTORIES>
)

target_link_libraries(
  js
  PUBLIC
    "-framework CoreFoundation"
    "-framework JavaScriptCore"
)

add_library(js_shared SHARED)

set_target_properties(
  js_shared
  PROPERTIES
  OUTPUT_NAME js
)

target_link_libraries(
  js_shared
  PUBLIC
    uv
    utf_shared
  PRIVATE
    js
)

add_library(js_static STATIC)

set_target_properties(
  js_static
  PROPERTIES
  OUTPUT_NAME js
  PREFIX lib
)

target_link_libraries(
  js_static
  PUBLIC
    uv_a
    utf_static
  PRIVATE
    js
)

install(TARGETS js_shared js_static)

if(PROJECT_IS_TOP_LEVEL)
  enable_testing()

  add_subdirectory(test)
endif()
