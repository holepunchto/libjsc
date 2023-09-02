cmake_minimum_required(VERSION 3.22)

project(jsc C)

if(NOT TARGET uv)
  add_subdirectory(vendor/libuv EXCLUDE_FROM_ALL)
endif()

if(NOT TARGET js)
  add_subdirectory(vendor/libjs EXCLUDE_FROM_ALL)
endif()

if(NOT TARGET utf)
  add_subdirectory(vendor/libutf EXCLUDE_FROM_ALL)
endif()

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

add_library(jsc_shared SHARED $<TARGET_OBJECTS:jsc>)

set_target_properties(
  jsc_shared
  PROPERTIES
  OUTPUT_NAME jsc
)

target_link_libraries(
  jsc_shared
  PUBLIC
    uv
    utf_shared
    "-framework CoreFoundation"
    "-framework JavaScriptCore"
)

add_library(jsc_static STATIC $<TARGET_OBJECTS:jsc>)

set_target_properties(
  jsc_static
  PROPERTIES
  OUTPUT_NAME jsc
  PREFIX lib
)

target_link_libraries(
  jsc_static
  PUBLIC
    uv_a
    utf_static
    "-framework CoreFoundation"
    "-framework JavaScriptCore"
)

install(TARGETS jsc_shared jsc_static)

if(PROJECT_IS_TOP_LEVEL)
  enable_testing()
  add_subdirectory(test)
endif()
