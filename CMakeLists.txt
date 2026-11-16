cmake_minimum_required(VERSION 4.0)

find_package(cmake-fetch REQUIRED PATHS node_modules/cmake-fetch)
find_package(cmake-prelude REQUIRED PATHS node_modules/cmake-prelude)
find_package(cmake-test REQUIRED PATHS node_modules/cmake-test)

project(js LANGUAGES C VERSION 0.0.0)

fetch_package("github:holepunchto/libintrusive")

add_library_targets(
  js
  FEATURES
    c_std_99
  SOURCES
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
  LINK
    utf::<TYPE>
  STATIC_LINK
    uv_a
    "-framework CoreFoundation"
    "-framework JavaScriptCore"
  SHARED_LINK
    uv
    "-framework CoreFoundation"
    "-framework JavaScriptCore"
  EXPORT OFF
)

target_link_libraries(
  js
  PRIVATE
    intrusive::headers
)

target_include_directories(
  js_headers
  INTERFACE
    $<TARGET_PROPERTY:uv,INTERFACE_INCLUDE_DIRECTORIES>
)

fetch_package("github:holepunchto/libjs" SOURCE_DIR js)

target_sources(
  js_headers
  INTERFACE
    FILE_SET HEADERS
    BASE_DIRS ${js}/include
    FILES ${js}/include/js.h
)

add_test_subdirectory(test)
