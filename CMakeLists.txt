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
    PRIVATE
      intrusive::headers
      "-framework CoreFoundation"
      "-framework JavaScriptCore"
    STATIC
      uv_a
    SHARED
      uv
  EXPORT OFF
)

fetch_package("github:holepunchto/libjs" SOURCE_DIR js)

add_test_subdirectory(test)
