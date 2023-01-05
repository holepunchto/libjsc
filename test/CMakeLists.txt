list(APPEND tests
  create-function
  create-function-args-extra
  create-function-args-fewer
  create-function-throw
  create-function-throw-indirect
  create-reference
  run-script
  run-script-throw
  set-named-property
  wasm
)

foreach(test IN LISTS tests)
  add_executable(${test} ../vendor/libjs/test/${test}.c)

  target_link_libraries(
    ${test}
    PRIVATE
      jsc_shared
  )

  target_include_directories(
    ${test}
    PRIVATE
      $<TARGET_PROPERTY:jsc,INCLUDE_DIRECTORIES>
  )

  add_test(
    NAME ${test}
    COMMAND ${test}
    WORKING_DIRECTORY ${PROJECT_SOURCE_DIR}
  )
endforeach()
