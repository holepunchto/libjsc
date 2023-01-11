list(APPEND tests
  call-function
  call-function-ignore-return
  call-function-throw
  create-external
  create-external-with-finalizer
  create-function
  create-function-args-extra
  create-function-args-fewer
  create-function-throw
  create-function-throw-indirect
  create-reference
  get-arraybuffer-info
  get-typedarray-info-uint8array
  get-typedarray-info-uint16array
  run-script
  run-script-ignore-return
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
