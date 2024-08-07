list(APPEND tests
  add-finalizer
  add-type-tag
  add-type-tag-delegate
  adjust-external-memory
  atomics-wait-timeout
  atomics-wait-timeout-notify
  call-function
  call-function-ignore-return
  call-function-microtask
  call-function-microtask-nested
  call-function-throw
  call-threadsafe-function-after-release
  call-threadsafe-function-with-data
  coerce-number-to-string
  coerce-object-to-string
  coerce-string-to-number
  coerce-symbol-to-string
  create-arraybuffer
  create-arraybuffer-with-backing-store
  create-date
  create-date-nan
  create-date-overflow
  create-delegate
  create-delegate-get-without-has
  create-delegate-get-throw
  create-delegate-has-throw
  create-delegate-set-throw
  create-delegate-delete-throw
  create-delegate-keys-throw
  create-external
  create-external-with-finalizer
  create-external-arraybuffer
  create-external-arraybuffer-with-finalizer
  create-function
  create-function-args-extra
  create-function-args-fewer
  create-function-throw
  create-function-throw-indirect
  create-function-with-ffi
  create-function-with-ffi-arraybuffer
  create-function-with-ffi-finalizer
  create-function-with-ffi-no-jit
  create-function-with-ffi-pointer
  create-function-with-ffi-receiver
  create-function-with-ffi-string
  create-function-with-ffi-uint8array
  create-function-with-finalizer
  create-function-with-source
  create-module-import-missing
  create-promise-reject
  create-promise-resolve
  create-reference-array
  create-reference-bigint
  create-reference-boolean
  create-reference-function
  create-reference-null
  create-reference-number
  create-reference-object
  create-reference-object-multiple
  create-reference-object-weak
  create-reference-string
  create-reference-symbol
  create-reference-undefined
  create-sharedarraybuffer
  create-sharedarraybuffer-with-backing-store
  create-string-utf8
  create-string-utf8-with-null
  create-threadsafe-function
  create-threadsafe-function-with-callback
  create-threadsafe-function-with-context
  create-threadsafe-function-with-finalizer
  create-uint8array
  create-unsafe-arraybuffer
  define-class
  define-class-with-value
  define-class-with-static-value
  define-class-with-method
  define-class-with-static-method
  dynamic-import
  dynamic-import-without-handler
  fatal-exception
  get-arraybuffer-info
  get-dataview-info
  get-platform-identifier
  get-platform-version
  get-property-missing
  get-typedarray-info-uint8array
  get-typedarray-info-uint8array-with-offset
  get-typedarray-info-uint16array
  get-value-string-utf8
  get-value-string-utf8-length
  get-value-string-utf8-no-null
  import-meta
  import-meta-throw
  inspector
  inspector-pause
  many-large-allocs
  many-small-allocs
  promise-rejection
  promise-rejection-unhandled
  run-module
  run-module-async
  run-module-cyclic-import
  run-module-nested-import
  run-module-double-nested-import
  run-module-throw
  run-script
  run-script-ignore-return
  run-script-throw
  set-named-property
  terminate-execution
  threads
  threads-platform-loop
  throw-error
  throw-error-formatted
  typeof-bigint
  typeof-boolean
  typeof-external
  typeof-function
  typeof-null
  typeof-number
  typeof-object
  typeof-string
  typeof-symbol
  typeof-undefined
  wasm
  wasm-async
  wasm-async-io
  wasm-async-io-multiple
  wrap
  wrap-with-finalizer
  wrap-with-reference
  wrap-remove-with-finalizer
)

list(APPEND skipped_tests
  # Not supported
  create-function-with-ffi
  create-function-with-ffi-arraybuffer
  create-function-with-ffi-finalizer
  create-function-with-ffi-pointer
  create-function-with-ffi-receiver
  create-function-with-ffi-string
  create-function-with-ffi-uint8array

  # Not supported
  inspector
  inspector-pause

  # Not implemented
  call-threadsafe-function-after-release
  call-threadsafe-function-with-data
  create-threadsafe-function
  create-threadsafe-function-with-callback
  create-threadsafe-function-with-context
  create-threadsafe-function-with-finalizer

  # Depends on JIT
  wasm
  wasm-async
  wasm-async-io
  wasm-async-io-multiple

  # https://bugs.webkit.org/show_bug.cgi?id=250554
  atomics-wait-timeout
  atomics-wait-timeout-notify
  create-promise-reject
  create-promise-resolve

  # https://bugs.webkit.org/show_bug.cgi?id=250511
  create-reference-bigint
  typeof-bigint

  # https://bugs.webkit.org/show_bug.cgi?id=257709
  create-sharedarraybuffer
  create-sharedarraybuffer-with-backing-store

  # https://bugs.webkit.org/show_bug.cgi?id=261600
  create-module-import-missing
  dynamic-import
  dynamic-import-without-handler
  import-meta
  import-meta-throw
  run-module
  run-module-async
  run-module-cyclic-import
  run-module-nested-import
  run-module-double-nested-import
  run-module-throw
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
      $<TARGET_PROPERTY:jsc,INTERFACE_INCLUDE_DIRECTORIES>
  )

  add_test(
    NAME ${test}
    COMMAND ${test}
    WORKING_DIRECTORY ${PROJECT_SOURCE_DIR}
  )

  set_tests_properties(
    ${test}
    PROPERTIES
    TIMEOUT 30
  )

  if(${test} IN_LIST skipped_tests)
    set_tests_properties(
      ${test}
      PROPERTIES
      DISABLED True
    )
  endif()
endforeach()
