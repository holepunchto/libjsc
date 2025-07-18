list(APPEND tests
  add-finalizer
  add-teardown-callback
  add-teardown-callback-deferred
  add-teardown-callback-deferred-remove
  add-teardown-callback-multiple
  add-teardown-callback-remove
  add-type-tag
  add-type-tag-delegate
  adjust-external-memory
  atomics-wait-timeout
  atomics-wait-timeout-notify
  call-function
  call-function-ignore-return
  call-function-in-context
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
  create-arraybuffer-too-large
  create-arraybuffer-with-backing-store
  create-date
  create-date-nan
  create-date-overflow
  create-delegate
  create-delegate-delete-throw
  create-delegate-get-throw
  create-delegate-get-without-has
  create-delegate-has-throw
  create-delegate-keys-throw
  create-delegate-set-throw
  create-env
  create-env-multiple
  create-external
  create-external-arraybuffer
  create-external-arraybuffer-with-finalizer
  create-external-arraybuffer-with-finalizer-detach
  create-external-string-latin1
  create-external-string-latin1-with-finalizer
  create-external-string-utf8
  create-external-string-utf8-with-finalizer
  create-external-string-utf16le
  create-external-string-utf16le-with-finalizer
  create-external-with-finalizer
  create-function
  create-function-args-extra
  create-function-args-fewer
  create-function-throw
  create-function-throw-indirect
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
  create-typed-function
  create-typed-function-no-jit
  create-typed-function-with-arraybuffer
  create-typed-function-with-bigint64
  create-typed-function-with-biguint64
  create-typed-function-with-dataview
  create-typed-function-with-finalizer
  create-typed-function-with-int8array
  create-typed-function-with-int32
  create-typed-function-with-int64
  create-typed-function-with-number
  create-typed-function-with-pointer
  create-typed-function-with-receiver
  create-typed-function-with-string-latin1
  create-typed-function-with-string-utf16le
  create-typed-function-with-uint8array
  create-typed-function-with-uint32
  create-typed-function-with-uint64
  create-uint8array
  create-unsafe-arraybuffer
  define-class
  define-class-with-method
  define-class-with-static-method
  define-class-with-static-value
  define-class-with-symbol-property
  define-class-with-value
  dynamic-import
  dynamic-import-without-handler
  fatal-exception
  get-arraybuffer-info
  get-dataview-info
  get-platform-identifier
  get-platform-limits
  get-platform-version
  get-property-missing
  get-typedarray-info-uint16array
  get-typedarray-info-uint16array-large
  get-typedarray-info-uint8array
  get-typedarray-info-uint8array-large
  get-typedarray-info-uint8array-with-offset
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
  promise-rejection-unhandled-reentrant
  promise-rejection-unhandled-reentrant-deferred
  run-module
  run-module-async
  run-module-cyclic-import
  run-module-double-nested-import
  run-module-in-context
  run-module-nested-import
  run-module-throw
  run-script
  run-script-ignore-return
  run-script-in-context
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
  wrap-remove-with-finalizer
  wrap-with-finalizer
  wrap-with-reference
)

list(APPEND skipped_tests
  # Not supported
  create-typed-function
  create-typed-function-with-arraybuffer
  create-typed-function-with-bigint64
  create-typed-function-with-biguint64
  create-typed-function-with-dataview
  create-typed-function-with-finalizer
  create-typed-function-with-int8array
  create-typed-function-with-int32
  create-typed-function-with-int64
  create-typed-function-with-number
  create-typed-function-with-pointer
  create-typed-function-with-receiver
  create-typed-function-with-string-latin1
  create-typed-function-with-string-utf16le
  create-typed-function-with-uint8array
  create-typed-function-with-uint32
  create-typed-function-with-uint64

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

  # Not implemented
  call-function-in-context
  run-script-in-context

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
  run-module-in-context
  run-module-throw

  # https://bugs.webkit.org/show_bug.cgi?id=250552
  create-external-arraybuffer-with-finalizer-detach
)

foreach(test IN LISTS tests)
  add_executable(${test} ${js}/test/${test}.c)

  target_link_libraries(
    ${test}
    PRIVATE
      js_static
  )

  add_test(
    NAME ${test}
    COMMAND ${test}
    WORKING_DIRECTORY ${PROJECT_SOURCE_DIR}
  )

  set_tests_properties(
    ${test}
    PROPERTIES
    TIMEOUT 60
  )

  if(${test} IN_LIST skipped_tests)
    set_tests_properties(
      ${test}
      PROPERTIES
      DISABLED ON
    )
  endif()
endforeach()
