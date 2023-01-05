#include <js.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <uv.h>

#include <JavaScriptCore/JavaScriptCore.h>

typedef struct js_callback_s js_callback_t;

struct js_platform_s {
  js_platform_options_t options;
  uv_loop_t *loop;
};

struct js_env_s {
  uv_loop_t *loop;
  js_platform_t *platform;
  JSGlobalContextRef context;
  JSValueRef exception;
  js_uncaught_exception_cb on_uncaught_exception;
  void *uncaught_exception_data;
};

struct js_ref_s {
  JSObjectRef value;
  uint32_t count;
};

struct js_deferred_s {
  JSObjectRef resolve;
  JSObjectRef reject;
};

struct js_callback_s {
  js_env_t *env;
  js_function_cb cb;
  void *data;
};

struct js_callback_info_s {
  js_callback_t *callback;
  int argc;
  const JSValueRef *argv;
  JSObjectRef receiver;
};

int
js_create_platform (uv_loop_t *loop, const js_platform_options_t *options, js_platform_t **result) {
  js_platform_t *platform = malloc(sizeof(js_platform_t));

  platform->loop = loop;
  platform->options = options ? *options : (js_platform_options_t){};

  *result = platform;

  return 0;
}

int
js_destroy_platform (js_platform_t *platform) {
  free(platform);

  return 0;
}

int
js_get_platform_loop (js_platform_t *platform, uv_loop_t **result) {
  *result = platform->loop;

  return 0;
}

int
js_create_env (uv_loop_t *loop, js_platform_t *platform, js_env_t **result) {
  JSGlobalContextRef context = JSGlobalContextCreate(NULL);

  js_env_t *env = malloc(sizeof(js_env_t));

  env->loop = loop;
  env->platform = platform;
  env->context = context;
  env->exception = NULL;

  *result = env;

  return 0;
}

int
js_destroy_env (js_env_t *env) {
  JSGlobalContextRelease(env->context);

  free(env);

  return 0;
}

int
js_on_uncaught_exception (js_env_t *env, js_uncaught_exception_cb cb, void *data) {
  env->on_uncaught_exception = cb;
  env->uncaught_exception_data = data;

  return 0;
}

int
js_get_env_loop (js_env_t *env, uv_loop_t **result) {
  *result = env->loop;

  return 0;
}

int
js_open_handle_scope (js_env_t *env, js_handle_scope_t **result) {
  *result = NULL;

  return 0;
}

int
js_close_handle_scope (js_env_t *env, js_handle_scope_t *scope) {
  return 0;
}

int
js_open_escapable_handle_scope (js_env_t *env, js_escapable_handle_scope_t **result) {
  *result = NULL;

  return 0;
}

int
js_close_escapable_handle_scope (js_env_t *env, js_escapable_handle_scope_t *scope) {
  return 0;
}

int
js_escape_handle (js_env_t *env, js_escapable_handle_scope_t *scope, js_value_t *escapee, js_value_t **result) {
  return 0;
}

int
js_run_script (js_env_t *env, js_value_t *source, js_value_t **result) {
  JSStringRef ref = JSValueToStringCopy(env->context, (JSValueRef) source, &env->exception);

  if (env->exception) return -1;

  JSValueRef value = JSEvaluateScript(env->context, ref, NULL, NULL, 1, &env->exception);

  JSStringRelease(ref);

  if (env->exception) return -1;

  *result = (js_value_t *) value;

  return 0;
}

static void
on_reference_finalize (JSObjectRef external) {
  js_ref_t *reference = (js_ref_t *) JSObjectGetPrivate(external);

  if (reference) reference->value = NULL;
}

static JSClassDefinition js_reference_finalizer = {
  .finalize = on_reference_finalize,
};

int
js_create_reference (js_env_t *env, js_value_t *value, uint32_t count, js_ref_t **result) {
  js_ref_t *reference = malloc(sizeof(js_ref_t));

  reference->value = (JSObjectRef) value;
  reference->count = count;

  if (reference->count > 0) JSValueProtect(env->context, reference->value);

  {
    JSClassRef class = JSClassCreate(&js_reference_finalizer);

    JSObjectRef external = JSObjectMake(env->context, class, (void *) reference);

    JSClassRelease(class);

    JSStringRef ref = JSStringCreateWithUTF8CString("__native_reference");

    JSObjectSetProperty(env->context, (JSObjectRef) value, ref, external, 0, NULL);

    JSStringRelease(ref);
  }

  *result = reference;

  return 0;
}

int
js_delete_reference (js_env_t *env, js_ref_t *reference) {
  JSStringRef ref = JSStringCreateWithUTF8CString("__native_reference");

  JSValueRef external = JSObjectGetProperty(env->context, reference->value, ref, NULL);

  JSStringRelease(ref);

  JSObjectSetPrivate((JSObjectRef) external, NULL);

  if (reference->count > 0) JSValueUnprotect(env->context, reference->value);

  free(reference);

  return 0;
}

int
js_reference_ref (js_env_t *env, js_ref_t *reference, uint32_t *result) {
  reference->count++;

  if (reference->count == 1) JSValueProtect(env->context, reference->value);

  if (result != NULL) {
    *result = reference->count;
  }

  return 0;
}

int
js_reference_unref (js_env_t *env, js_ref_t *reference, uint32_t *result) {
  if (reference->count == 0) {
    return -1;
  }

  reference->count--;

  if (reference->count == 0) JSValueUnprotect(env->context, reference->value);

  if (result != NULL) {
    *result = reference->count;
  }

  return 0;
}

int
js_get_reference_value (js_env_t *env, js_ref_t *reference, js_value_t **result) {
  *result = (js_value_t *) reference->value;

  return 0;
}

int
js_create_int32 (js_env_t *env, int32_t value, js_value_t **result) {
  *result = (js_value_t *) JSValueMakeNumber(env->context, (double) value);

  return 0;
}

int
js_create_uint32 (js_env_t *env, uint32_t value, js_value_t **result) {
  *result = (js_value_t *) JSValueMakeNumber(env->context, (double) value);

  return 0;
}

int
js_create_string_utf8 (js_env_t *env, const char *str, size_t len, js_value_t **result) {
  JSStringRef ref;

  if (len == (size_t) -1) {
    ref = JSStringCreateWithUTF8CString(str);
  } else {
    char *copy = strndup(str, len);

    ref = JSStringCreateWithUTF8CString(copy);

    free(copy);
  }

  *result = (js_value_t *) JSValueMakeString(env->context, ref);

  JSStringRelease(ref);

  return 0;
}

int
js_create_object (js_env_t *env, js_value_t **result) {
  *result = (js_value_t *) JSObjectMake(env->context, NULL, NULL);

  return 0;
}

static void
on_function_finalize (JSObjectRef external) {
  js_callback_t *callback = (js_callback_t *) JSObjectGetPrivate(external);

  free(callback);
}

static JSValueRef
on_function_call (JSContextRef context, JSObjectRef function, JSObjectRef receiver, size_t argc, const JSValueRef argv[], JSValueRef *exception) {
  JSStringRef ref = JSStringCreateWithUTF8CString("__native_function");

  JSValueRef external = JSObjectGetProperty(context, function, ref, NULL);

  JSStringRelease(ref);

  js_callback_t *callback = (js_callback_t *) JSObjectGetPrivate((JSObjectRef) external);

  js_env_t *env = callback->env;

  js_callback_info_t callback_info = {
    .callback = callback,
    .argc = argc,
    .argv = argv,
    .receiver = receiver,
  };

  js_value_t *result = callback->cb(env, &callback_info);

  JSValueRef value;

  if (result == NULL) value = JSValueMakeUndefined(env->context);
  else value = (JSValueRef) result;

  if (env->exception == NULL) return value;

  *exception = env->exception;

  return NULL;
}

static JSClassDefinition js_function_finalizer = {
  .finalize = on_function_finalize,
};

int
js_create_function (js_env_t *env, const char *name, size_t len, js_function_cb cb, void *data, js_value_t **result) {
  JSStringRef ref;

  if (len == (size_t) -1) {
    ref = JSStringCreateWithUTF8CString(name);
  } else {
    char *copy = strndup(name, len);

    ref = JSStringCreateWithUTF8CString(name);

    free(copy);
  }

  JSObjectRef function = JSObjectMakeFunctionWithCallback(env->context, ref, on_function_call);

  JSStringRelease(ref);

  js_callback_t *callback = malloc(sizeof(js_callback_t));

  callback->env = env;
  callback->cb = cb;
  callback->data = data;

  {
    JSClassRef class = JSClassCreate(&js_function_finalizer);

    JSObjectRef external = JSObjectMake(env->context, class, (void *) callback);

    JSClassRelease(class);

    JSStringRef ref = JSStringCreateWithUTF8CString("__native_function");

    JSObjectSetProperty(env->context, function, ref, external, 0, NULL);

    JSStringRelease(ref);
  }

  *result = (js_value_t *) function;

  return 0;
}

int
js_create_promise (js_env_t *env, js_deferred_t **deferred, js_value_t **promise) {
  JSObjectRef resolve, reject;

  JSObjectRef value = JSObjectMakeDeferredPromise(env->context, &resolve, &reject, &env->exception);

  if (env->exception) return -1;

  js_deferred_t *result = malloc(sizeof(js_deferred_t));

  result->resolve = resolve;
  result->reject = reject;

  *deferred = result;
  *promise = (js_value_t *) value;

  return 0;
}

int
js_resolve_deferred (js_env_t *env, js_deferred_t *deferred, js_value_t *resolution) {
  JSValueRef argv[1] = {(JSValueRef) resolution};

  JSObjectCallAsFunction(env->context, deferred->resolve, NULL, 1, argv, &env->exception);

  if (env->exception) return -1;

  return 0;
}

int
js_reject_deferred (js_env_t *env, js_deferred_t *deferred, js_value_t *resolution) {
  JSValueRef argv[1] = {(JSValueRef) resolution};

  JSObjectCallAsFunction(env->context, deferred->reject, NULL, 1, argv, &env->exception);

  if (env->exception) return -1;

  return 0;
}

int
js_create_error (js_env_t *env, js_value_t *code, js_value_t *message, js_value_t **result) {
  JSValueRef argv[1] = {(JSValueRef) message};

  JSObjectRef error = JSObjectMakeError(env->context, 1, argv, &env->exception);

  if (env->exception) return -1;

  *result = (js_value_t *) error;

  return 0;
}

int
js_typeof (js_env_t *env, js_value_t *value, js_value_type_t *result) {
  return -1;
}

int
js_is_array (js_env_t *env, js_value_t *value, bool *result) {
  *result = JSValueIsArray(env->context, (JSValueRef) value);

  return 0;
}

int
js_is_arraybuffer (js_env_t *env, js_value_t *value, bool *result) {
  return -1;
}

int
js_is_number (js_env_t *env, js_value_t *value, bool *result) {
  *result = JSValueIsNumber(env->context, (JSValueRef) value);

  return 0;
}

int
js_is_bigint (js_env_t *env, js_value_t *value, bool *result) {
  return -1;
}

int
js_is_null (js_env_t *env, js_value_t *value, bool *result) {
  *result = JSValueIsNull(env->context, (JSValueRef) value);

  return 0;
}

int
js_is_undefined (js_env_t *env, js_value_t *value, bool *result) {
  *result = JSValueIsUndefined(env->context, (JSValueRef) value);

  return 0;
}

int
js_is_symbol (js_env_t *env, js_value_t *value, bool *result) {
  *result = JSValueIsSymbol(env->context, (JSValueRef) value);

  return 0;
}

int
js_is_boolean (js_env_t *env, js_value_t *value, bool *result) {
  *result = JSValueIsBoolean(env->context, (JSValueRef) value);

  return 0;
}

int
js_is_external (js_env_t *env, js_value_t *value, bool *result) {
  return -1;
}

int
js_is_string (js_env_t *env, js_value_t *value, bool *result) {
  *result = JSValueIsString(env->context, (JSValueRef) value);

  return 0;
}

int
js_is_function (js_env_t *env, js_value_t *value, bool *result) {
  *result = JSValueIsObject(env->context, (JSValueRef) value) && JSObjectIsFunction(env->context, (JSObjectRef) value);

  return 0;
}

int
js_is_object (js_env_t *env, js_value_t *value, bool *result) {
  *result = JSValueIsObject(env->context, (JSValueRef) value);

  return 0;
}

int
js_is_date (js_env_t *env, js_value_t *value, bool *result) {
  *result = JSValueIsDate(env->context, (JSValueRef) value);

  return 0;
}

int
js_is_error (js_env_t *env, js_value_t *value, bool *result) {
  return -1;
}

int
js_is_typedarray (js_env_t *env, js_value_t *value, bool *result) {
  return -1;
}

int
js_is_dataview (js_env_t *env, js_value_t *value, bool *result) {
  return -1;
}

int
js_is_promise (js_env_t *env, js_value_t *value, bool *result) {
  return -1;
}

int
js_strict_equals (js_env_t *env, js_value_t *a, js_value_t *b, bool *result) {
  *result = JSValueIsStrictEqual(env->context, (JSValueRef) a, (JSValueRef) b);

  return 0;
}

int
js_get_global (js_env_t *env, js_value_t **result) {
  *result = (js_value_t *) JSContextGetGlobalObject(env->context);

  return 0;
}

int
js_get_null (js_env_t *env, js_value_t **result) {
  *result = (js_value_t *) JSValueMakeNull(env->context);

  return 0;
}

int
js_get_undefined (js_env_t *env, js_value_t **result) {
  *result = (js_value_t *) JSValueMakeUndefined(env->context);

  return 0;
}

int
js_get_boolean (js_env_t *env, bool value, js_value_t **result) {
  *result = (js_value_t *) JSValueMakeBoolean(env->context, value);

  return 0;
}

int
js_get_value_int32 (js_env_t *env, js_value_t *value, int32_t *result) {
  double number = JSValueToNumber(env->context, (JSValueRef) value, &env->exception);

  if (env->exception) return -1;

  *result = (int32_t) number;

  return 0;
}

int
js_get_value_uint32 (js_env_t *env, js_value_t *value, uint32_t *result) {
  double number = JSValueToNumber(env->context, (JSValueRef) value, &env->exception);

  if (env->exception) return -1;

  *result = (uint32_t) number;

  return 0;
}

int
js_get_value_string_utf8 (js_env_t *env, js_value_t *value, char *str, size_t len, size_t *result) {
  JSStringRef ref = JSValueToStringCopy(env->context, (JSValueRef) value, &env->exception);

  if (env->exception) return -1;

  len = JSStringGetUTF8CString(ref, str, len);

  if (result != NULL) {
    *result = len;
  }

  JSStringRelease(ref);

  return 0;
}

int
js_get_named_property (js_env_t *env, js_value_t *object, const char *name, js_value_t **result) {
  JSStringRef ref = JSStringCreateWithUTF8CString(name);

  JSValueRef value = JSObjectGetProperty(env->context, (JSObjectRef) object, ref, &env->exception);

  JSStringRelease(ref);

  if (env->exception) return -1;

  *result = (js_value_t *) value;

  return 0;
}

int
js_set_named_property (js_env_t *env, js_value_t *object, const char *name, js_value_t *value) {
  JSStringRef ref = JSStringCreateWithUTF8CString(name);

  JSObjectSetProperty(env->context, (JSObjectRef) object, ref, (JSValueRef) value, kJSPropertyAttributeNone, &env->exception);

  JSStringRelease(ref);

  if (env->exception) return -1;

  return 0;
}

int
js_get_callback_info (js_env_t *env, const js_callback_info_t *info, size_t *argc, js_value_t *argv[], js_value_t **self, void **data) {
  if (argv != NULL) {
    size_t i = 0, n = info->argc < *argc ? info->argc : *argc;

    for (; i < n; i++) {
      argv[i] = (js_value_t *) info->argv[i];
    }

    n = *argc;

    if (i < n) {
      js_value_t *undefined = (js_value_t *) JSValueMakeUndefined(env->context);

      for (; i < n; i++) {
        argv[i] = undefined;
      }
    }
  }

  if (argc != NULL) {
    *argc = info->argc;
  }

  if (self != NULL) {
    *self = (js_value_t *) info->receiver;
  }

  if (data != NULL) {
    *data = info->callback->data;
  }

  return 0;
}

int
js_get_arraybuffer_info (js_env_t *env, js_value_t *arraybuffer, void **pdata, size_t *plen) {
  uint8_t *data = JSObjectGetArrayBufferBytesPtr(env->context, (JSObjectRef) arraybuffer, &env->exception);

  if (env->exception) return -1;

  size_t len = JSObjectGetArrayBufferByteLength(env->context, (JSObjectRef) arraybuffer, &env->exception);

  if (env->exception) return -1;

  if (pdata != NULL) {
    *pdata = data;
  }

  if (plen != NULL) {
    *plen = len;
  }

  return 0;
}

int
js_get_typedarray_info (js_env_t *env, js_value_t *typedarray, js_typedarray_type_t *ptype, void **pdata, size_t *plen, js_value_t **parraybuffer, size_t *poffset) {
  JSObjectRef arraybuffer;

  if (pdata != NULL || parraybuffer != NULL) {
    arraybuffer = JSObjectGetTypedArrayBuffer(env->context, (JSObjectRef) typedarray, &env->exception);

    if (env->exception) return -1;
  }

  if (ptype != NULL) {
    JSTypedArrayType type = JSValueGetTypedArrayType(env->context, (JSValueRef) typedarray, &env->exception);

    if (env->exception) return -1;

    switch (type) {
    case kJSTypedArrayTypeInt8Array:
      *ptype = js_int8_array;
      break;
    case kJSTypedArrayTypeInt16Array:
      *ptype = js_int16_array;
      break;
    case kJSTypedArrayTypeInt32Array:
      *ptype = js_int32_array;
      break;
    case kJSTypedArrayTypeUint8Array:
      *ptype = js_uint8_array;
      break;
    case kJSTypedArrayTypeUint8ClampedArray:
      *ptype = js_uint8_clamped_array;
      break;
    case kJSTypedArrayTypeUint16Array:
      *ptype = js_uint16_array;
      break;
    case kJSTypedArrayTypeUint32Array:
      *ptype = js_uint32_array;
      break;
    case kJSTypedArrayTypeFloat32Array:
      *ptype = js_float32_array;
      break;
    case kJSTypedArrayTypeFloat64Array:
      *ptype = js_float64_array;
      break;
    case kJSTypedArrayTypeBigInt64Array:
      *ptype = js_bigint64_array;
      break;
    case kJSTypedArrayTypeBigUint64Array:
      *ptype = js_biguint64_array;
      break;

    case kJSTypedArrayTypeArrayBuffer:
    case kJSTypedArrayTypeNone:
      break;
    }
  }

  if (pdata != NULL) {
    void *data = JSObjectGetArrayBufferBytesPtr(env->context, arraybuffer, &env->exception);

    if (env->exception) return -1;

    *pdata = data;
  }

  if (plen != NULL) {
    size_t len = JSObjectGetTypedArrayLength(env->context, (JSObjectRef) typedarray, &env->exception);

    if (env->exception) return -1;

    *plen = len;
  }

  if (parraybuffer != NULL) {
    *parraybuffer = (js_value_t *) arraybuffer;
  }

  if (poffset != NULL) {
    size_t offset = JSObjectGetTypedArrayByteOffset(env->context, (JSObjectRef) typedarray, &env->exception);

    if (env->exception) return -1;

    *poffset = offset;
  }

  return 0;
}

int
js_throw (js_env_t *env, js_value_t *error) {
  env->exception = (JSValueRef) error;

  return 0;
}

int
js_is_exception_pending (js_env_t *env, bool *result) {
  *result = env->exception != NULL;

  return 0;
}

int
js_get_and_clear_last_exception (js_env_t *env, js_value_t **result) {
  if (env->exception == NULL) return js_get_undefined(env, result);

  *result = (js_value_t *) env->exception;

  env->exception = NULL;

  return 0;
}

int
js_request_garbage_collection (js_env_t *env) {
  JSGarbageCollect(env->context);

  return 0;
}
