#include <js.h>
#include <js/ffi.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <uv.h>

#include <JavaScriptCore/JavaScriptCore.h>

#include "jsc.h"

typedef struct js_callback_s js_callback_t;
typedef struct js_finalizer_s js_finalizer_t;
typedef struct js_finalizer_list_s js_finalizer_list_t;

struct js_platform_s {
  js_platform_options_t options;
  uv_loop_t *loop;
};

struct js_env_s {
  uv_loop_t *loop;
  js_platform_t *platform;
  uint32_t depth;
  JSContextGroupRef group;
  JSGlobalContextRef context;
  JSValueRef exception;
  int64_t external_memory;
  js_uncaught_exception_cb on_uncaught_exception;
  void *uncaught_exception_data;
  js_unhandled_rejection_cb on_unhandled_rejection;
  void *unhandled_rejection_data;

  struct {
    JSClassRef reference;
    JSClassRef wrap;
    JSClassRef finalizer;
    JSClassRef external;
    JSClassRef function;
  } classes;
};

struct js_ref_s {
  JSObjectRef value;
  uint32_t count;
};

struct js_deferred_s {
  JSObjectRef resolve;
  JSObjectRef reject;
};

struct js_finalizer_s {
  js_env_t *env;
  void *data;
  js_finalize_cb cb;
  void *hint;
};

struct js_finalizer_list_s {
  js_finalizer_t finalizer;
  js_finalizer_list_t *next;
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

const char *js_platform_identifier = "javascriptcore";

const char *js_platform_version = NULL;

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

static void
on_uncaught_exception (js_env_t *env, js_value_t *error) {
  if (env->on_uncaught_exception) {
    env->on_uncaught_exception(env, error, env->uncaught_exception_data);
  } else {
    env->exception = error;
  }
}

static js_value_t *
on_unhandled_rejection (js_env_t *env, js_callback_info_t *info) {
  if (env->on_unhandled_rejection) {
    size_t argc = 2;
    js_value_t *argv[2];

    js_get_callback_info(env, info, &argc, argv, NULL, NULL);

    env->on_unhandled_rejection(env, argv[1], argv[0], env->unhandled_rejection_data);
  }

  return NULL;
}

static void
on_reference_finalize (JSObjectRef external);

static void
on_wrap_finalize (JSObjectRef external);

static void
on_finalizer_finalize (JSObjectRef external);

static void
on_function_finalize (JSObjectRef external);

static void
on_external_finalize (JSObjectRef external);

int
js_create_env (uv_loop_t *loop, js_platform_t *platform, js_env_t **result) {
  JSContextGroupRef group = JSContextGroupCreate();

  JSGlobalContextRef context = JSGlobalContextCreateInGroup(group, NULL);

  js_env_t *env = malloc(sizeof(js_env_t));

  env->loop = loop;
  env->platform = platform;
  env->depth = 0;
  env->group = group;
  env->context = context;
  env->exception = NULL;
  env->external_memory = 0;

  env->on_uncaught_exception = NULL;
  env->uncaught_exception_data = NULL;
  env->on_unhandled_rejection = NULL;
  env->unhandled_rejection_data = NULL;

  env->classes.reference = JSClassCreate(&(JSClassDefinition){
    .finalize = on_reference_finalize,
  });

  env->classes.wrap = JSClassCreate(&(JSClassDefinition){
    .finalize = on_wrap_finalize,
  });

  env->classes.finalizer = JSClassCreate(&(JSClassDefinition){
    .finalize = on_finalizer_finalize,
  });

  env->classes.function = JSClassCreate(&(JSClassDefinition){
    .finalize = on_function_finalize,
  });

  env->classes.external = JSClassCreate(&(JSClassDefinition){
    .finalize = on_external_finalize,
  });

  js_value_t *fn;
  js_create_function(env, "onunhandledrejection", -1, on_unhandled_rejection, NULL, &fn);

  JSGlobalContextSetUnhandledRejectionCallback(context, (JSObjectRef) fn, NULL);

  *result = env;

  return 0;
}

int
js_destroy_env (js_env_t *env) {
  JSClassRelease(env->classes.reference);
  JSClassRelease(env->classes.wrap);
  JSClassRelease(env->classes.finalizer);
  JSClassRelease(env->classes.function);
  JSClassRelease(env->classes.external);

  JSGlobalContextRelease(env->context);
  JSContextGroupRelease(env->group);

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
js_on_unhandled_rejection (js_env_t *env, js_unhandled_rejection_cb cb, void *data) {
  env->on_unhandled_rejection = cb;
  env->unhandled_rejection_data = data;

  return 0;
}

int
js_on_dynamic_import (js_env_t *env, js_dynamic_import_cb cb, void *data) {
  return 0;
}

int
js_get_env_loop (js_env_t *env, uv_loop_t **result) {
  *result = env->loop;

  return 0;
}

int
js_get_env_platform (js_env_t *env, js_platform_t **result) {
  *result = env->platform;

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
js_run_script (js_env_t *env, const char *file, size_t len, int offset, js_value_t *source, js_value_t **result) {
  JSStringRef ref = JSValueToStringCopy(env->context, (JSValueRef) source, &env->exception);

  if (env->exception) return -1;

  env->depth++;

  if (file == NULL) file = "";

  JSStringRef url = JSStringCreateWithUTF8CString(file);

  JSValueRef value = JSEvaluateScript(env->context, ref, NULL, url, offset + 1, &env->exception);

  env->depth--;

  JSStringRelease(ref);
  JSStringRelease(url);

  if (env->exception) {
    if (env->depth == 0) {
      JSValueRef error = env->exception;

      env->exception = NULL;

      on_uncaught_exception(env, (js_value_t *) error);
    }

    return -1;
  }

  if (result) {
    *result = (js_value_t *) value;
  }

  return 0;
}

int
js_create_module (js_env_t *env, const char *name, size_t len, int offset, js_value_t *source, js_module_t **result) {
  js_throw_error(env, NULL, "Unsupported operation");

  return -1;
}

int
js_create_synthetic_module (js_env_t *env, const char *name, size_t len, js_value_t *const export_names[], size_t names_len, js_synthetic_module_cb cb, void *data, js_module_t **result) {
  js_throw_error(env, NULL, "Unsupported operation");

  return -1;
}

int
js_delete_module (js_env_t *env, js_module_t *module) {
  js_throw_error(env, NULL, "Unsupported operation");

  return -1;
}

int
js_get_module_name (js_env_t *env, js_module_t *module, const char **result) {
  js_throw_error(env, NULL, "Unsupported operation");

  return -1;
}

int
js_get_module_namespace (js_env_t *env, js_module_t *module, js_value_t **result) {
  js_throw_error(env, NULL, "Unsupported operation");

  return -1;
}

int
js_set_module_export (js_env_t *env, js_module_t *module, js_value_t *name, js_value_t *value) {
  js_throw_error(env, NULL, "Unsupported operation");

  return -1;
}

int
js_instantiate_module (js_env_t *env, js_module_t *module, js_module_cb cb, void *data) {
  js_throw_error(env, NULL, "Unsupported operation");

  return -1;
}

int
js_run_module (js_env_t *env, js_module_t *module, js_value_t **result) {
  js_throw_error(env, NULL, "Unsupported operation");

  return -1;
}

static void
on_reference_finalize (JSObjectRef external) {
  js_ref_t *reference = (js_ref_t *) JSObjectGetPrivate(external);

  if (reference) reference->value = NULL;
}

int
js_create_reference (js_env_t *env, js_value_t *value, uint32_t count, js_ref_t **result) {
  js_ref_t *reference = malloc(sizeof(js_ref_t));

  reference->value = (JSObjectRef) value;
  reference->count = count;

  if (reference->count > 0) JSValueProtect(env->context, reference->value);

  JSObjectRef external = JSObjectMake(env->context, env->classes.reference, (void *) reference);

  JSStringRef ref = JSStringCreateWithUTF8CString("__native_reference");

  JSObjectSetProperty(
    env->context,
    reference->value,
    ref,
    external,
    kJSPropertyAttributeDontEnum,
    NULL
  );

  JSStringRelease(ref);

  *result = reference;

  return 0;
}

int
js_delete_reference (js_env_t *env, js_ref_t *reference) {
  JSStringRef ref = JSStringCreateWithUTF8CString("__native_reference");

  JSValueRef external = JSObjectGetProperty(env->context, reference->value, ref, NULL);

  JSStringRelease(ref);

  JSObjectSetPrivate((JSObjectRef) external, NULL);

  JSObjectDeleteProperty(
    env->context,
    (JSObjectRef) reference->value,
    ref,
    NULL
  );

  if (reference->count > 0) JSValueUnprotect(env->context, reference->value);

  free(reference);

  return 0;
}

int
js_reference_ref (js_env_t *env, js_ref_t *reference, uint32_t *result) {
  reference->count++;

  if (reference->count == 1) JSValueProtect(env->context, reference->value);

  if (result) {
    *result = reference->count;
  }

  return 0;
}

int
js_reference_unref (js_env_t *env, js_ref_t *reference, uint32_t *result) {
  if (reference->count == 0) {
    js_throw_error(env, NULL, "Cannot decrease reference count");

    return -1;
  }

  reference->count--;

  if (reference->count == 0) JSValueUnprotect(env->context, reference->value);

  if (result) {
    *result = reference->count;
  }

  return 0;
}

int
js_get_reference_value (js_env_t *env, js_ref_t *reference, js_value_t **result) {
  *result = (js_value_t *) reference->value;

  return 0;
}

static void
on_wrap_finalize (JSObjectRef external) {
  js_finalizer_t *finalizer = (js_finalizer_t *) JSObjectGetPrivate(external);

  if (finalizer->cb) {
    finalizer->cb(finalizer->env, finalizer->data, finalizer->hint);
  }

  free(finalizer);
}

int
js_wrap (js_env_t *env, js_value_t *object, void *data, js_finalize_cb finalize_cb, void *finalize_hint, js_ref_t **result) {
  js_finalizer_t *finalizer = malloc(sizeof(js_finalizer_t));

  finalizer->env = env;
  finalizer->data = data;
  finalizer->cb = finalize_cb;
  finalizer->hint = finalize_hint;

  JSObjectRef external = JSObjectMake(env->context, env->classes.wrap, (void *) finalizer);

  JSStringRef ref = JSStringCreateWithUTF8CString("__native_external");

  JSObjectSetProperty(
    env->context,
    (JSObjectRef) object,
    ref,
    external,
    kJSPropertyAttributeReadOnly | kJSPropertyAttributeDontEnum,
    NULL
  );

  JSStringRelease(ref);

  if (result) js_create_reference(env, object, 0, result);

  return 0;
}

int
js_unwrap (js_env_t *env, js_value_t *object, void **result) {
  JSStringRef ref = JSStringCreateWithUTF8CString("__native_external");

  JSValueRef external = JSObjectGetProperty(env->context, (JSObjectRef) object, ref, NULL);

  JSStringRelease(ref);

  js_finalizer_t *finalizer = (js_finalizer_t *) JSObjectGetPrivate((JSObjectRef) external);

  *result = finalizer->data;

  return 0;
}

int
js_remove_wrap (js_env_t *env, js_value_t *object, void **result) {
  JSStringRef ref = JSStringCreateWithUTF8CString("__native_external");

  JSValueRef external = JSObjectGetProperty(env->context, (JSObjectRef) object, ref, NULL);

  js_finalizer_t *finalizer = (js_finalizer_t *) JSObjectGetPrivate((JSObjectRef) external);

  finalizer->cb = NULL;

  if (result) {
    *result = finalizer->data;
  }

  JSObjectDeleteProperty(env->context, (JSObjectRef) object, ref, NULL);

  JSStringRelease(ref);

  return 0;
}

static void
on_finalizer_finalize (JSObjectRef external) {
  js_finalizer_list_t *next = (js_finalizer_list_t *) JSObjectGetPrivate(external);

  js_finalizer_list_t *prev = NULL;

  while (next) {
    js_finalizer_t *finalizer = &next->finalizer;

    if (finalizer->cb) {
      finalizer->cb(finalizer->env, finalizer->data, finalizer->hint);
    }

    prev = next;
    next = next->next;

    free(prev);
  }
}

int
js_add_finalizer (js_env_t *env, js_value_t *object, void *data, js_finalize_cb finalize_cb, void *finalize_hint, js_ref_t **result) {
  js_finalizer_list_t *prev = malloc(sizeof(js_finalizer_list_t));

  js_finalizer_t *finalizer = &prev->finalizer;

  finalizer->env = env;
  finalizer->data = data;
  finalizer->cb = finalize_cb;
  finalizer->hint = finalize_hint;

  JSStringRef ref = JSStringCreateWithUTF8CString("__native_finalizer");

  JSObjectRef external;

  if (JSObjectHasProperty(env->context, (JSObjectRef) object, ref)) {
    external = (JSObjectRef) JSObjectGetProperty(env->context, (JSObjectRef) object, ref, NULL);
  } else {
    external = JSObjectMake(env->context, env->classes.finalizer, NULL);

    JSObjectSetProperty(
      env->context,
      (JSObjectRef) object,
      ref,
      external,
      kJSPropertyAttributeReadOnly | kJSPropertyAttributeDontEnum | kJSPropertyAttributeDontDelete,
      NULL
    );
  }

  JSStringRelease(ref);

  prev->next = (js_finalizer_list_t *) JSObjectGetPrivate(external);

  JSObjectSetPrivate(external, (void *) prev);

  if (result) js_create_reference(env, object, 0, result);

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
js_create_int64 (js_env_t *env, int64_t value, js_value_t **result) {
  *result = (js_value_t *) JSValueMakeNumber(env->context, (double) value);

  return 0;
}

int
js_create_double (js_env_t *env, double value, js_value_t **result) {
  *result = (js_value_t *) JSValueMakeNumber(env->context, value);

  return 0;
}

int
js_create_bigint_int64 (js_env_t *env, int64_t value, js_value_t **result) {
  JSObjectRef global = JSContextGetGlobalObject(env->context);

  JSStringRef ref = JSStringCreateWithUTF8CString("BigInt");

  JSValueRef constructor = JSObjectGetProperty(env->context, global, ref, &env->exception);

  JSStringRelease(ref);

  if (env->exception) return -1;

  JSValueRef argv[] = {JSValueMakeNumber(env->context, (double) value)};

  *result = (js_value_t *) JSObjectCallAsFunction(env->context, (JSObjectRef) constructor, global, 1, argv, &env->exception);

  if (env->exception) return -1;

  return 0;
}

int
js_create_bigint_uint64 (js_env_t *env, uint64_t value, js_value_t **result) {
  JSObjectRef global = JSContextGetGlobalObject(env->context);

  JSStringRef ref = JSStringCreateWithUTF8CString("BigInt");

  JSValueRef constructor = JSObjectGetProperty(env->context, global, ref, &env->exception);

  JSStringRelease(ref);

  if (env->exception) return -1;

  JSValueRef argv[] = {JSValueMakeNumber(env->context, (double) value)};

  *result = (js_value_t *) JSObjectCallAsFunction(env->context, (JSObjectRef) constructor, global, 1, argv, &env->exception);

  if (env->exception) return -1;

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
js_create_symbol (js_env_t *env, js_value_t *description, js_value_t **result) {
  JSStringRef ref = JSValueToStringCopy(env->context, (JSValueRef) description, &env->exception);

  if (env->exception) return -1;

  *result = (js_value_t *) JSValueMakeSymbol(env->context, ref);

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

int
js_create_function (js_env_t *env, const char *name, size_t len, js_function_cb cb, void *data, js_value_t **result) {
  JSStringRef ref;

  if (len == (size_t) -1) {
    ref = JSStringCreateWithUTF8CString(name);
  } else if (name) {
    char *copy = strndup(name, len);

    ref = JSStringCreateWithUTF8CString(name);

    free(copy);
  } else {
    ref = NULL;
  }

  JSObjectRef function = JSObjectMakeFunctionWithCallback(env->context, ref, on_function_call);

  if (ref) JSStringRelease(ref);

  js_callback_t *callback = malloc(sizeof(js_callback_t));

  callback->env = env;
  callback->cb = cb;
  callback->data = data;

  JSObjectRef external = JSObjectMake(env->context, env->classes.function, (void *) callback);

  ref = JSStringCreateWithUTF8CString("__native_function");

  JSObjectSetProperty(
    env->context,
    function,
    ref,
    external,
    kJSPropertyAttributeReadOnly | kJSPropertyAttributeDontEnum | kJSPropertyAttributeDontDelete,
    NULL
  );

  JSStringRelease(ref);

  *result = (js_value_t *) function;

  return 0;
}

int
js_create_function_with_source (js_env_t *env, const char *name, size_t name_len, const char *file, size_t file_len, js_value_t *const args[], size_t args_len, int offset, js_value_t *source, js_value_t **result) {
  JSStringRef name_ref, file_ref;

  if (name_len == (size_t) -1) {
    name_ref = JSStringCreateWithUTF8CString(name);
  } else if (name) {
    char *copy = strndup(name, name_len);

    name_ref = JSStringCreateWithUTF8CString(name);

    free(copy);
  } else {
    name_ref = NULL;
  }

  if (file_len == (size_t) -1) {
    file_ref = JSStringCreateWithUTF8CString(file);
  } else if (file) {
    char *copy = strndup(file, file_len);

    file_ref = JSStringCreateWithUTF8CString(file);

    free(copy);
  } else {
    file = NULL;
  }

  JSStringRef *arg_refs = malloc(sizeof(JSStringRef) * args_len);

  for (int i = 0; i < args_len; i++) {
    arg_refs[i] = JSValueToStringCopy(env->context, (JSValueRef) args[i], NULL);
  }

  JSStringRef source_ref = JSValueToStringCopy(env->context, (JSValueRef) source, NULL);

  JSObjectRef function = JSObjectMakeFunction(env->context, name_ref, args_len, arg_refs, source_ref, file_ref, offset, &env->exception);

  if (name_ref) JSStringRelease(name_ref);
  if (file_ref) JSStringRelease(file_ref);

  for (int i = 0; i < args_len; i++) {
    JSStringRelease(arg_refs[i]);
  }

  JSStringRelease(source_ref);

  if (env->exception) return -1;

  *result = (js_value_t *) function;

  return 0;
}

int
js_create_function_with_ffi (js_env_t *env, const char *name, size_t len, js_function_cb cb, void *data, js_ffi_function_t *ffi, js_value_t **result) {
  return js_create_function(env, name, len, cb, data, result);
}

int
js_create_array (js_env_t *env, js_value_t **result) {
  *result = (js_value_t *) JSObjectMakeArray(env->context, 0, NULL, &env->exception);

  if (env->exception) return -1;

  return 0;
}

int
js_create_array_with_length (js_env_t *env, size_t len, js_value_t **result) {
  JSValueRef argv[1] = {JSValueMakeNumber(env->context, (double) len)};

  *result = (js_value_t *) JSObjectMakeArray(env->context, 1, argv, &env->exception);

  if (env->exception) return -1;

  return 0;
}

static void
on_external_finalize (JSObjectRef external) {
  js_finalizer_t *finalizer = (js_finalizer_t *) JSObjectGetPrivate(external);

  if (finalizer->cb) {
    finalizer->cb(finalizer->env, finalizer->data, finalizer->hint);
  }

  free(finalizer);
}

int
js_create_external (js_env_t *env, void *data, js_finalize_cb finalize_cb, void *finalize_hint, js_value_t **result) {
  js_finalizer_t *finalizer = malloc(sizeof(js_finalizer_t));

  finalizer->env = env;
  finalizer->data = data;
  finalizer->cb = finalize_cb;
  finalizer->hint = finalize_hint;

  JSObjectRef external = JSObjectMake(env->context, env->classes.external, (void *) finalizer);

  *result = (js_value_t *) external;

  return 0;
}

int
js_create_date (js_env_t *env, double time, js_value_t **result) {
  JSObjectRef global = JSContextGetGlobalObject(env->context);

  JSStringRef ref = JSStringCreateWithUTF8CString("Date");

  JSValueRef constructor = JSObjectGetProperty(env->context, global, ref, &env->exception);

  JSStringRelease(ref);

  if (env->exception) return -1;

  JSValueRef argv[] = {JSValueMakeNumber(env->context, (double) time)};

  *result = (js_value_t *) JSObjectCallAsConstructor(env->context, (JSObjectRef) constructor, 1, argv, &env->exception);

  if (env->exception) return -1;

  return 0;
}

int
js_create_error (js_env_t *env, js_value_t *code, js_value_t *message, js_value_t **result) {
  JSValueRef argv[1] = {(JSValueRef) message};

  JSObjectRef error = JSObjectMakeError(env->context, 1, argv, &env->exception);

  if (env->exception) return -1;

  if (code) {
    JSStringRef ref = JSStringCreateWithUTF8CString("code");

    JSObjectSetProperty(
      env->context,
      error,
      ref,
      (JSValueRef) code,
      kJSPropertyAttributeNone,
      &env->exception
    );

    JSStringRelease(ref);

    if (env->exception) return -1;
  }

  *result = (js_value_t *) error;

  return 0;
}

int
js_create_type_error (js_env_t *env, js_value_t *code, js_value_t *message, js_value_t **result) {
  JSObjectRef global = JSContextGetGlobalObject(env->context);

  JSStringRef ref = JSStringCreateWithUTF8CString("TypeError");

  JSValueRef constructor = JSObjectGetProperty(env->context, global, ref, &env->exception);

  JSStringRelease(ref);

  if (env->exception) return -1;

  JSValueRef argv[1] = {(JSValueRef) message};

  JSObjectRef error = JSObjectCallAsConstructor(env->context, (JSObjectRef) constructor, 1, argv, &env->exception);

  if (env->exception) return -1;

  if (code) {
    JSStringRef ref = JSStringCreateWithUTF8CString("code");

    JSObjectSetProperty(
      env->context,
      error,
      ref,
      (JSValueRef) code,
      kJSPropertyAttributeNone,
      &env->exception
    );

    JSStringRelease(ref);

    if (env->exception) return -1;
  }

  *result = (js_value_t *) error;

  return 0;
}

int
js_create_range_error (js_env_t *env, js_value_t *code, js_value_t *message, js_value_t **result) {
  JSObjectRef global = JSContextGetGlobalObject(env->context);

  JSStringRef ref = JSStringCreateWithUTF8CString("RangeError");

  JSValueRef constructor = JSObjectGetProperty(env->context, global, ref, &env->exception);

  JSStringRelease(ref);

  if (env->exception) return -1;

  JSValueRef argv[1] = {(JSValueRef) message};

  JSObjectRef error = JSObjectCallAsConstructor(env->context, (JSObjectRef) constructor, 1, argv, &env->exception);

  if (env->exception) return -1;

  if (code) {
    JSStringRef ref = JSStringCreateWithUTF8CString("code");

    JSObjectSetProperty(
      env->context,
      error,
      ref,
      (JSValueRef) code,
      kJSPropertyAttributeNone,
      &env->exception
    );

    JSStringRelease(ref);

    if (env->exception) return -1;
  }

  *result = (js_value_t *) error;

  return 0;
}

int
js_create_syntax_error (js_env_t *env, js_value_t *code, js_value_t *message, js_value_t **result) {
  JSObjectRef global = JSContextGetGlobalObject(env->context);

  JSStringRef ref = JSStringCreateWithUTF8CString("SyntaxError");

  JSValueRef constructor = JSObjectGetProperty(env->context, global, ref, &env->exception);

  JSStringRelease(ref);

  if (env->exception) return -1;

  JSValueRef argv[1] = {(JSValueRef) message};

  JSObjectRef error = JSObjectCallAsConstructor(env->context, (JSObjectRef) constructor, 1, argv, &env->exception);

  if (env->exception) return -1;

  if (code) {
    JSStringRef ref = JSStringCreateWithUTF8CString("code");

    JSObjectSetProperty(
      env->context,
      error,
      ref,
      (JSValueRef) code,
      kJSPropertyAttributeNone,
      &env->exception
    );

    JSStringRelease(ref);

    if (env->exception) return -1;
  }

  *result = (js_value_t *) error;

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

// https://bugs.webkit.org/show_bug.cgi?id=250554
int
js_get_promise_state (js_env_t *env, js_value_t *promise, js_promise_state_t *result) {
  js_throw_error(env, NULL, "Unsupported operation");

  return -1;
}

// https://bugs.webkit.org/show_bug.cgi?id=250554
int
js_get_promise_result (js_env_t *env, js_value_t *promise, js_value_t **result) {
  js_throw_error(env, NULL, "Unsupported operation");

  return -1;
}

int
js_create_arraybuffer (js_env_t *env, size_t len, void **data, js_value_t **result) {
  JSObjectRef typedarray = JSObjectMakeTypedArray(env->context, kJSTypedArrayTypeUint8Array, len, &env->exception);

  if (env->exception) return -1;

  JSObjectRef arraybuffer = JSObjectGetTypedArrayBuffer(env->context, typedarray, &env->exception);

  if (env->exception) return -1;

  *result = (js_value_t *) arraybuffer;

  if (data) {
    *data = JSObjectGetArrayBufferBytesPtr(env->context, arraybuffer, &env->exception);

    if (env->exception) return -1;
  }

  return 0;
}

static void
on_unsafe_arraybuffer_finalize (void *bytes, void *deallocatorContext) {
  free(bytes);
}

int
js_create_unsafe_arraybuffer (js_env_t *env, size_t len, void **data, js_value_t **result) {
  void *bytes = malloc(len);

  JSObjectRef arraybuffer = JSObjectMakeArrayBufferWithBytesNoCopy(env->context, bytes, len, on_unsafe_arraybuffer_finalize, NULL, &env->exception);

  if (env->exception) {
    free(bytes);

    return -1;
  }

  *result = (js_value_t *) arraybuffer;

  if (data) {
    *data = bytes;
  }

  return 0;
}

static void
on_external_arraybuffer_finalize (void *bytes, void *deallocatorContext) {
  js_finalizer_t *finalizer = (js_finalizer_t *) deallocatorContext;

  if (finalizer->cb) {
    finalizer->cb(finalizer->env, finalizer->data, finalizer->hint);
  }

  free(finalizer);
}

int
js_create_external_arraybuffer (js_env_t *env, void *data, size_t len, js_finalize_cb finalize_cb, void *finalize_hint, js_value_t **result) {
  js_finalizer_t *finalizer = malloc(sizeof(js_finalizer_t));

  finalizer->env = env;
  finalizer->data = data;
  finalizer->cb = finalize_cb;
  finalizer->hint = finalize_hint;

  JSObjectRef arraybuffer = JSObjectMakeArrayBufferWithBytesNoCopy(env->context, data, len, on_external_arraybuffer_finalize, (void *) finalizer, &env->exception);

  if (env->exception) {
    free(finalizer);

    return -1;
  }

  *result = (js_value_t *) arraybuffer;

  return 0;
}

// https://bugs.webkit.org/show_bug.cgi?id=250552
int
js_detach_arraybuffer (js_env_t *env, js_value_t *arraybuffer) {
  js_throw_error(env, NULL, "Unsupported operation");

  return -1;
}

int
js_set_arraybuffer_zero_fill_enabled (bool enabled) {
  return 0;
}

static inline JSTypedArrayType
js_convert_from_typedarray_type (js_typedarray_type_t type) {
  switch (type) {
  case js_int8_array:
    return kJSTypedArrayTypeInt8Array;
  case js_uint8_array:
    return kJSTypedArrayTypeUint8Array;
  case js_uint8_clamped_array:
    return kJSTypedArrayTypeUint8ClampedArray;
  case js_int16_array:
    return kJSTypedArrayTypeInt16Array;
  case js_uint16_array:
    return kJSTypedArrayTypeUint16Array;
  case js_int32_array:
    return kJSTypedArrayTypeInt32Array;
  case js_uint32_array:
    return kJSTypedArrayTypeUint32Array;
  case js_float32_array:
    return kJSTypedArrayTypeFloat32Array;
  case js_float64_array:
    return kJSTypedArrayTypeFloat64Array;
  case js_bigint64_array:
    return kJSTypedArrayTypeBigInt64Array;
  case js_biguint64_array:
    return kJSTypedArrayTypeBigUint64Array;
  }
}

static inline js_typedarray_type_t
js_convert_to_typedarray_type (JSTypedArrayType type) {
  switch (type) {
  case kJSTypedArrayTypeInt8Array:
    return js_int8_array;
  case kJSTypedArrayTypeInt16Array:
    return js_int16_array;
    break;
  case kJSTypedArrayTypeInt32Array:
    return js_int32_array;
  case kJSTypedArrayTypeUint8Array:
    return js_uint8_array;
  case kJSTypedArrayTypeUint8ClampedArray:
    return js_uint8_clamped_array;
  case kJSTypedArrayTypeUint16Array:
    return js_uint16_array;
  case kJSTypedArrayTypeUint32Array:
    return js_uint32_array;
  case kJSTypedArrayTypeFloat32Array:
    return js_float32_array;
  case kJSTypedArrayTypeFloat64Array:
    return js_float64_array;
  case kJSTypedArrayTypeBigInt64Array:
    return js_bigint64_array;
  case kJSTypedArrayTypeBigUint64Array:
    return js_biguint64_array;

  case kJSTypedArrayTypeArrayBuffer:
  case kJSTypedArrayTypeNone:
    return -1;
  }
}

int
js_create_typedarray (js_env_t *env, js_typedarray_type_t type, size_t len, js_value_t *arraybuffer, size_t offset, js_value_t **result) {
  JSObjectRef typedarray = JSObjectMakeTypedArrayWithArrayBufferAndOffset(
    env->context,
    js_convert_from_typedarray_type(type),
    (JSObjectRef) arraybuffer,
    offset,
    len,
    &env->exception
  );

  if (env->exception) return -1;

  *result = (js_value_t *) typedarray;

  return 0;
}

int
js_create_dataview (js_env_t *env, size_t len, js_value_t *arraybuffer, size_t offset, js_value_t **result) {
  JSStringRef ref = JSStringCreateWithUTF8CString("DataView");

  JSValueRef constructor = JSObjectGetProperty(env->context, JSContextGetGlobalObject(env->context), ref, &env->exception);

  JSStringRelease(ref);

  if (env->exception) return -1;

  JSValueRef argv[3] = {(JSValueRef) arraybuffer, JSValueMakeNumber(env->context, offset), JSValueMakeNumber(env->context, len)};

  JSObjectRef dataview = JSObjectCallAsConstructor(env->context, (JSObjectRef) constructor, 3, argv, &env->exception);

  if (env->exception) return -1;

  *result = (js_value_t *) dataview;

  return 0;
}

// https://bugs.webkit.org/show_bug.cgi?id=250511
int
js_typeof (js_env_t *env, js_value_t *value, js_value_type_t *result) {
  JSType type = JSValueGetType(env->context, (JSValueRef) value);

  switch (type) {
  case kJSTypeUndefined:
    *result = js_undefined;
    break;
  case kJSTypeNull:
    *result = js_null;
    break;
  case kJSTypeBoolean:
    *result = js_boolean;
    break;
  case kJSTypeNumber:
    *result = js_number;
    break;
  case kJSTypeString:
    *result = js_string;
    break;
  case kJSTypeObject:
    *result = JSObjectIsFunction(env->context, (JSObjectRef) value)
                ? js_function
              : JSValueIsObjectOfClass(env->context, (JSValueRef) value, env->classes.external)
                ? js_external
                : js_object;
    break;
  case kJSTypeSymbol:
    *result = js_symbol;
    break;
  }

  return 0;
}

int
js_is_undefined (js_env_t *env, js_value_t *value, bool *result) {
  *result = JSValueIsUndefined(env->context, (JSValueRef) value);

  return 0;
}

int
js_is_null (js_env_t *env, js_value_t *value, bool *result) {
  *result = JSValueIsNull(env->context, (JSValueRef) value);

  return 0;
}

int
js_is_boolean (js_env_t *env, js_value_t *value, bool *result) {
  *result = JSValueIsBoolean(env->context, (JSValueRef) value);

  return 0;
}

int
js_is_number (js_env_t *env, js_value_t *value, bool *result) {
  *result = JSValueIsNumber(env->context, (JSValueRef) value);

  return 0;
}

int
js_is_string (js_env_t *env, js_value_t *value, bool *result) {
  *result = JSValueIsString(env->context, (JSValueRef) value);

  return 0;
}

int
js_is_symbol (js_env_t *env, js_value_t *value, bool *result) {
  *result = JSValueIsSymbol(env->context, (JSValueRef) value);

  return 0;
}

int
js_is_object (js_env_t *env, js_value_t *value, bool *result) {
  *result = JSValueIsObject(env->context, (JSValueRef) value);

  return 0;
}

int
js_is_function (js_env_t *env, js_value_t *value, bool *result) {
  *result = JSValueIsObject(env->context, (JSValueRef) value) && JSObjectIsFunction(env->context, (JSObjectRef) value);

  return 0;
}

int
js_is_array (js_env_t *env, js_value_t *value, bool *result) {
  *result = JSValueIsArray(env->context, (JSValueRef) value);

  return 0;
}

int
js_is_external (js_env_t *env, js_value_t *value, bool *result) {
  *result = JSValueIsObjectOfClass(env->context, (JSValueRef) value, env->classes.external);

  return 0;
}

// https://bugs.webkit.org/show_bug.cgi?id=250511
int
js_is_bigint (js_env_t *env, js_value_t *value, bool *result) {
  js_throw_error(env, NULL, "Unsupported operation");

  return -1;
}

int
js_is_date (js_env_t *env, js_value_t *value, bool *result) {
  *result = JSValueIsDate(env->context, (JSValueRef) value);

  return 0;
}

int
js_is_error (js_env_t *env, js_value_t *value, bool *result) {
  JSStringRef ref = JSStringCreateWithUTF8CString("Error");

  JSValueRef constructor = JSObjectGetProperty(env->context, JSContextGetGlobalObject(env->context), ref, &env->exception);

  JSStringRelease(ref);

  if (env->exception) return -1;

  *result = JSValueIsInstanceOfConstructor(env->context, (JSValueRef) value, (JSObjectRef) constructor, &env->exception);

  if (env->exception) return -1;

  return 0;
}

int
js_is_promise (js_env_t *env, js_value_t *value, bool *result) {
  JSStringRef ref = JSStringCreateWithUTF8CString("Promise");

  JSValueRef constructor = JSObjectGetProperty(env->context, JSContextGetGlobalObject(env->context), ref, &env->exception);

  JSStringRelease(ref);

  if (env->exception) return -1;

  *result = JSValueIsInstanceOfConstructor(env->context, (JSValueRef) value, (JSObjectRef) constructor, &env->exception);

  if (env->exception) return -1;

  return 0;
}

int
js_is_arraybuffer (js_env_t *env, js_value_t *value, bool *result) {
  JSTypedArrayType type = JSValueGetTypedArrayType(env->context, (JSValueRef) value, &env->exception);

  if (env->exception) return -1;

  *result = type == kJSTypedArrayTypeArrayBuffer;

  return 0;
}

// https://bugs.webkit.org/show_bug.cgi?id=250552
int
js_is_detached_arraybuffer (js_env_t *env, js_value_t *value, bool *result) {
  *result = false;

  return 0;
}

int
js_is_typedarray (js_env_t *env, js_value_t *value, bool *result) {
  JSTypedArrayType type = JSValueGetTypedArrayType(env->context, (JSValueRef) value, &env->exception);

  if (env->exception) return -1;

  *result = type != kJSTypedArrayTypeNone && type != kJSTypedArrayTypeArrayBuffer;

  return 0;
}

int
js_is_dataview (js_env_t *env, js_value_t *value, bool *result) {
  JSStringRef ref = JSStringCreateWithUTF8CString("DataView");

  JSValueRef constructor = JSObjectGetProperty(env->context, JSContextGetGlobalObject(env->context), ref, &env->exception);

  JSStringRelease(ref);

  if (env->exception) return -1;

  *result = JSValueIsInstanceOfConstructor(env->context, (JSValueRef) value, (JSObjectRef) constructor, &env->exception);

  if (env->exception) return -1;

  return 0;
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
js_get_undefined (js_env_t *env, js_value_t **result) {
  *result = (js_value_t *) JSValueMakeUndefined(env->context);

  return 0;
}

int
js_get_null (js_env_t *env, js_value_t **result) {
  *result = (js_value_t *) JSValueMakeNull(env->context);

  return 0;
}

int
js_get_boolean (js_env_t *env, bool value, js_value_t **result) {
  *result = (js_value_t *) JSValueMakeBoolean(env->context, value);

  return 0;
}

int
js_get_value_bool (js_env_t *env, js_value_t *value, bool *result) {
  *result = JSValueToBoolean(env->context, (JSValueRef) value);

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
js_get_value_int64 (js_env_t *env, js_value_t *value, int64_t *result) {
  double number = JSValueToNumber(env->context, (JSValueRef) value, &env->exception);

  if (env->exception) return -1;

  *result = (int64_t) number;

  return 0;
}

int
js_get_value_double (js_env_t *env, js_value_t *value, double *result) {
  double number = JSValueToNumber(env->context, (JSValueRef) value, &env->exception);

  if (env->exception) return -1;

  *result = number;

  return 0;
}

// https://bugs.webkit.org/show_bug.cgi?id=250511
int
js_get_value_bigint_int64 (js_env_t *env, js_value_t *value, int64_t *result) {
  js_throw_error(env, NULL, "Unsupported operation");

  return -1;
}

// https://bugs.webkit.org/show_bug.cgi?id=250511
int
js_get_value_bigint_uint64 (js_env_t *env, js_value_t *value, uint64_t *result) {
  js_throw_error(env, NULL, "Unsupported operation");

  return -1;
}

int
js_get_value_string_utf8 (js_env_t *env, js_value_t *value, char *str, size_t len, size_t *result) {
  JSStringRef ref = JSValueToStringCopy(env->context, (JSValueRef) value, &env->exception);

  if (env->exception) return -1;

  if (str == NULL) {
    *result = JSStringGetMaximumUTF8CStringSize(ref) - 1 /* NULL */;
  } else if (len != 0) {
    len = JSStringGetUTF8CString(ref, str, len) - 1 /* NULL */;

    if (result) {
      *result = len;
    }
  } else if (result) {
    *result = 0;
  }

  JSStringRelease(ref);

  return 0;
}

int
js_get_value_external (js_env_t *env, js_value_t *value, void **result) {
  js_finalizer_t *finalizer = (js_finalizer_t *) JSObjectGetPrivate((JSObjectRef) value);

  *result = finalizer->data;

  return 0;
}

int
js_get_value_date (js_env_t *env, js_value_t *value, double *result) {
  *result = JSValueToNumber(env->context, (JSValueRef) value, &env->exception);

  if (env->exception) return -1;

  return 0;
}

int
js_get_array_length (js_env_t *env, js_value_t *value, uint32_t *result) {
  JSStringRef ref = JSStringCreateWithUTF8CString("length");

  JSValueRef length = JSObjectGetProperty(env->context, (JSObjectRef) value, ref, &env->exception);

  JSStringRelease(ref);

  if (env->exception) return -1;

  *result = (uint32_t) JSValueToNumber(env->context, length, &env->exception);

  if (env->exception) return -1;

  return 0;
}

int
js_get_property (js_env_t *env, js_value_t *object, js_value_t *key, js_value_t **result) {
  JSValueRef value = JSObjectGetPropertyForKey(env->context, (JSObjectRef) object, (JSValueRef) key, &env->exception);

  if (env->exception) return -1;

  *result = (js_value_t *) value;

  return 0;
}

int
js_has_property (js_env_t *env, js_value_t *object, js_value_t *key, bool *result) {
  *result = JSObjectHasPropertyForKey(env->context, (JSObjectRef) object, (JSValueRef) key, &env->exception);

  if (env->exception) return -1;

  return 0;
}

int
js_set_property (js_env_t *env, js_value_t *object, js_value_t *key, js_value_t *value) {
  JSObjectSetPropertyForKey(env->context, (JSObjectRef) object, (JSValueRef) key, (JSValueRef) value, kJSPropertyAttributeNone, &env->exception);

  if (env->exception) return -1;

  return 0;
}

int
js_delete_property (js_env_t *env, js_value_t *object, js_value_t *key, bool *result) {
  bool value = JSObjectDeletePropertyForKey(env->context, (JSObjectRef) object, (JSValueRef) key, &env->exception);

  if (env->exception) return -1;

  if (result) {
    *result = value;
  }

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
js_has_named_property (js_env_t *env, js_value_t *object, const char *name, bool *result) {
  JSStringRef ref = JSStringCreateWithUTF8CString(name);

  *result = JSObjectHasProperty(env->context, (JSObjectRef) object, ref);

  JSStringRelease(ref);

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
js_delete_named_property (js_env_t *env, js_value_t *object, const char *name, bool *result) {
  JSStringRef ref = JSStringCreateWithUTF8CString(name);

  bool value = JSObjectDeleteProperty(env->context, (JSObjectRef) object, ref, &env->exception);

  JSStringRelease(ref);

  if (env->exception) return -1;

  if (result) {
    *result = value;
  }

  return 0;
}

int
js_get_element (js_env_t *env, js_value_t *object, uint32_t index, js_value_t **result) {
  JSValueRef value = JSObjectGetPropertyAtIndex(env->context, (JSObjectRef) object, index, &env->exception);

  if (env->exception) return -1;

  *result = (js_value_t *) value;

  return 0;
}

int
js_has_element (js_env_t *env, js_value_t *object, uint32_t index, bool *result) {
  JSValueRef value = JSObjectGetPropertyAtIndex(env->context, (JSObjectRef) object, index, &env->exception);

  if (env->exception) return -1;

  *result = !JSValueIsUndefined(env->context, value);

  return 0;
}

int
js_set_element (js_env_t *env, js_value_t *object, uint32_t index, js_value_t *value) {
  JSObjectSetPropertyAtIndex(env->context, (JSObjectRef) object, index, (JSValueRef) value, &env->exception);

  if (env->exception) return -1;

  return 0;
}

int
js_delete_element (js_env_t *env, js_value_t *object, uint32_t index, bool *result) {
  JSValueRef key = JSValueMakeNumber(env->context, (double) index);

  bool value = JSObjectDeletePropertyForKey(env->context, (JSObjectRef) object, key, &env->exception);

  if (env->exception) return -1;

  if (result) {
    *result = value;
  }

  return 0;
}

int
js_get_callback_info (js_env_t *env, const js_callback_info_t *info, size_t *argc, js_value_t *argv[], js_value_t **self, void **data) {
  if (argv) {
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

  if (argc) {
    *argc = info->argc;
  }

  if (self) {
    *self = (js_value_t *) info->receiver;
  }

  if (data) {
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

  if (pdata) {
    *pdata = data;
  }

  if (plen) {
    *plen = len;
  }

  return 0;
}

int
js_get_typedarray_info (js_env_t *env, js_value_t *typedarray, js_typedarray_type_t *ptype, void **pdata, size_t *plen, js_value_t **parraybuffer, size_t *poffset) {
  JSObjectRef arraybuffer;

  if (pdata || parraybuffer) {
    arraybuffer = JSObjectGetTypedArrayBuffer(env->context, (JSObjectRef) typedarray, &env->exception);

    if (env->exception) return -1;
  }

  if (ptype) {
    JSTypedArrayType type = JSValueGetTypedArrayType(env->context, (JSValueRef) typedarray, &env->exception);

    if (env->exception) return -1;

    *ptype = js_convert_to_typedarray_type(type);
  }

  if (pdata) {
    void *data = JSObjectGetArrayBufferBytesPtr(env->context, arraybuffer, &env->exception);

    if (env->exception) return -1;

    *pdata = data;
  }

  if (plen) {
    size_t len = JSObjectGetTypedArrayLength(env->context, (JSObjectRef) typedarray, &env->exception);

    if (env->exception) return -1;

    *plen = len;
  }

  if (parraybuffer) {
    *parraybuffer = (js_value_t *) arraybuffer;
  }

  if (poffset) {
    size_t offset = JSObjectGetTypedArrayByteOffset(env->context, (JSObjectRef) typedarray, &env->exception);

    if (env->exception) return -1;

    *poffset = offset;
  }

  return 0;
}

int
js_get_dataview_info (js_env_t *env, js_value_t *dataview, void **pdata, size_t *plen, js_value_t **parraybuffer, size_t *poffset) {
  JSObjectRef arraybuffer;

  if (pdata || parraybuffer) {
    JSStringRef ref = JSStringCreateWithUTF8CString("buffer");

    arraybuffer = (JSObjectRef) JSObjectGetProperty(env->context, (JSObjectRef) dataview, ref, &env->exception);

    JSStringRelease(ref);

    if (env->exception) return -1;
  }

  if (pdata) {
    void *data = JSObjectGetArrayBufferBytesPtr(env->context, arraybuffer, &env->exception);

    if (env->exception) return -1;

    *pdata = data;
  }

  if (plen) {
    JSStringRef ref = JSStringCreateWithUTF8CString("byteLength");

    JSValueRef value = JSObjectGetProperty(env->context, (JSObjectRef) dataview, ref, &env->exception);

    JSStringRelease(ref);

    if (env->exception) return -1;

    double len = JSValueToNumber(env->context, value, &env->exception);

    if (env->exception) return -1;

    *plen = (size_t) len;
  }

  if (parraybuffer) {
    *parraybuffer = (js_value_t *) arraybuffer;
  }

  if (poffset) {
    JSStringRef ref = JSStringCreateWithUTF8CString("byteOffset");

    JSValueRef value = JSObjectGetProperty(env->context, (JSObjectRef) dataview, ref, &env->exception);

    JSStringRelease(ref);

    if (env->exception) return -1;

    double offset = JSValueToNumber(env->context, value, &env->exception);

    if (env->exception) return -1;

    *poffset = (size_t) offset;
  }

  return 0;
}

int
js_call_function (js_env_t *env, js_value_t *receiver, js_value_t *function, size_t argc, js_value_t *const argv[], js_value_t **result) {
  env->depth++;

  JSValueRef value = JSObjectCallAsFunction(env->context, (JSObjectRef) function, (JSObjectRef) receiver, argc, (const JSValueRef *) argv, &env->exception);

  env->depth--;

  if (env->exception) {
    if (env->depth == 0) {
      JSValueRef error = env->exception;

      env->exception = NULL;

      on_uncaught_exception(env, (js_value_t *) error);
    }

    return -1;
  }

  if (result) {
    *result = (js_value_t *) value;
  }

  return 0;
}

int
js_throw (js_env_t *env, js_value_t *error) {
  env->exception = (JSValueRef) error;

  return 0;
}

int
js_vformat (char **result, size_t *size, const char *message, va_list args) {
  int res = vsnprintf(NULL, 0, message, args);
  if (res < 0) return res;

  *size = res + 1 /* NULL */;
  *result = malloc(*size);

  vsnprintf(*result, *size, message, args);

  return 0;
}

int
js_throw_error (js_env_t *env, const char *code, const char *message) {
  JSStringRef ref = JSStringCreateWithUTF8CString(message);

  JSValueRef argv[1] = {JSValueMakeString(env->context, ref)};

  JSStringRelease(ref);

  JSObjectRef error = JSObjectMakeError(env->context, 1, argv, &env->exception);

  if (env->exception) return -1;

  if (code) {
    ref = JSStringCreateWithUTF8CString(code);

    JSValueRef value = JSValueMakeString(env->context, ref);

    JSStringRelease(ref);

    ref = JSStringCreateWithUTF8CString("code");

    JSObjectSetProperty(
      env->context,
      error,
      ref,
      value,
      kJSPropertyAttributeNone,
      &env->exception
    );

    JSStringRelease(ref);

    if (env->exception) return -1;
  }

  env->exception = error;

  return 0;
}

int
js_throw_verrorf (js_env_t *env, const char *code, const char *message, va_list args) {
  size_t len;
  char *formatted;
  js_vformat(&formatted, &len, message, args);

  int err = js_throw_error(env, code, formatted);

  free(formatted);

  return err;
}

int
js_throw_type_error (js_env_t *env, const char *code, const char *message) {
  JSObjectRef global = JSContextGetGlobalObject(env->context);

  JSStringRef ref = JSStringCreateWithUTF8CString("TypeError");

  JSValueRef constructor = JSObjectGetProperty(env->context, global, ref, &env->exception);

  JSStringRelease(ref);

  if (env->exception) return -1;

  ref = JSStringCreateWithUTF8CString(message);

  JSValueRef argv[1] = {JSValueMakeString(env->context, ref)};

  JSStringRelease(ref);

  JSObjectRef error = JSObjectCallAsConstructor(env->context, (JSObjectRef) constructor, 1, argv, &env->exception);

  if (env->exception) return -1;

  if (code) {
    ref = JSStringCreateWithUTF8CString(code);

    JSValueRef value = JSValueMakeString(env->context, ref);

    JSStringRelease(ref);

    ref = JSStringCreateWithUTF8CString("code");

    JSObjectSetProperty(
      env->context,
      error,
      ref,
      value,
      kJSPropertyAttributeNone,
      &env->exception
    );

    JSStringRelease(ref);

    if (env->exception) return -1;
  }

  env->exception = error;

  return 0;
}

int
js_throw_type_verrorf (js_env_t *env, const char *code, const char *message, va_list args) {
  size_t len;
  char *formatted;
  js_vformat(&formatted, &len, message, args);

  int err = js_throw_type_error(env, code, formatted);

  free(formatted);

  return err;
}

int
js_throw_range_error (js_env_t *env, const char *code, const char *message) {
  JSObjectRef global = JSContextGetGlobalObject(env->context);

  JSStringRef ref = JSStringCreateWithUTF8CString("RangeError");

  JSValueRef constructor = JSObjectGetProperty(env->context, global, ref, &env->exception);

  JSStringRelease(ref);

  if (env->exception) return -1;

  ref = JSStringCreateWithUTF8CString(message);

  JSValueRef argv[1] = {JSValueMakeString(env->context, ref)};

  JSStringRelease(ref);

  JSObjectRef error = JSObjectCallAsConstructor(env->context, (JSObjectRef) constructor, 1, argv, &env->exception);

  if (env->exception) return -1;

  if (code) {
    ref = JSStringCreateWithUTF8CString(code);

    JSValueRef value = JSValueMakeString(env->context, ref);

    JSStringRelease(ref);

    ref = JSStringCreateWithUTF8CString("code");

    JSObjectSetProperty(
      env->context,
      error,
      ref,
      value,
      kJSPropertyAttributeNone,
      &env->exception
    );

    JSStringRelease(ref);

    if (env->exception) return -1;
  }

  env->exception = error;

  return 0;
}

int
js_throw_range_verrorf (js_env_t *env, const char *code, const char *message, va_list args) {
  size_t len;
  char *formatted;
  js_vformat(&formatted, &len, message, args);

  int err = js_throw_range_error(env, code, formatted);

  free(formatted);

  return err;
}

int
js_throw_syntax_error (js_env_t *env, const char *code, const char *message) {
  JSObjectRef global = JSContextGetGlobalObject(env->context);

  JSStringRef ref = JSStringCreateWithUTF8CString("SyntaxError");

  JSValueRef constructor = JSObjectGetProperty(env->context, global, ref, &env->exception);

  JSStringRelease(ref);

  if (env->exception) return -1;

  ref = JSStringCreateWithUTF8CString(message);

  JSValueRef argv[1] = {JSValueMakeString(env->context, ref)};

  JSStringRelease(ref);

  JSObjectRef error = JSObjectCallAsConstructor(env->context, (JSObjectRef) constructor, 1, argv, &env->exception);

  if (env->exception) return -1;

  if (code) {
    ref = JSStringCreateWithUTF8CString(code);

    JSValueRef value = JSValueMakeString(env->context, ref);

    JSStringRelease(ref);

    ref = JSStringCreateWithUTF8CString("code");

    JSObjectSetProperty(
      env->context,
      error,
      ref,
      value,
      kJSPropertyAttributeNone,
      &env->exception
    );

    JSStringRelease(ref);

    if (env->exception) return -1;
  }

  env->exception = error;

  return 0;
}

int
js_throw_syntax_verrorf (js_env_t *env, const char *code, const char *message, va_list args) {
  size_t len;
  char *formatted;
  js_vformat(&formatted, &len, message, args);

  int err = js_throw_range_error(env, code, formatted);

  free(formatted);

  return err;
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
js_fatal_exception (js_env_t *env, js_value_t *error) {
  on_uncaught_exception(env, error);

  return 0;
}

int
js_adjust_external_memory (js_env_t *env, int64_t change_in_bytes, int64_t *result) {
  env->external_memory += change_in_bytes;

  if (change_in_bytes > 0) {
    JSReportExtraMemoryCost(env->context, change_in_bytes);
  }

  if (result) {
    *result = env->external_memory;
  }

  return 0;
}

int
js_request_garbage_collection (js_env_t *env) {
  if (!env->platform->options.expose_garbage_collection) {
    js_throw_error(env, NULL, "Garbage collection is unavailable");

    return -1;
  }

  JSSynchronousEdenCollectForDebugging(env->context);

  JSSynchronousGarbageCollectForDebugging(env->context);

  return 0;
}

int
js_ffi_create_type_info (js_ffi_type_t type, js_ffi_type_info_t **result) {
  *result = NULL;

  return 0;
}

int
js_ffi_create_function_info (const js_ffi_type_info_t *return_info, js_ffi_type_info_t *const arg_info[], unsigned int arg_len, js_ffi_function_info_t **result) {
  *result = NULL;

  return 0;
}

int
js_ffi_create_function (const void *function, const js_ffi_function_info_t *type_info, js_ffi_function_t **result) {
  *result = NULL;

  return 0;
}
