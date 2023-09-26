#include <js.h>
#include <js/ffi.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <utf.h>
#include <uv.h>
#include <wchar.h>

#include <CoreFoundation/CoreFoundation.h>
#include <JavaScriptCore/JavaScriptCore.h>

#include "jsc.h"

typedef struct js_callback_s js_callback_t;
typedef struct js_finalizer_s js_finalizer_t;
typedef struct js_finalizer_list_s js_finalizer_list_t;
typedef struct js_delegate_s js_delegate_t;

struct js_platform_s {
  js_platform_options_t options;
  uv_loop_t *loop;
};

struct js_env_s {
  uv_loop_t *loop;

  js_platform_t *platform;
  js_handle_scope_t *scope;

  uint32_t depth;

  JSContextGroupRef group;
  JSGlobalContextRef context;

  JSValueRef exception;

  int64_t external_memory;

  struct {
    js_uncaught_exception_cb uncaught_exception;
    void *uncaught_exception_data;

    js_unhandled_rejection_cb unhandled_rejection;
    void *unhandled_rejection_data;
  } callbacks;

  struct {
    JSClassRef reference;
    JSClassRef wrap;
    JSClassRef finalizer;
    JSClassRef type_tag;
    JSClassRef external;
    JSClassRef function;
    JSClassRef constructor;
    JSClassRef delegate;
  } classes;
};

struct js_handle_scope_s {
  js_handle_scope_t *parent;
  JSValueRef *values;
  size_t len;
  size_t capacity;
};

struct js_escapable_handle_scope_s {
  js_handle_scope_t *scope;
  bool escaped;
};

struct js_ref_s {
  JSValueRef value;
  JSValueRef symbol;
  uint32_t count;
};

struct js_deferred_s {
  JSObjectRef resolve;
  JSObjectRef reject;
};

struct js_finalizer_s {
  js_env_t *env;
  void *data;
  js_finalize_cb finalize_cb;
  void *finalize_hint;
};

struct js_finalizer_list_s {
  js_finalizer_t finalizer;
  js_finalizer_list_t *next;
};

struct js_delegate_s {
  js_env_t *env;
  js_delegate_callbacks_t callbacks;
  void *data;
  js_finalize_cb finalize_cb;
  void *finalize_hint;
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
  JSValueRef new_target;
};

struct js_arraybuffer_backing_store_s {
  js_env_t *env;
  uint32_t references;
  size_t len;
  uint8_t *data;
  JSValueRef owner;
};

static const char *js_platform_identifier = "javascriptcore";

static const char *js_platform_version = NULL;

static uv_once_t js_platform_version_guard = UV_ONCE_INIT;

int
js_create_platform (uv_loop_t *loop, const js_platform_options_t *options, js_platform_t **result) {
  int err;

  if (options) {
    if (options->trace_garbage_collection) {
      err = uv_os_setenv("JSC_logGC", "true");
      assert(err == 0);
    }

    if (options->disable_optimizing_compiler) {
      err = uv_os_setenv("JSC_useJIT", "false");
      assert(err == 0);
    } else {
      if (options->trace_optimizations) {
        err = uv_os_setenv("JSC_logJIT", "true");
        assert(err == 0);
      }
    }

    if (options->enable_sampling_profiler) {
      err = uv_os_setenv("JSC_useSamplingProfiler", "true");
      assert(err == 0);

      err = uv_os_setenv("JSC_samplingProfilerPath", ".");
      assert(err == 0);

      err = uv_os_setenv("JSC_collectExtraSamplingProfilerData", "true");
      assert(err == 0);

      if (options->sampling_profiler_interval > 0) {
        char interval[16];
        err = snprintf(interval, 16, "%d", options->sampling_profiler_interval);
        assert(err >= 0);

        err = uv_os_setenv("JSC_sampleInterval", interval);
        assert(err == 0);
      }
    }
  }

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
js_get_platform_identifier (js_platform_t *platform, const char **result) {
  *result = js_platform_identifier;

  return 0;
}

static void
on_platform_version_init () {
  CFStringRef ref;

  ref = CFStringCreateWithCString(NULL, "com.apple.JavaScriptCore", kCFStringEncodingUTF8);

  CFBundleRef bundle = CFBundleGetBundleWithIdentifier(ref);

  CFRelease(ref);

  ref = CFStringCreateWithCString(NULL, "CFBundleVersion", kCFStringEncodingUTF8);

  CFStringRef version = CFBundleGetValueForInfoDictionaryKey(bundle, ref);

  CFRelease(ref);

  const char *ptr = CFStringGetCStringPtr(version, kCFStringEncodingUTF8);

  if (ptr) js_platform_version = strdup(ptr);

  CFRelease(version);
  CFRelease(bundle);
}

int
js_get_platform_version (js_platform_t *platform, const char **result) {
  uv_once(&js_platform_version_guard, on_platform_version_init);

  *result = js_platform_version;

  return 0;
}

int
js_get_platform_loop (js_platform_t *platform, uv_loop_t **result) {
  *result = platform->loop;

  return 0;
}

static void
on_uncaught_exception (js_env_t *env, js_value_t *error) {
  int err;

  if (env->callbacks.uncaught_exception) {
    js_handle_scope_t *scope;
    err = js_open_handle_scope(env, &scope);
    assert(err == 0);

    env->callbacks.uncaught_exception(env, error, env->callbacks.uncaught_exception_data);

    err = js_close_handle_scope(env, scope);
    assert(err == 0);
  } else {
    env->exception = (JSValueRef) error;
  }
}

static js_value_t *
on_unhandled_rejection (js_env_t *env, js_callback_info_t *info) {
  int err;

  if (env->callbacks.unhandled_rejection) {
    size_t argc = 2;
    js_value_t *argv[2];

    js_get_callback_info(env, info, &argc, argv, NULL, NULL);

    js_handle_scope_t *scope;
    err = js_open_handle_scope(env, &scope);
    assert(err == 0);

    env->callbacks.unhandled_rejection(env, argv[1], argv[0], env->callbacks.unhandled_rejection_data);

    err = js_close_handle_scope(env, scope);
    assert(err == 0);
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
on_type_tag_finalize (JSObjectRef external);

static void
on_function_finalize (JSObjectRef external);

static void
on_external_finalize (JSObjectRef external);

static void
on_constructor_finalize (JSObjectRef external);

static JSValueRef
on_delegate_get_property (JSContextRef context, JSObjectRef object, JSStringRef property, JSValueRef *exception);

static bool
on_delegate_set_property (JSContextRef context, JSObjectRef object, JSStringRef property, JSValueRef value, JSValueRef *exception);

static bool
on_delegate_delete_property (JSContextRef context, JSObjectRef object, JSStringRef property, JSValueRef *exception);

static void
on_delegate_get_property_names (JSContextRef context, JSObjectRef object, JSPropertyNameAccumulatorRef properties);

static void
on_delegate_finalize (JSObjectRef object);

static inline int
js_propagate_exception (js_env_t *env) {
  if (env->depth == 0) {
    JSValueRef error = env->exception;

    env->exception = NULL;

    on_uncaught_exception(env, (js_value_t *) error);
  }

  return -1;
}

int
js_create_env (uv_loop_t *loop, js_platform_t *platform, const js_env_options_t *options, js_env_t **result) {
  int err;

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

  env->callbacks.uncaught_exception = NULL;
  env->callbacks.uncaught_exception_data = NULL;

  env->callbacks.unhandled_rejection = NULL;
  env->callbacks.unhandled_rejection_data = NULL;

  env->classes.reference = JSClassCreate(&(JSClassDefinition){
    .finalize = on_reference_finalize,
  });

  env->classes.wrap = JSClassCreate(&(JSClassDefinition){
    .finalize = on_wrap_finalize,
  });

  env->classes.finalizer = JSClassCreate(&(JSClassDefinition){
    .finalize = on_finalizer_finalize,
  });

  env->classes.type_tag = JSClassCreate(&(JSClassDefinition){
    .finalize = on_type_tag_finalize,
  });

  env->classes.function = JSClassCreate(&(JSClassDefinition){
    .finalize = on_function_finalize,
  });

  env->classes.external = JSClassCreate(&(JSClassDefinition){
    .finalize = on_external_finalize,
  });

  env->classes.constructor = JSClassCreate(&(JSClassDefinition){
    .finalize = on_constructor_finalize,
  });

  env->classes.delegate = JSClassCreate(&(JSClassDefinition){
    .getProperty = on_delegate_get_property,
    .setProperty = on_delegate_set_property,
    .deleteProperty = on_delegate_delete_property,
    .getPropertyNames = on_delegate_get_property_names,
    .finalize = on_delegate_finalize,
  });

  err = js_open_handle_scope(env, &env->scope);
  assert(err == 0);

  js_value_t *fn;
  err = js_create_function(env, "onunhandledrejection", -1, on_unhandled_rejection, NULL, &fn);
  assert(err == 0);

  JSGlobalContextSetUnhandledRejectionCallback(context, (JSObjectRef) fn, &env->exception);

  assert(env->exception == NULL);

  *result = env;

  return 0;
}

int
js_destroy_env (js_env_t *env) {
  int err;

  err = js_open_handle_scope(env, &env->scope);
  assert(err == 0);

  JSClassRelease(env->classes.reference);
  JSClassRelease(env->classes.wrap);
  JSClassRelease(env->classes.finalizer);
  JSClassRelease(env->classes.type_tag);
  JSClassRelease(env->classes.function);
  JSClassRelease(env->classes.external);
  JSClassRelease(env->classes.constructor);

  JSGlobalContextRelease(env->context);
  JSContextGroupRelease(env->group);

  free(env);

  return 0;
}

int
js_on_uncaught_exception (js_env_t *env, js_uncaught_exception_cb cb, void *data) {
  env->callbacks.uncaught_exception = cb;
  env->callbacks.uncaught_exception_data = data;

  return 0;
}

int
js_on_unhandled_rejection (js_env_t *env, js_unhandled_rejection_cb cb, void *data) {
  env->callbacks.unhandled_rejection = cb;
  env->callbacks.unhandled_rejection_data = data;

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
  js_handle_scope_t *scope = malloc(sizeof(js_handle_scope_t));

  scope->parent = env->scope;
  scope->values = NULL;
  scope->len = 0;
  scope->capacity = 0;

  env->scope = scope;

  *result = scope;

  return 0;
}

int
js_close_handle_scope (js_env_t *env, js_handle_scope_t *scope) {
  for (size_t i = 0; i < scope->len; i++) {
    JSValueUnprotect(env->context, scope->values[i]);
  }

  env->scope = scope->parent;

  if (scope->values) free(scope->values);

  free(scope);

  return 0;
}

int
js_open_escapable_handle_scope (js_env_t *env, js_escapable_handle_scope_t **result) {
  js_escapable_handle_scope_t *scope = malloc(sizeof(js_escapable_handle_scope_t));

  scope->escaped = false;

  return js_open_handle_scope(env, &scope->scope);
}

int
js_close_escapable_handle_scope (js_env_t *env, js_escapable_handle_scope_t *scope) {
  int err = js_close_handle_scope(env, scope->scope);

  free(scope);

  return err;
}

static void
js_attach_to_handle_scope (js_env_t *env, js_handle_scope_t *scope, JSValueRef value) {
  if (scope->len >= scope->capacity) {
    if (scope->capacity) scope->capacity *= 2;
    else scope->capacity = 4;

    scope->values = realloc(scope->values, scope->capacity * sizeof(JSValueRef));
  }

  JSValueProtect(env->context, value);

  scope->values[scope->len++] = value;
}

int
js_escape_handle (js_env_t *env, js_escapable_handle_scope_t *scope, js_value_t *escapee, js_value_t **result) {
  if (scope->escaped) {
    js_throw_error(env, NULL, "Scope has already been escaped");

    return -1;
  }

  scope->escaped = true;

  *result = escapee;

  js_attach_to_handle_scope(env, scope->scope->parent, (JSValueRef) escapee);

  return 0;
}

int
js_run_script (js_env_t *env, const char *file, size_t len, int offset, js_value_t *source, js_value_t **result) {
  JSStringRef ref = JSValueToStringCopy(env->context, (JSValueRef) source, &env->exception);

  if (env->exception) return js_propagate_exception(env);

  if (file == NULL) file = "";

  JSStringRef url = JSStringCreateWithUTF8CString(file);

  env->depth++;

  JSValueRef value = JSEvaluateScript(env->context, ref, NULL, url, offset + 1, &env->exception);

  env->depth--;

  JSStringRelease(ref);
  JSStringRelease(url);

  if (env->exception) return js_propagate_exception(env);

  if (result) {
    *result = (js_value_t *) value;

    js_attach_to_handle_scope(env, env->scope, value);
  }

  return 0;
}

// https://bugs.webkit.org/show_bug.cgi?id=261600
int
js_create_module (js_env_t *env, const char *name, size_t len, int offset, js_value_t *source, js_module_meta_cb cb, void *data, js_module_t **result) {
  js_throw_error(env, NULL, "Unsupported operation");

  return -1;
}

// https://bugs.webkit.org/show_bug.cgi?id=261600
int
js_create_synthetic_module (js_env_t *env, const char *name, size_t len, js_value_t *const export_names[], size_t names_len, js_module_evaluate_cb cb, void *data, js_module_t **result) {
  js_throw_error(env, NULL, "Unsupported operation");

  return -1;
}

// https://bugs.webkit.org/show_bug.cgi?id=261600
int
js_delete_module (js_env_t *env, js_module_t *module) {
  js_throw_error(env, NULL, "Unsupported operation");

  return -1;
}

// https://bugs.webkit.org/show_bug.cgi?id=261600
int
js_get_module_name (js_env_t *env, js_module_t *module, const char **result) {
  js_throw_error(env, NULL, "Unsupported operation");

  return -1;
}

// https://bugs.webkit.org/show_bug.cgi?id=261600
int
js_get_module_namespace (js_env_t *env, js_module_t *module, js_value_t **result) {
  js_throw_error(env, NULL, "Unsupported operation");

  return -1;
}

// https://bugs.webkit.org/show_bug.cgi?id=261600
int
js_set_module_export (js_env_t *env, js_module_t *module, js_value_t *name, js_value_t *value) {
  js_throw_error(env, NULL, "Unsupported operation");

  return -1;
}

// https://bugs.webkit.org/show_bug.cgi?id=261600
int
js_instantiate_module (js_env_t *env, js_module_t *module, js_module_resolve_cb cb, void *data) {
  js_throw_error(env, NULL, "Unsupported operation");

  return -1;
}

// https://bugs.webkit.org/show_bug.cgi?id=261600
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

  reference->value = (JSValueRef) value;
  reference->count = count;

  if (JSValueIsObject(env->context, reference->value)) {
    JSObjectRef external = JSObjectMake(env->context, env->classes.reference, (void *) reference);

    JSStringRef ref = JSStringCreateWithUTF8CString("__native_reference");

    reference->symbol = JSValueMakeSymbol(env->context, ref);

    JSValueProtect(env->context, reference->symbol);

    JSStringRelease(ref);

    JSObjectSetPropertyForKey(
      env->context,
      (JSObjectRef) reference->value,
      reference->symbol,
      external,
      kJSPropertyAttributeReadOnly | kJSPropertyAttributeDontEnum,
      NULL
    );

    if (reference->count > 0) JSValueProtect(env->context, reference->value);
  } else {
    if (reference->count == 0) {
      js_throw_errorf(env, NULL, "Cannot make weak reference to non-object type");

      free(reference);

      return -1;
    }

    JSValueProtect(env->context, reference->value);

    reference->symbol = NULL;
  }

  *result = reference;

  return 0;
}

int
js_delete_reference (js_env_t *env, js_ref_t *reference) {
  if (JSValueIsObject(env->context, reference->value)) {
    JSValueRef external = JSObjectGetPropertyForKey(env->context, (JSObjectRef) reference->value, reference->symbol, NULL);

    JSObjectSetPrivate((JSObjectRef) external, NULL);

    JSObjectDeletePropertyForKey(
      env->context,
      (JSObjectRef) reference->value,
      reference->symbol,
      NULL
    );
  }

  if (reference->count > 0) JSValueUnprotect(env->context, reference->value);

  JSValueUnprotect(env->context, reference->symbol);

  free(reference);

  return 0;
}

int
js_reference_ref (js_env_t *env, js_ref_t *reference, uint32_t *result) {
  reference->count++;

  if (JSValueIsObject(env->context, reference->value)) {
    if (reference->count == 1) JSValueProtect(env->context, reference->value);
  }

  if (result) *result = reference->count;

  return 0;
}

int
js_reference_unref (js_env_t *env, js_ref_t *reference, uint32_t *result) {
  if (reference->count == 0) {
    js_throw_error(env, NULL, "Cannot decrease reference count");

    return -1;
  }

  if (reference->count == 1) {
    if (JSValueIsObject(env->context, reference->value)) {
      JSValueUnprotect(env->context, reference->value);
    } else {
      js_throw_errorf(env, NULL, "Cannot make weak reference to non-object type");

      return -1;
    }
  }

  reference->count--;

  if (result) *result = reference->count;

  return 0;
}

int
js_get_reference_value (js_env_t *env, js_ref_t *reference, js_value_t **result) {
  if (reference->value == NULL) *result = NULL;
  else {
    *result = (js_value_t *) reference->value;

    js_attach_to_handle_scope(env, env->scope, reference->value);
  }

  return 0;
}

static void
on_constructor_finalize (JSObjectRef external) {
  js_callback_t *callback = (js_callback_t *) JSObjectGetPrivate(external);

  free(callback);
}

static JSObjectRef
on_constructor_call (JSContextRef context, JSObjectRef new_target, size_t argc, const JSValueRef argv[], JSValueRef *exception) {
  int err;

  JSObjectRef receiver = JSObjectMake(context, NULL, NULL);

  JSObjectSetPrototype(context, receiver, JSObjectGetPrototype(context, new_target));

  JSStringRef ref = JSStringCreateWithUTF8CString("__native_constructor");

  JSValueRef external = JSObjectGetProperty(context, new_target, ref, NULL);

  JSStringRelease(ref);

  js_callback_t *callback = (js_callback_t *) JSObjectGetPrivate((JSObjectRef) external);

  js_env_t *env = callback->env;

  js_callback_info_t callback_info = {
    .callback = callback,
    .argc = argc,
    .argv = argv,
    .receiver = receiver,
    .new_target = new_target,
  };

  js_handle_scope_t *scope;
  err = js_open_handle_scope(env, &scope);
  assert(err == 0);

  js_value_t *result = callback->cb(env, &callback_info);

  err = js_close_handle_scope(env, scope);
  assert(err == 0);

  JSValueRef value;

  if (result == NULL) value = JSValueMakeUndefined(env->context);
  else value = (JSValueRef) result;

  if (env->exception == NULL) return receiver;

  *exception = env->exception;

  env->exception = NULL;

  return NULL;
}

int
js_define_class (js_env_t *env, const char *name, size_t len, js_function_cb constructor, void *data, js_property_descriptor_t const properties[], size_t properties_len, js_value_t **result) {
  int err;

  JSStringRef ref;

  JSObjectRef class = JSObjectMakeConstructor(env->context, NULL, on_constructor_call);

  JSObjectRef prototype = JSObjectMake(env->context, NULL, NULL);

  JSObjectSetPrototype(env->context, prototype, JSObjectGetPrototype(env->context, class));

  JSObjectSetPrototype(env->context, class, prototype);

  ref = JSStringCreateWithUTF8CString("constructor");

  JSObjectSetProperty(
    env->context,
    prototype,
    ref,
    class,
    kJSPropertyAttributeReadOnly | kJSPropertyAttributeDontDelete,
    &env->exception
  );

  JSStringRelease(ref);

  if (env->exception) return js_propagate_exception(env);

  size_t instance_properties_len = 0;
  size_t static_properties_len = 0;

  for (size_t i = 0; i < properties_len; i++) {
    const js_property_descriptor_t *property = &properties[i];

    if ((property->attributes & js_static) == 0) {
      instance_properties_len++;
    } else {
      static_properties_len++;
    }
  }

  if (instance_properties_len) {
    js_property_descriptor_t *instance_properties = malloc(sizeof(js_property_descriptor_t) * instance_properties_len);

    for (size_t i = 0, j = 0; i < properties_len; i++) {
      const js_property_descriptor_t *property = &properties[i];

      if ((property->attributes & js_static) == 0) {
        instance_properties[j++] = *property;
      }
    }

    err = js_define_properties(env, (js_value_t *) prototype, instance_properties, instance_properties_len);
    assert(err == 0);

    free(instance_properties);
  }

  if (static_properties_len) {
    js_property_descriptor_t *static_properties = malloc(sizeof(js_property_descriptor_t) * static_properties_len);

    for (size_t i = 0, j = 0; i < properties_len; i++) {
      const js_property_descriptor_t *property = &properties[i];

      if ((property->attributes & js_static) != 0) {
        static_properties[j++] = *property;
      }
    }

    err = js_define_properties(env, (js_value_t *) class, static_properties, static_properties_len);
    assert(err == 0);

    free(static_properties);
  }

  js_callback_t *callback = malloc(sizeof(js_callback_t));

  callback->env = env;
  callback->cb = constructor;
  callback->data = data;

  JSObjectRef external = JSObjectMake(env->context, env->classes.function, (void *) callback);

  ref = JSStringCreateWithUTF8CString("__native_constructor");

  JSObjectSetProperty(
    env->context,
    class,
    ref,
    external,
    kJSPropertyAttributeReadOnly | kJSPropertyAttributeDontEnum | kJSPropertyAttributeDontDelete,
    NULL
  );

  JSStringRelease(ref);

  *result = (js_value_t *) class;

  js_attach_to_handle_scope(env, env->scope, class);

  return 0;
}

int
js_define_properties (js_env_t *env, js_value_t *object, js_property_descriptor_t const properties[], size_t properties_len) {
  int err;

  for (size_t i = 0; i < properties_len; i++) {
    const js_property_descriptor_t *property = &properties[i];

    int flags = kJSPropertyAttributeNone;

    if ((property->attributes & js_writable) == 0 && property->getter == NULL && property->setter == NULL) {
      flags |= kJSPropertyAttributeReadOnly;
    }

    if ((property->attributes & js_enumerable) == 0) {
      flags |= kJSPropertyAttributeDontEnum;
    }

    if ((property->attributes & js_configurable) == 0) {
      flags |= kJSPropertyAttributeDontDelete;
    }

    JSValueRef value;

    if (property->getter || property->setter) {
      if (property->getter) {
        js_value_t *fn;
        err = js_create_function(env, property->name, -1, property->getter, property->data, &fn);
        assert(err == 0);
      }

      if (property->setter) {
        js_value_t *fn;
        err = js_create_function(env, property->name, -1, property->setter, property->data, &fn);
        assert(err == 0);
      }

      return -1;
    } else if (property->method) {
      js_value_t *fn;
      err = js_create_function(env, property->name, -1, property->method, property->data, &fn);
      assert(err == 0);

      value = (JSValueRef) fn;
    } else {
      value = (JSValueRef) property->value;
    }

    JSStringRef name = JSStringCreateWithUTF8CString(property->name);

    JSObjectSetProperty(env->context, (JSObjectRef) object, name, value, flags, &env->exception);

    JSStringRelease(name);

    if (env->exception) return js_propagate_exception(env);
  }

  return 0;
}

static void
on_wrap_finalize (JSObjectRef external) {
  js_finalizer_t *finalizer = (js_finalizer_t *) JSObjectGetPrivate(external);

  if (finalizer->finalize_cb) {
    finalizer->finalize_cb(finalizer->env, finalizer->data, finalizer->finalize_hint);
  }

  free(finalizer);
}

int
js_wrap (js_env_t *env, js_value_t *object, void *data, js_finalize_cb finalize_cb, void *finalize_hint, js_ref_t **result) {
  js_finalizer_t *finalizer = malloc(sizeof(js_finalizer_t));

  finalizer->env = env;
  finalizer->data = data;
  finalizer->finalize_cb = finalize_cb;
  finalizer->finalize_hint = finalize_hint;

  JSObjectRef external = JSObjectMake(env->context, env->classes.wrap, (void *) finalizer);

  JSStringRef ref = JSStringCreateWithUTF8CString("__native_external");

  JSObjectSetProperty(
    env->context,
    (JSObjectRef) object,
    ref,
    external,
    kJSPropertyAttributeReadOnly | kJSPropertyAttributeDontEnum,
    &env->exception
  );

  JSStringRelease(ref);

  if (env->exception) return js_propagate_exception(env);

  if (result) return js_create_reference(env, object, 0, result);

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

  finalizer->finalize_cb = NULL;

  if (result) *result = finalizer->data;

  JSObjectDeleteProperty(env->context, (JSObjectRef) object, ref, &env->exception);

  JSStringRelease(ref);

  if (env->exception) return js_propagate_exception(env);

  return 0;
}

static JSValueRef
on_delegate_get_property (JSContextRef context, JSObjectRef object, JSStringRef property, JSValueRef *exception) {
  js_delegate_t *delegate = (js_delegate_t *) JSObjectGetPrivate(object);

  js_env_t *env = delegate->env;

  if (delegate->callbacks.has) {
    bool exists = delegate->callbacks.has(
      env,
      (js_value_t *) JSValueMakeString(context, property),
      delegate->data
    );

    if (env->exception) *exception = env->exception;

    env->exception = NULL;

    if (!exists) return NULL;
  }

  if (delegate->callbacks.get) {
    js_value_t *result = delegate->callbacks.get(
      env,
      (js_value_t *) JSValueMakeString(context, property),
      delegate->data
    );

    if (env->exception) *exception = env->exception;

    env->exception = NULL;

    return (JSValueRef) result;
  }

  return NULL;
}

static bool
on_delegate_set_property (JSContextRef context, JSObjectRef object, JSStringRef property, JSValueRef value, JSValueRef *exception) {
  js_delegate_t *delegate = (js_delegate_t *) JSObjectGetPrivate(object);

  js_env_t *env = delegate->env;

  if (delegate->callbacks.set) {
    bool success = delegate->callbacks.set(
      env,
      (js_value_t *) JSValueMakeString(context, property),
      (js_value_t *) value,
      delegate->data
    );

    if (env->exception) *exception = env->exception;

    env->exception = NULL;

    return success;
  }

  return false;
}

static bool
on_delegate_delete_property (JSContextRef context, JSObjectRef object, JSStringRef property, JSValueRef *exception) {
  js_delegate_t *delegate = (js_delegate_t *) JSObjectGetPrivate(object);

  js_env_t *env = delegate->env;

  if (delegate->callbacks.delete_property) {
    bool success = delegate->callbacks.delete_property(
      env,
      (js_value_t *) JSValueMakeString(context, property),
      delegate->data
    );

    if (env->exception) *exception = env->exception;

    env->exception = NULL;

    return success;
  }

  return false;
}

static void
on_delegate_get_property_names (JSContextRef context, JSObjectRef object, JSPropertyNameAccumulatorRef properties) {
  js_delegate_t *delegate = (js_delegate_t *) JSObjectGetPrivate(object);

  js_env_t *env = delegate->env;

  if (delegate->callbacks.own_keys) {
    js_value_t *result = delegate->callbacks.own_keys(env, delegate->data);

    if (env->exception) return;

    int err;

    uint32_t len;
    err = js_get_array_length(env, result, &len);
    assert(err == 0);

    for (size_t i = 0; i < len; i++) {
      js_value_t *name;
      err = js_get_element(env, result, i, &name);
      assert(err == 0);

      JSStringRef ref = JSValueToStringCopy(env->context, (JSValueRef) name, NULL);

      JSPropertyNameAccumulatorAddName(properties, ref);

      JSStringRelease(ref);
    }
  }
}

static void
on_delegate_finalize (JSObjectRef object) {
  js_delegate_t *delegate = (js_delegate_t *) JSObjectGetPrivate(object);

  if (delegate->finalize_cb) {
    delegate->finalize_cb(delegate->env, delegate->data, delegate->finalize_hint);
  }

  free(delegate);
}

int
js_create_delegate (js_env_t *env, const js_delegate_callbacks_t *callbacks, void *data, js_finalize_cb finalize_cb, void *finalize_hint, js_value_t **result) {
  js_delegate_t *delegate = malloc(sizeof(js_delegate_t));

  delegate->env = env;
  delegate->data = data;
  delegate->finalize_cb = finalize_cb;
  delegate->finalize_hint = finalize_hint;

  memcpy(&delegate->callbacks, callbacks, sizeof(js_delegate_callbacks_t));

  JSObjectRef object = JSObjectMake(env->context, env->classes.delegate, delegate);

  *result = (js_value_t *) object;

  js_attach_to_handle_scope(env, env->scope, object);

  return 0;
}

static void
on_finalizer_finalize (JSObjectRef external) {
  js_finalizer_list_t *next = (js_finalizer_list_t *) JSObjectGetPrivate(external);

  js_finalizer_list_t *prev = NULL;

  while (next) {
    js_finalizer_t *finalizer = &next->finalizer;

    if (finalizer->finalize_cb) {
      finalizer->finalize_cb(finalizer->env, finalizer->data, finalizer->finalize_hint);
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
  finalizer->finalize_cb = finalize_cb;
  finalizer->finalize_hint = finalize_hint;

  JSStringRef ref = JSStringCreateWithUTF8CString("__native_finalizer");

  JSObjectRef external;

  if (JSObjectHasProperty(env->context, (JSObjectRef) object, ref)) {
    external = (JSObjectRef) JSObjectGetProperty(env->context, (JSObjectRef) object, ref, &env->exception);
  } else {
    external = JSObjectMake(env->context, env->classes.finalizer, NULL);

    JSObjectSetProperty(
      env->context,
      (JSObjectRef) object,
      ref,
      external,
      kJSPropertyAttributeReadOnly | kJSPropertyAttributeDontEnum | kJSPropertyAttributeDontDelete,
      &env->exception
    );
  }

  JSStringRelease(ref);

  if (env->exception) return js_propagate_exception(env);

  prev->next = (js_finalizer_list_t *) JSObjectGetPrivate(external);

  JSObjectSetPrivate(external, (void *) prev);

  if (result) return js_create_reference(env, object, 0, result);

  return 0;
}

static void
on_type_tag_finalize (JSObjectRef external) {
  js_type_tag_t *tag = (js_type_tag_t *) JSObjectGetPrivate(external);

  free(tag);
}

int
js_add_type_tag (js_env_t *env, js_value_t *object, const js_type_tag_t *tag) {
  js_type_tag_t *existing = malloc(sizeof(js_type_tag_t));

  existing->lower = tag->lower;
  existing->upper = tag->upper;

  JSObjectRef external = JSObjectMake(env->context, env->classes.type_tag, (void *) existing);

  JSStringRef ref = JSStringCreateWithUTF8CString("__native_type_tag");

  if (JSObjectHasProperty(env->context, (JSObjectRef) object, ref)) {
    JSStringRelease(ref);

    js_throw_errorf(env, NULL, "Object is already type tagged");

    free(existing);

    return -1;
  }

  JSObjectSetProperty(
    env->context,
    (JSObjectRef) object,
    ref,
    external,
    kJSPropertyAttributeReadOnly | kJSPropertyAttributeDontEnum | kJSPropertyAttributeDontDelete,
    &env->exception
  );

  JSStringRelease(ref);

  if (env->exception) {
    free(existing);

    return js_propagate_exception(env);
  }

  return 0;
}

int
js_check_type_tag (js_env_t *env, js_value_t *object, const js_type_tag_t *tag, bool *result) {
  JSStringRef ref = JSStringCreateWithUTF8CString("__native_type_tag");

  JSValueRef external = JSObjectGetProperty(env->context, (JSObjectRef) object, ref, NULL);

  *result = false;

  if (external) {
    js_type_tag_t *existing = (js_type_tag_t *) JSObjectGetPrivate((JSObjectRef) external);

    *result = existing->lower == tag->lower && existing->upper == tag->upper;
  }

  return 0;
}

int
js_create_int32 (js_env_t *env, int32_t value, js_value_t **result) {
  JSValueRef number = JSValueMakeNumber(env->context, (double) value);

  *result = (js_value_t *) number;

  js_attach_to_handle_scope(env, env->scope, number);

  return 0;
}

int
js_create_uint32 (js_env_t *env, uint32_t value, js_value_t **result) {
  JSValueRef number = JSValueMakeNumber(env->context, (double) value);

  *result = (js_value_t *) number;

  js_attach_to_handle_scope(env, env->scope, number);

  return 0;
}

int
js_create_int64 (js_env_t *env, int64_t value, js_value_t **result) {
  JSValueRef number = JSValueMakeNumber(env->context, (double) value);

  *result = (js_value_t *) number;

  js_attach_to_handle_scope(env, env->scope, number);

  return 0;
}

int
js_create_double (js_env_t *env, double value, js_value_t **result) {
  JSValueRef number = JSValueMakeNumber(env->context, value);

  *result = (js_value_t *) number;

  js_attach_to_handle_scope(env, env->scope, number);

  return 0;
}

int
js_create_bigint_int64 (js_env_t *env, int64_t value, js_value_t **result) {
  JSObjectRef global = JSContextGetGlobalObject(env->context);

  JSStringRef ref = JSStringCreateWithUTF8CString("BigInt");

  JSValueRef constructor = JSObjectGetProperty(env->context, global, ref, &env->exception);

  JSStringRelease(ref);

  if (env->exception) return js_propagate_exception(env);

  JSValueRef argv[] = {JSValueMakeNumber(env->context, (double) value)};

  JSValueRef bigint = JSObjectCallAsFunction(env->context, (JSObjectRef) constructor, global, 1, argv, &env->exception);

  *result = (js_value_t *) bigint;

  if (env->exception) return js_propagate_exception(env);

  js_attach_to_handle_scope(env, env->scope, bigint);

  return 0;
}

int
js_create_bigint_uint64 (js_env_t *env, uint64_t value, js_value_t **result) {
  JSObjectRef global = JSContextGetGlobalObject(env->context);

  JSStringRef ref = JSStringCreateWithUTF8CString("BigInt");

  JSValueRef constructor = JSObjectGetProperty(env->context, global, ref, &env->exception);

  JSStringRelease(ref);

  if (env->exception) return js_propagate_exception(env);

  JSValueRef argv[] = {JSValueMakeNumber(env->context, (double) value)};

  JSValueRef bigint = JSObjectCallAsFunction(env->context, (JSObjectRef) constructor, global, 1, argv, &env->exception);

  *result = (js_value_t *) bigint;

  if (env->exception) return js_propagate_exception(env);

  js_attach_to_handle_scope(env, env->scope, bigint);

  return 0;
}

int
js_create_string_utf8 (js_env_t *env, const utf8_t *str, size_t len, js_value_t **result) {
  JSStringRef ref;

  if (len == (size_t) -1) len = strlen((char *) str);

  size_t utf16_len = utf16_length_from_utf8(str, len);

  utf16_t *utf16 = malloc(utf16_len * sizeof(utf16_t));

  utf8_convert_to_utf16le((utf8_t *) str, len, utf16);

  ref = JSStringCreateWithCharactersNoCopy(utf16, utf16_len);

  JSValueRef string = JSValueMakeString(env->context, ref);

  *result = (js_value_t *) string;

  JSStringRelease(ref);

  js_attach_to_handle_scope(env, env->scope, string);

  return 0;
}

int
js_create_string_utf16le (js_env_t *env, const utf16_t *str, size_t len, js_value_t **result) {
  JSStringRef ref;

  if (len == (size_t) -1) len = wcslen((wchar_t *) str);

  ref = JSStringCreateWithCharacters(str, len);

  JSValueRef string = JSValueMakeString(env->context, ref);

  *result = (js_value_t *) string;

  JSStringRelease(ref);

  js_attach_to_handle_scope(env, env->scope, string);

  return 0;
}

int
js_create_symbol (js_env_t *env, js_value_t *description, js_value_t **result) {
  JSStringRef ref = JSValueToStringCopy(env->context, (JSValueRef) description, &env->exception);

  if (env->exception) return js_propagate_exception(env);

  JSValueRef symbol = JSValueMakeSymbol(env->context, ref);

  *result = (js_value_t *) symbol;

  JSStringRelease(ref);

  js_attach_to_handle_scope(env, env->scope, symbol);

  return 0;
}

int
js_create_object (js_env_t *env, js_value_t **result) {
  JSObjectRef object = JSObjectMake(env->context, NULL, NULL);

  *result = (js_value_t *) object;

  js_attach_to_handle_scope(env, env->scope, object);

  return 0;
}

static void
on_function_finalize (JSObjectRef external) {
  js_callback_t *callback = (js_callback_t *) JSObjectGetPrivate(external);

  free(callback);
}

static JSValueRef
on_function_call (JSContextRef context, JSObjectRef function, JSObjectRef receiver, size_t argc, const JSValueRef argv[], JSValueRef *exception) {
  int err;

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
    .new_target = JSValueMakeUndefined(env->context),
  };

  js_handle_scope_t *scope;
  err = js_open_handle_scope(env, &scope);
  assert(err == 0);

  js_value_t *result = callback->cb(env, &callback_info);

  err = js_close_handle_scope(env, scope);
  assert(err == 0);

  JSValueRef value;

  if (result == NULL) value = JSValueMakeUndefined(env->context);
  else value = (JSValueRef) result;

  if (env->exception == NULL) return value;

  *exception = env->exception;

  env->exception = NULL;

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
    &env->exception
  );

  assert(env->exception == NULL);

  JSStringRelease(ref);

  *result = (js_value_t *) function;

  js_attach_to_handle_scope(env, env->scope, function);

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

  if (env->exception) return js_propagate_exception(env);

  *result = (js_value_t *) function;

  js_attach_to_handle_scope(env, env->scope, function);

  return 0;
}

int
js_create_function_with_ffi (js_env_t *env, const char *name, size_t len, js_function_cb cb, void *data, js_ffi_function_t *ffi, js_value_t **result) {
  return js_create_function(env, name, len, cb, data, result);
}

int
js_create_array (js_env_t *env, js_value_t **result) {
  JSObjectRef array = JSObjectMakeArray(env->context, 0, NULL, &env->exception);

  if (env->exception) return js_propagate_exception(env);

  *result = (js_value_t *) array;

  js_attach_to_handle_scope(env, env->scope, array);

  return 0;
}

int
js_create_array_with_length (js_env_t *env, size_t len, js_value_t **result) {
  JSValueRef argv[1] = {JSValueMakeNumber(env->context, (double) len)};

  JSObjectRef array = JSObjectMakeArray(env->context, 1, argv, &env->exception);

  if (env->exception) return js_propagate_exception(env);

  *result = (js_value_t *) array;

  js_attach_to_handle_scope(env, env->scope, array);

  return 0;
}

static void
on_external_finalize (JSObjectRef external) {
  js_finalizer_t *finalizer = (js_finalizer_t *) JSObjectGetPrivate(external);

  if (finalizer->finalize_cb) {
    finalizer->finalize_cb(finalizer->env, finalizer->data, finalizer->finalize_hint);
  }

  free(finalizer);
}

int
js_create_external (js_env_t *env, void *data, js_finalize_cb finalize_cb, void *finalize_hint, js_value_t **result) {
  js_finalizer_t *finalizer = malloc(sizeof(js_finalizer_t));

  finalizer->env = env;
  finalizer->data = data;
  finalizer->finalize_cb = finalize_cb;
  finalizer->finalize_hint = finalize_hint;

  JSObjectRef external = JSObjectMake(env->context, env->classes.external, (void *) finalizer);

  *result = (js_value_t *) external;

  js_attach_to_handle_scope(env, env->scope, external);

  return 0;
}

int
js_create_date (js_env_t *env, double time, js_value_t **result) {
  JSObjectRef global = JSContextGetGlobalObject(env->context);

  JSStringRef ref = JSStringCreateWithUTF8CString("Date");

  JSValueRef constructor = JSObjectGetProperty(env->context, global, ref, &env->exception);

  JSStringRelease(ref);

  if (env->exception) return js_propagate_exception(env);

  JSValueRef argv[] = {JSValueMakeNumber(env->context, (double) time)};

  JSValueRef date = JSObjectCallAsConstructor(env->context, (JSObjectRef) constructor, 1, argv, &env->exception);

  if (env->exception) return js_propagate_exception(env);

  *result = (js_value_t *) date;

  js_attach_to_handle_scope(env, env->scope, date);

  return 0;
}

int
js_create_error (js_env_t *env, js_value_t *code, js_value_t *message, js_value_t **result) {
  JSValueRef argv[1] = {(JSValueRef) message};

  JSObjectRef error = JSObjectMakeError(env->context, 1, argv, &env->exception);

  if (env->exception) return js_propagate_exception(env);

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

    if (env->exception) return js_propagate_exception(env);
  }

  *result = (js_value_t *) error;

  js_attach_to_handle_scope(env, env->scope, error);

  return 0;
}

int
js_create_type_error (js_env_t *env, js_value_t *code, js_value_t *message, js_value_t **result) {
  JSObjectRef global = JSContextGetGlobalObject(env->context);

  JSStringRef ref = JSStringCreateWithUTF8CString("TypeError");

  JSValueRef constructor = JSObjectGetProperty(env->context, global, ref, &env->exception);

  JSStringRelease(ref);

  if (env->exception) return js_propagate_exception(env);

  JSValueRef argv[1] = {(JSValueRef) message};

  JSObjectRef error = JSObjectCallAsConstructor(env->context, (JSObjectRef) constructor, 1, argv, &env->exception);

  if (env->exception) return js_propagate_exception(env);

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

    if (env->exception) return js_propagate_exception(env);
  }

  *result = (js_value_t *) error;

  js_attach_to_handle_scope(env, env->scope, error);

  return 0;
}

int
js_create_range_error (js_env_t *env, js_value_t *code, js_value_t *message, js_value_t **result) {
  JSObjectRef global = JSContextGetGlobalObject(env->context);

  JSStringRef ref = JSStringCreateWithUTF8CString("RangeError");

  JSValueRef constructor = JSObjectGetProperty(env->context, global, ref, &env->exception);

  JSStringRelease(ref);

  if (env->exception) return js_propagate_exception(env);

  JSValueRef argv[1] = {(JSValueRef) message};

  JSObjectRef error = JSObjectCallAsConstructor(env->context, (JSObjectRef) constructor, 1, argv, &env->exception);

  if (env->exception) return js_propagate_exception(env);

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

    if (env->exception) return js_propagate_exception(env);
  }

  *result = (js_value_t *) error;

  js_attach_to_handle_scope(env, env->scope, error);

  return 0;
}

int
js_create_syntax_error (js_env_t *env, js_value_t *code, js_value_t *message, js_value_t **result) {
  JSObjectRef global = JSContextGetGlobalObject(env->context);

  JSStringRef ref = JSStringCreateWithUTF8CString("SyntaxError");

  JSValueRef constructor = JSObjectGetProperty(env->context, global, ref, &env->exception);

  JSStringRelease(ref);

  if (env->exception) return js_propagate_exception(env);

  JSValueRef argv[1] = {(JSValueRef) message};

  JSObjectRef error = JSObjectCallAsConstructor(env->context, (JSObjectRef) constructor, 1, argv, &env->exception);

  if (env->exception) return js_propagate_exception(env);

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

    if (env->exception) return js_propagate_exception(env);
  }

  *result = (js_value_t *) error;

  js_attach_to_handle_scope(env, env->scope, error);

  return 0;
}

int
js_create_promise (js_env_t *env, js_deferred_t **deferred, js_value_t **promise) {
  JSObjectRef resolve, reject;

  JSObjectRef value = JSObjectMakeDeferredPromise(env->context, &resolve, &reject, &env->exception);

  if (env->exception) return js_propagate_exception(env);

  js_deferred_t *result = malloc(sizeof(js_deferred_t));

  result->resolve = resolve;
  result->reject = reject;

  *deferred = result;
  *promise = (js_value_t *) value;

  js_attach_to_handle_scope(env, env->scope, value);

  return 0;
}

int
js_resolve_deferred (js_env_t *env, js_deferred_t *deferred, js_value_t *resolution) {
  JSValueRef argv[1] = {(JSValueRef) resolution};

  JSObjectCallAsFunction(env->context, deferred->resolve, NULL, 1, argv, &env->exception);

  if (env->exception) return js_propagate_exception(env);

  return 0;
}

int
js_reject_deferred (js_env_t *env, js_deferred_t *deferred, js_value_t *resolution) {
  JSValueRef argv[1] = {(JSValueRef) resolution};

  JSObjectCallAsFunction(env->context, deferred->reject, NULL, 1, argv, &env->exception);

  if (env->exception) return js_propagate_exception(env);

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

  if (env->exception) return js_propagate_exception(env);

  JSObjectRef arraybuffer = JSObjectGetTypedArrayBuffer(env->context, typedarray, &env->exception);

  if (env->exception) return js_propagate_exception(env);

  *result = (js_value_t *) arraybuffer;

  if (data) {
    *data = JSObjectGetArrayBufferBytesPtr(env->context, arraybuffer, &env->exception);

    if (env->exception) return js_propagate_exception(env);
  }

  js_attach_to_handle_scope(env, env->scope, arraybuffer);

  return 0;
}

static void
on_backed_arraybuffer_finalize (void *bytes, void *deallocatorContext) {
  js_arraybuffer_backing_store_t *backing_store = (js_arraybuffer_backing_store_t *) deallocatorContext;

  if (--backing_store->references == 0) {
    JSValueUnprotect(backing_store->env->context, backing_store->owner);

    free(backing_store);
  }
}

int
js_create_arraybuffer_with_backing_store (js_env_t *env, js_arraybuffer_backing_store_t *backing_store, void **data, size_t *len, js_value_t **result) {
  JSObjectRef arraybuffer = JSObjectMakeArrayBufferWithBytesNoCopy(env->context, backing_store->data, backing_store->len, on_backed_arraybuffer_finalize, backing_store, &env->exception);

  if (env->exception) return js_propagate_exception(env);

  backing_store->references++;

  *result = (js_value_t *) arraybuffer;

  if (data) {
    *data = backing_store->data;
  }

  if (len) {
    *len = backing_store->len;
  }

  js_attach_to_handle_scope(env, env->scope, arraybuffer);

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

    return js_propagate_exception(env);
  }

  *result = (js_value_t *) arraybuffer;

  if (data) {
    *data = bytes;
  }

  js_attach_to_handle_scope(env, env->scope, arraybuffer);

  return 0;
}

static void
on_external_arraybuffer_finalize (void *bytes, void *deallocatorContext) {
  js_finalizer_t *finalizer = (js_finalizer_t *) deallocatorContext;

  if (finalizer->finalize_cb) {
    finalizer->finalize_cb(finalizer->env, finalizer->data, finalizer->finalize_hint);
  }

  free(finalizer);
}

int
js_create_external_arraybuffer (js_env_t *env, void *data, size_t len, js_finalize_cb finalize_cb, void *finalize_hint, js_value_t **result) {
  js_finalizer_t *finalizer = malloc(sizeof(js_finalizer_t));

  finalizer->env = env;
  finalizer->data = data;
  finalizer->finalize_cb = finalize_cb;
  finalizer->finalize_hint = finalize_hint;

  JSObjectRef arraybuffer = JSObjectMakeArrayBufferWithBytesNoCopy(env->context, data, len, on_external_arraybuffer_finalize, (void *) finalizer, &env->exception);

  if (env->exception) {
    free(finalizer);

    return js_propagate_exception(env);
  }

  *result = (js_value_t *) arraybuffer;

  js_attach_to_handle_scope(env, env->scope, arraybuffer);

  return 0;
}

// https://bugs.webkit.org/show_bug.cgi?id=250552
int
js_detach_arraybuffer (js_env_t *env, js_value_t *arraybuffer) {
  js_throw_error(env, NULL, "Unsupported operation");

  return -1;
}

int
js_get_arraybuffer_backing_store (js_env_t *env, js_value_t *arraybuffer, js_arraybuffer_backing_store_t **result) {
  js_arraybuffer_backing_store_t *backing_store = malloc(sizeof(js_arraybuffer_backing_store_t));

  backing_store->env = env;
  backing_store->references = 1;

  backing_store->data = JSObjectGetArrayBufferBytesPtr(env->context, (JSObjectRef) arraybuffer, &env->exception);

  if (env->exception) {
    free(backing_store);

    return js_propagate_exception(env);
  }

  backing_store->len = JSObjectGetArrayBufferByteLength(env->context, (JSObjectRef) arraybuffer, &env->exception);

  if (env->exception) {
    free(backing_store);

    return js_propagate_exception(env);
  }

  backing_store->owner = (JSValueRef) arraybuffer;

  JSValueProtect(env->context, backing_store->owner);

  *result = backing_store;

  return 0;
}

// https://bugs.webkit.org/show_bug.cgi?id=257709
int
js_create_sharedarraybuffer (js_env_t *env, size_t len, void **data, js_value_t **result) {
  js_throw_error(env, NULL, "Unsupported operation");

  return -1;
}

// https://bugs.webkit.org/show_bug.cgi?id=257709
int
js_create_sharedarraybuffer_with_backing_store (js_env_t *env, js_arraybuffer_backing_store_t *backing_store, void **data, size_t *len, js_value_t **result) {
  js_throw_error(env, NULL, "Unsupported operation");

  return -1;
}

// https://bugs.webkit.org/show_bug.cgi?id=257709
int
js_create_unsafe_sharedarraybuffer (js_env_t *env, size_t len, void **data, js_value_t **result) {
  js_throw_error(env, NULL, "Unsupported operation");

  return -1;
}

// https://bugs.webkit.org/show_bug.cgi?id=257709
int
js_get_sharedarraybuffer_backing_store (js_env_t *env, js_value_t *sharedarraybuffer, js_arraybuffer_backing_store_t **result) {
  js_throw_error(env, NULL, "Unsupported operation");

  return -1;
}

int
js_release_arraybuffer_backing_store (js_env_t *env, js_arraybuffer_backing_store_t *backing_store) {
  if (--backing_store->references == 0) {
    JSValueUnprotect(env->context, backing_store->owner);

    free(backing_store);
  }

  return 0;
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

  if (env->exception) return js_propagate_exception(env);

  *result = (js_value_t *) typedarray;

  js_attach_to_handle_scope(env, env->scope, typedarray);

  return 0;
}

int
js_create_dataview (js_env_t *env, size_t len, js_value_t *arraybuffer, size_t offset, js_value_t **result) {
  JSStringRef ref = JSStringCreateWithUTF8CString("DataView");

  JSValueRef constructor = JSObjectGetProperty(env->context, JSContextGetGlobalObject(env->context), ref, &env->exception);

  JSStringRelease(ref);

  if (env->exception) return js_propagate_exception(env);

  JSValueRef argv[3] = {(JSValueRef) arraybuffer, JSValueMakeNumber(env->context, offset), JSValueMakeNumber(env->context, len)};

  JSObjectRef dataview = JSObjectCallAsConstructor(env->context, (JSObjectRef) constructor, 3, argv, &env->exception);

  if (env->exception) return js_propagate_exception(env);

  *result = (js_value_t *) dataview;

  js_attach_to_handle_scope(env, env->scope, dataview);

  return 0;
}

int
js_coerce_to_boolean (js_env_t *env, js_value_t *value, js_value_t **result) {
  JSValueRef boolean = JSValueMakeBoolean(env->context, JSValueToBoolean(env->context, (JSValueRef) value));

  *result = (js_value_t *) boolean;

  js_attach_to_handle_scope(env, env->scope, boolean);

  return 0;
}

int
js_coerce_to_number (js_env_t *env, js_value_t *value, js_value_t **result) {
  JSValueRef number = JSValueMakeNumber(env->context, JSValueToNumber(env->context, (JSValueRef) value, &env->exception));

  if (env->exception) return js_propagate_exception(env);

  *result = (js_value_t *) number;

  js_attach_to_handle_scope(env, env->scope, number);

  return 0;
}

int
js_coerce_to_string (js_env_t *env, js_value_t *value, js_value_t **result) {
  JSStringRef ref = JSValueToStringCopy(env->context, (JSValueRef) value, &env->exception);

  if (env->exception) return js_propagate_exception(env);

  JSValueRef string = JSValueMakeString(env->context, ref);

  JSStringRelease(ref);

  *result = (js_value_t *) string;

  js_attach_to_handle_scope(env, env->scope, string);

  return 0;
}

int
js_coerce_to_object (js_env_t *env, js_value_t *value, js_value_t **result) {
  JSObjectRef object = JSValueToObject(env->context, (JSValueRef) value, &env->exception);

  if (env->exception) return js_propagate_exception(env);

  *result = (js_value_t *) object;

  js_attach_to_handle_scope(env, env->scope, object);

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
js_instanceof (js_env_t *env, js_value_t *object, js_value_t *constructor, bool *result) {
  *result = JSValueIsInstanceOfConstructor(env->context, (JSValueRef) object, (JSObjectRef) constructor, &env->exception);

  if (env->exception) return js_propagate_exception(env);

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

int
js_is_wrapped (js_env_t *env, js_value_t *value, bool *result) {
  JSStringRef ref = JSStringCreateWithUTF8CString("__native_external");

  *result = JSValueIsObject(env->context, (JSValueRef) value) && JSObjectHasProperty(env->context, (JSObjectRef) value, ref);

  JSStringRelease(ref);

  return 0;
}

int
js_is_delegate (js_env_t *env, js_value_t *value, bool *result) {
  *result = JSValueIsObjectOfClass(env->context, (JSValueRef) value, env->classes.delegate);

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

  if (env->exception) return js_propagate_exception(env);

  *result = JSValueIsInstanceOfConstructor(env->context, (JSValueRef) value, (JSObjectRef) constructor, &env->exception);

  if (env->exception) return js_propagate_exception(env);

  return 0;
}

int
js_is_promise (js_env_t *env, js_value_t *value, bool *result) {
  JSStringRef ref = JSStringCreateWithUTF8CString("Promise");

  JSValueRef constructor = JSObjectGetProperty(env->context, JSContextGetGlobalObject(env->context), ref, &env->exception);

  JSStringRelease(ref);

  if (env->exception) return js_propagate_exception(env);

  *result = JSValueIsInstanceOfConstructor(env->context, (JSValueRef) value, (JSObjectRef) constructor, &env->exception);

  if (env->exception) return js_propagate_exception(env);

  return 0;
}

int
js_is_arraybuffer (js_env_t *env, js_value_t *value, bool *result) {
  JSTypedArrayType type = JSValueGetTypedArrayType(env->context, (JSValueRef) value, &env->exception);

  if (env->exception) return js_propagate_exception(env);

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
js_is_sharedarraybuffer (js_env_t *env, js_value_t *value, bool *result) {
  JSStringRef ref = JSStringCreateWithUTF8CString("SharedArrayBuffer");

  JSValueRef constructor = JSObjectGetProperty(env->context, JSContextGetGlobalObject(env->context), ref, &env->exception);

  JSStringRelease(ref);

  if (env->exception) return js_propagate_exception(env);

  if (JSValueIsUndefined(env->context, constructor)) {
    *result = false;
  } else {
    *result = JSValueIsInstanceOfConstructor(env->context, (JSValueRef) value, (JSObjectRef) constructor, &env->exception);

    if (env->exception) return js_propagate_exception(env);
  }

  return 0;
}

int
js_is_typedarray (js_env_t *env, js_value_t *value, bool *result) {
  JSTypedArrayType type = JSValueGetTypedArrayType(env->context, (JSValueRef) value, &env->exception);

  if (env->exception) return js_propagate_exception(env);

  *result = type != kJSTypedArrayTypeNone && type != kJSTypedArrayTypeArrayBuffer;

  return 0;
}

int
js_is_dataview (js_env_t *env, js_value_t *value, bool *result) {
  JSStringRef ref = JSStringCreateWithUTF8CString("DataView");

  JSValueRef constructor = JSObjectGetProperty(env->context, JSContextGetGlobalObject(env->context), ref, &env->exception);

  JSStringRelease(ref);

  if (env->exception) return js_propagate_exception(env);

  *result = JSValueIsInstanceOfConstructor(env->context, (JSValueRef) value, (JSObjectRef) constructor, &env->exception);

  if (env->exception) return js_propagate_exception(env);

  return 0;
}

int
js_strict_equals (js_env_t *env, js_value_t *a, js_value_t *b, bool *result) {
  *result = JSValueIsStrictEqual(env->context, (JSValueRef) a, (JSValueRef) b);

  return 0;
}

int
js_get_global (js_env_t *env, js_value_t **result) {
  JSObjectRef global = JSContextGetGlobalObject(env->context);

  *result = (js_value_t *) global;

  js_attach_to_handle_scope(env, env->scope, global);

  return 0;
}

int
js_get_undefined (js_env_t *env, js_value_t **result) {
  JSValueRef undefined = JSValueMakeUndefined(env->context);

  *result = (js_value_t *) undefined;

  js_attach_to_handle_scope(env, env->scope, undefined);

  return 0;
}

int
js_get_null (js_env_t *env, js_value_t **result) {
  JSValueRef null = JSValueMakeNull(env->context);

  *result = (js_value_t *) null;

  js_attach_to_handle_scope(env, env->scope, null);

  return 0;
}

int
js_get_boolean (js_env_t *env, bool value, js_value_t **result) {
  JSValueRef boolean = JSValueMakeBoolean(env->context, value);

  *result = (js_value_t *) boolean;

  js_attach_to_handle_scope(env, env->scope, boolean);

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

  if (env->exception) return js_propagate_exception(env);

  *result = (int32_t) number;

  return 0;
}

int
js_get_value_uint32 (js_env_t *env, js_value_t *value, uint32_t *result) {
  double number = JSValueToNumber(env->context, (JSValueRef) value, &env->exception);

  if (env->exception) return js_propagate_exception(env);

  *result = (uint32_t) number;

  return 0;
}

int
js_get_value_int64 (js_env_t *env, js_value_t *value, int64_t *result) {
  double number = JSValueToNumber(env->context, (JSValueRef) value, &env->exception);

  if (env->exception) return js_propagate_exception(env);

  *result = (int64_t) number;

  return 0;
}

int
js_get_value_double (js_env_t *env, js_value_t *value, double *result) {
  double number = JSValueToNumber(env->context, (JSValueRef) value, &env->exception);

  if (env->exception) return js_propagate_exception(env);

  *result = number;

  return 0;
}

// https://bugs.webkit.org/show_bug.cgi?id=250511
int
js_get_value_bigint_int64 (js_env_t *env, js_value_t *value, int64_t *result, bool *lossless) {
  js_throw_error(env, NULL, "Unsupported operation");

  return -1;
}

// https://bugs.webkit.org/show_bug.cgi?id=250511
int
js_get_value_bigint_uint64 (js_env_t *env, js_value_t *value, uint64_t *result, bool *lossless) {
  js_throw_error(env, NULL, "Unsupported operation");

  return -1;
}

int
js_get_value_string_utf8 (js_env_t *env, js_value_t *value, utf8_t *str, size_t len, size_t *result) {
  JSStringRef ref = JSValueToStringCopy(env->context, (JSValueRef) value, &env->exception);

  if (env->exception) return js_propagate_exception(env);

  size_t utf16_len = JSStringGetLength(ref);

  const JSChar *utf16 = JSStringGetCharactersPtr(ref);

  if (str == NULL) {
    *result = utf8_length_from_utf16le(utf16, utf16_len);
  } else if (len != 0) {
    size_t written = utf16le_convert_to_utf8(utf16, utf16_len, str);

    if (written < len) str[written] = '\0';

    if (result) *result = written;
  } else if (result) *result = 0;

  JSStringRelease(ref);

  return 0;
}

int
js_get_value_string_utf16le (js_env_t *env, js_value_t *value, utf16_t *str, size_t len, size_t *result) {
  JSStringRef ref = JSValueToStringCopy(env->context, (JSValueRef) value, &env->exception);

  if (env->exception) return js_propagate_exception(env);

  size_t utf16_len = JSStringGetLength(ref);

  const JSChar *utf16 = JSStringGetCharactersPtr(ref);

  if (str == NULL) {
    *result = utf16_len;
  } else if (len != 0) {
    size_t written = len < utf16_len ? len : utf16_len;

    memcpy(str, utf16, written * sizeof(utf16_t));

    if (written < len) str[written] = L'\0';

    if (result) *result = written;
  } else if (result) *result = 0;

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

  if (env->exception) return js_propagate_exception(env);

  return 0;
}

int
js_get_array_length (js_env_t *env, js_value_t *value, uint32_t *result) {
  JSStringRef ref = JSStringCreateWithUTF8CString("length");

  JSValueRef length = JSObjectGetProperty(env->context, (JSObjectRef) value, ref, &env->exception);

  JSStringRelease(ref);

  if (env->exception) return js_propagate_exception(env);

  *result = (uint32_t) JSValueToNumber(env->context, length, &env->exception);

  if (env->exception) return js_propagate_exception(env);

  return 0;
}

int
js_get_prototype (js_env_t *env, js_value_t *object, js_value_t **result) {
  JSValueRef prototype = JSObjectGetPrototype(env->context, (JSObjectRef) object);

  *result = (js_value_t *) prototype;

  js_attach_to_handle_scope(env, env->scope, prototype);

  return 0;
}

int
js_get_property_names (js_env_t *env, js_value_t *object, js_value_t **result) {
  env->depth++;

  JSPropertyNameArrayRef properties = JSObjectCopyPropertyNames(env->context, (JSObjectRef) object);

  env->depth--;

  if (env->exception) return js_propagate_exception(env);

  size_t len = JSPropertyNameArrayGetCount(properties);

  JSValueRef argv[1] = {JSValueMakeNumber(env->context, (double) len)};

  JSObjectRef array = JSObjectMakeArray(env->context, 1, argv, &env->exception);

  if (env->exception) goto err;

  for (size_t i = 0; i < len; i++) {
    JSStringRef name = JSPropertyNameArrayGetNameAtIndex(properties, i);

    JSObjectSetPropertyAtIndex(env->context, array, i, JSValueMakeString(env->context, name), &env->exception);

    if (env->exception) goto err;
  }

  JSPropertyNameArrayRelease(properties);

  if (result) {
    *result = (js_value_t *) array;

    js_attach_to_handle_scope(env, env->scope, array);
  }

  return 0;

err:
  JSPropertyNameArrayRelease(properties);

  return js_propagate_exception(env);
}

int
js_get_property (js_env_t *env, js_value_t *object, js_value_t *key, js_value_t **result) {
  env->depth++;

  JSValueRef value = JSObjectGetPropertyForKey(env->context, (JSObjectRef) object, (JSValueRef) key, &env->exception);

  env->depth--;

  if (env->exception) return js_propagate_exception(env);

  if (result) {
    *result = (js_value_t *) value;

    js_attach_to_handle_scope(env, env->scope, value);
  }

  return 0;
}

int
js_has_property (js_env_t *env, js_value_t *object, js_value_t *key, bool *result) {
  env->depth++;

  bool value = JSObjectHasPropertyForKey(env->context, (JSObjectRef) object, (JSValueRef) key, &env->exception);

  env->depth--;

  if (env->exception) return js_propagate_exception(env);

  if (result) *result = value;

  return 0;
}

int
js_set_property (js_env_t *env, js_value_t *object, js_value_t *key, js_value_t *value) {
  env->depth++;

  JSObjectSetPropertyForKey(env->context, (JSObjectRef) object, (JSValueRef) key, (JSValueRef) value, kJSPropertyAttributeNone, &env->exception);

  env->depth--;

  if (env->exception) return js_propagate_exception(env);

  return 0;
}

int
js_delete_property (js_env_t *env, js_value_t *object, js_value_t *key, bool *result) {
  env->depth++;

  bool value = JSObjectDeletePropertyForKey(env->context, (JSObjectRef) object, (JSValueRef) key, &env->exception);

  env->depth--;

  if (env->exception) return js_propagate_exception(env);

  if (result) *result = value;

  return 0;
}

int
js_get_named_property (js_env_t *env, js_value_t *object, const char *name, js_value_t **result) {
  JSStringRef ref = JSStringCreateWithUTF8CString(name);

  env->depth++;

  JSValueRef value = JSObjectGetProperty(env->context, (JSObjectRef) object, ref, &env->exception);

  env->depth--;

  JSStringRelease(ref);

  if (env->exception) return js_propagate_exception(env);

  if (result) {
    *result = (js_value_t *) value;

    js_attach_to_handle_scope(env, env->scope, value);
  }

  return 0;
}

int
js_has_named_property (js_env_t *env, js_value_t *object, const char *name, bool *result) {
  JSStringRef ref = JSStringCreateWithUTF8CString(name);

  env->depth++;

  bool value = JSObjectHasPropertyForKey(env->context, (JSObjectRef) object, JSValueMakeString(env->context, ref), &env->exception);

  env->depth--;

  JSStringRelease(ref);

  if (env->exception) return js_propagate_exception(env);

  if (result) *result = value;

  return 0;
}

int
js_set_named_property (js_env_t *env, js_value_t *object, const char *name, js_value_t *value) {
  JSStringRef ref = JSStringCreateWithUTF8CString(name);

  env->depth++;

  JSObjectSetProperty(env->context, (JSObjectRef) object, ref, (JSValueRef) value, kJSPropertyAttributeNone, &env->exception);

  env->depth--;

  JSStringRelease(ref);

  if (env->exception) return js_propagate_exception(env);

  return 0;
}

int
js_delete_named_property (js_env_t *env, js_value_t *object, const char *name, bool *result) {
  JSStringRef ref = JSStringCreateWithUTF8CString(name);

  env->depth++;

  bool value = JSObjectDeleteProperty(env->context, (JSObjectRef) object, ref, &env->exception);

  env->depth--;

  JSStringRelease(ref);

  if (env->exception) return js_propagate_exception(env);

  if (result) *result = value;

  return 0;
}

int
js_get_element (js_env_t *env, js_value_t *object, uint32_t index, js_value_t **result) {
  env->depth++;

  JSValueRef value = JSObjectGetPropertyAtIndex(env->context, (JSObjectRef) object, index, &env->exception);

  env->depth--;

  if (env->exception) return js_propagate_exception(env);

  if (result) {
    *result = (js_value_t *) value;

    js_attach_to_handle_scope(env, env->scope, value);
  }

  return 0;
}

int
js_has_element (js_env_t *env, js_value_t *object, uint32_t index, bool *result) {
  JSValueRef key = JSValueMakeNumber(env->context, (double) index);

  env->depth++;

  bool value = JSObjectHasPropertyForKey(env->context, (JSObjectRef) object, key, &env->exception);

  env->depth--;

  if (env->exception) return js_propagate_exception(env);

  if (result) *result = value;

  return 0;
}

int
js_set_element (js_env_t *env, js_value_t *object, uint32_t index, js_value_t *value) {
  env->depth++;

  JSObjectSetPropertyAtIndex(env->context, (JSObjectRef) object, index, (JSValueRef) value, &env->exception);

  env->depth--;

  if (env->exception) return js_propagate_exception(env);

  return 0;
}

int
js_delete_element (js_env_t *env, js_value_t *object, uint32_t index, bool *result) {
  JSValueRef key = JSValueMakeNumber(env->context, (double) index);

  env->depth++;

  bool value = JSObjectDeletePropertyForKey(env->context, (JSObjectRef) object, key, &env->exception);

  env->depth--;

  if (env->exception) return js_propagate_exception(env);

  if (result) *result = value;

  return 0;
}

int
js_get_callback_info (js_env_t *env, const js_callback_info_t *info, size_t *argc, js_value_t *argv[], js_value_t **receiver, void **data) {
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

  if (receiver) {
    *receiver = (js_value_t *) info->receiver;
  }

  if (data) {
    *data = info->callback->data;
  }

  return 0;
}

int
js_get_new_target (js_env_t *env, const js_callback_info_t *info, js_value_t **result) {
  *result = (js_value_t *) info->new_target;

  return 0;
}

int
js_get_arraybuffer_info (js_env_t *env, js_value_t *arraybuffer, void **pdata, size_t *plen) {
  uint8_t *data = JSObjectGetArrayBufferBytesPtr(env->context, (JSObjectRef) arraybuffer, &env->exception);

  if (env->exception) return js_propagate_exception(env);

  size_t len = JSObjectGetArrayBufferByteLength(env->context, (JSObjectRef) arraybuffer, &env->exception);

  if (env->exception) return js_propagate_exception(env);

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
  size_t offset;

  JSObjectRef arraybuffer;

  if (pdata || poffset) {
    offset = JSObjectGetTypedArrayByteOffset(env->context, (JSObjectRef) typedarray, &env->exception);

    if (env->exception) return js_propagate_exception(env);
  }

  if (pdata || parraybuffer) {
    arraybuffer = JSObjectGetTypedArrayBuffer(env->context, (JSObjectRef) typedarray, &env->exception);

    if (env->exception) return js_propagate_exception(env);
  }

  if (ptype) {
    JSTypedArrayType type = JSValueGetTypedArrayType(env->context, (JSValueRef) typedarray, &env->exception);

    if (env->exception) return js_propagate_exception(env);

    *ptype = js_convert_to_typedarray_type(type);
  }

  if (pdata) {
    void *data = JSObjectGetArrayBufferBytesPtr(env->context, arraybuffer, &env->exception);

    if (env->exception) return js_propagate_exception(env);

    *pdata = data + offset;
  }

  if (plen) {
    size_t len = JSObjectGetTypedArrayLength(env->context, (JSObjectRef) typedarray, &env->exception);

    if (env->exception) return js_propagate_exception(env);

    *plen = len;
  }

  if (parraybuffer) {
    *parraybuffer = (js_value_t *) arraybuffer;

    js_attach_to_handle_scope(env, env->scope, arraybuffer);
  }

  if (poffset) {
    *poffset = offset;
  }

  return 0;
}

int
js_get_dataview_info (js_env_t *env, js_value_t *dataview, void **pdata, size_t *plen, js_value_t **parraybuffer, size_t *poffset) {
  size_t offset;

  JSObjectRef arraybuffer;

  if (pdata || poffset) {
    JSStringRef ref = JSStringCreateWithUTF8CString("byteOffset");

    JSValueRef value = JSObjectGetProperty(env->context, (JSObjectRef) dataview, ref, &env->exception);

    JSStringRelease(ref);

    if (env->exception) return js_propagate_exception(env);

    offset = (size_t) JSValueToNumber(env->context, value, &env->exception);

    if (env->exception) return js_propagate_exception(env);
  }

  if (pdata || parraybuffer) {
    JSStringRef ref = JSStringCreateWithUTF8CString("buffer");

    arraybuffer = (JSObjectRef) JSObjectGetProperty(env->context, (JSObjectRef) dataview, ref, &env->exception);

    JSStringRelease(ref);

    if (env->exception) return js_propagate_exception(env);
  }

  if (pdata) {
    void *data = JSObjectGetArrayBufferBytesPtr(env->context, arraybuffer, &env->exception);

    if (env->exception) return js_propagate_exception(env);

    *pdata = data + offset;
  }

  if (plen) {
    JSStringRef ref = JSStringCreateWithUTF8CString("byteLength");

    JSValueRef value = JSObjectGetProperty(env->context, (JSObjectRef) dataview, ref, &env->exception);

    JSStringRelease(ref);

    if (env->exception) return js_propagate_exception(env);

    double len = JSValueToNumber(env->context, value, &env->exception);

    if (env->exception) return js_propagate_exception(env);

    *plen = (size_t) len;
  }

  if (parraybuffer) {
    *parraybuffer = (js_value_t *) arraybuffer;

    js_attach_to_handle_scope(env, env->scope, arraybuffer);
  }

  if (poffset) {
    *poffset = offset;
  }

  return 0;
}

int
js_call_function (js_env_t *env, js_value_t *receiver, js_value_t *function, size_t argc, js_value_t *const argv[], js_value_t **result) {
  env->depth++;

  JSValueRef value = JSObjectCallAsFunction(env->context, (JSObjectRef) function, (JSObjectRef) receiver, argc, (const JSValueRef *) argv, &env->exception);

  env->depth--;

  if (env->exception) return js_propagate_exception(env);

  if (result) {
    *result = (js_value_t *) value;

    js_attach_to_handle_scope(env, env->scope, value);
  }

  return 0;
}

int
js_call_function_with_checkpoint (js_env_t *env, js_value_t *receiver, js_value_t *function, size_t argc, js_value_t *const argv[], js_value_t **result) {
  env->depth++;

  JSValueRef value = JSObjectCallAsFunction(env->context, (JSObjectRef) function, (JSObjectRef) receiver, argc, (const JSValueRef *) argv, &env->exception);

  env->depth--;

  if (env->exception) return js_propagate_exception(env);

  if (result) *result = (js_value_t *) value;

  return 0;
}

int
js_new_instance (js_env_t *env, js_value_t *constructor, size_t argc, js_value_t *const argv[], js_value_t **result) {
  env->depth++;

  JSValueRef value = JSObjectCallAsConstructor(env->context, (JSObjectRef) constructor, argc, (const JSValueRef *) argv, &env->exception);

  env->depth--;

  if (env->exception) return js_propagate_exception(env);

  if (result) {
    *result = (js_value_t *) value;

    js_attach_to_handle_scope(env, env->scope, value);
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
  va_list args_copy;
  va_copy(args_copy, args);

  int res = vsnprintf(NULL, 0, message, args_copy);

  va_end(args_copy);

  if (res < 0) return res;

  *size = res + 1 /* NULL */;
  *result = malloc(*size);

  va_copy(args_copy, args);

  vsnprintf(*result, *size, message, args_copy);

  va_end(args_copy);

  return 0;
}

int
js_throw_error (js_env_t *env, const char *code, const char *message) {
  JSStringRef ref = JSStringCreateWithUTF8CString(message);

  JSValueRef argv[1] = {JSValueMakeString(env->context, ref)};

  JSStringRelease(ref);

  JSObjectRef error = JSObjectMakeError(env->context, 1, argv, &env->exception);

  if (env->exception) return js_propagate_exception(env);

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

    if (env->exception) return js_propagate_exception(env);
  }

  env->exception = error;

  js_propagate_exception(env);

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
js_throw_errorf (js_env_t *env, const char *code, const char *message, ...) {
  va_list args;
  va_start(args, message);

  int err = js_throw_verrorf(env, code, message, args);

  va_end(args);

  return err;
}

int
js_throw_type_error (js_env_t *env, const char *code, const char *message) {
  JSObjectRef global = JSContextGetGlobalObject(env->context);

  JSStringRef ref = JSStringCreateWithUTF8CString("TypeError");

  JSValueRef constructor = JSObjectGetProperty(env->context, global, ref, &env->exception);

  JSStringRelease(ref);

  if (env->exception) return js_propagate_exception(env);

  ref = JSStringCreateWithUTF8CString(message);

  JSValueRef argv[1] = {JSValueMakeString(env->context, ref)};

  JSStringRelease(ref);

  JSObjectRef error = JSObjectCallAsConstructor(env->context, (JSObjectRef) constructor, 1, argv, &env->exception);

  if (env->exception) return js_propagate_exception(env);

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

    if (env->exception) return js_propagate_exception(env);
  }

  env->exception = error;

  js_propagate_exception(env);

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
js_throw_type_errorf (js_env_t *env, const char *code, const char *message, ...) {
  va_list args;
  va_start(args, message);

  int err = js_throw_type_verrorf(env, code, message, args);

  va_end(args);

  return err;
}

int
js_throw_range_error (js_env_t *env, const char *code, const char *message) {
  JSObjectRef global = JSContextGetGlobalObject(env->context);

  JSStringRef ref = JSStringCreateWithUTF8CString("RangeError");

  JSValueRef constructor = JSObjectGetProperty(env->context, global, ref, &env->exception);

  JSStringRelease(ref);

  if (env->exception) return js_propagate_exception(env);

  ref = JSStringCreateWithUTF8CString(message);

  JSValueRef argv[1] = {JSValueMakeString(env->context, ref)};

  JSStringRelease(ref);

  JSObjectRef error = JSObjectCallAsConstructor(env->context, (JSObjectRef) constructor, 1, argv, &env->exception);

  if (env->exception) return js_propagate_exception(env);

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

    if (env->exception) return js_propagate_exception(env);
  }

  env->exception = error;

  js_propagate_exception(env);

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
js_throw_range_errorf (js_env_t *env, const char *code, const char *message, ...) {
  va_list args;
  va_start(args, message);

  int err = js_throw_range_verrorf(env, code, message, args);

  va_end(args);

  return err;
}

int
js_throw_syntax_error (js_env_t *env, const char *code, const char *message) {
  JSObjectRef global = JSContextGetGlobalObject(env->context);

  JSStringRef ref = JSStringCreateWithUTF8CString("SyntaxError");

  JSValueRef constructor = JSObjectGetProperty(env->context, global, ref, &env->exception);

  JSStringRelease(ref);

  if (env->exception) return js_propagate_exception(env);

  ref = JSStringCreateWithUTF8CString(message);

  JSValueRef argv[1] = {JSValueMakeString(env->context, ref)};

  JSStringRelease(ref);

  JSObjectRef error = JSObjectCallAsConstructor(env->context, (JSObjectRef) constructor, 1, argv, &env->exception);

  if (env->exception) return js_propagate_exception(env);

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

    if (env->exception) return js_propagate_exception(env);
  }

  env->exception = error;

  js_propagate_exception(env);

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
js_throw_syntax_errorf (js_env_t *env, const char *code, const char *message, ...) {
  va_list args;
  va_start(args, message);

  int err = js_throw_syntax_verrorf(env, code, message, args);

  va_end(args);

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

  js_attach_to_handle_scope(env, env->scope, env->exception);

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

  if (result) *result = env->external_memory;

  return 0;
}

int
js_request_garbage_collection (js_env_t *env) {
  if (!env->platform->options.expose_garbage_collection) {
    js_throw_error(env, NULL, "Garbage collection is unavailable");

    return -1;
  }

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
