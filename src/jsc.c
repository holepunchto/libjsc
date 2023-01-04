#include <js.h>
#include <uv.h>

#include <JavaScriptCore/JavaScriptCore.h>

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
js_run_script (js_env_t *env, js_value_t *source, js_value_t **result) {
  JSStringRef ref = JSValueToStringCopy(env->context, (JSValueRef) source, &env->exception);

  if (env->exception) return -1;

  JSValueRef value = JSEvaluateScript(env->context, ref, NULL, NULL, 1, &env->exception);

  JSStringRelease(ref);

  if (env->exception) return -1;

  *result = (js_value_t *) value;

  return 0;
}

int
js_create_string_utf8 (js_env_t *env, const char *str, size_t len, js_value_t **result) {
  JSStringRef ref = JSStringCreateWithUTF8CString(str);

  *result = (js_value_t *) JSValueMakeString(env->context, ref);

  JSStringRelease(ref);

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
