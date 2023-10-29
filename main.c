#include <janet.h>

int pledge(const char *promises, const char *execpromises);
int unveil(const char *path, const char *permissions);

static Janet janet_pledge(int32_t argc, Janet *argv) {
    if (argc != 1 && argc != 2){
        janet_panicf("expected 1 or 2 arguments");
    }
    if (!janet_checktype(argv[0], JANET_STRING)) {
        janet_panicf("expected string, got %v", argv[0]);
    }
    JanetString prom = janet_unwrap_string(argv[0]);
    JanetString eprom = NULL;
    if (argc == 2) {
        if (!janet_checktype(argv[1], JANET_STRING)) {
            janet_panicf("expected string, got %v", argv[1]);
        }
        eprom = janet_unwrap_string(argv[1]);
    }

    int ret = pledge((char *) prom, eprom);
    
    return janet_wrap_number(ret);
}

static Janet janet_unveil(int32_t argc, Janet *argv) {
    if (argc != 0 && argc != 2){
        janet_panicf("expected 0 or 2 arguments");
    }
    int ret = 0;
    if (argc == 2) {
        if (!janet_checktype(argv[0], JANET_STRING)) {
            janet_panicf("expected string, got %v", argv[0]);
        }
        JanetString path = janet_unwrap_string(argv[0]);
        if (!janet_checktype(argv[1], JANET_STRING)) {
            janet_panicf("expected string, got %v", argv[1]);
        }
        JanetString perms = janet_unwrap_string(argv[1]);

        ret = unveil((char *) path, (char *) perms);
    } else {
        ret = unveil(NULL, NULL);
    }
    return janet_wrap_number(ret);
}

static const JanetReg cfuns[] = {
    {"pledge", janet_pledge, "(pledge/pledge promises &opt execpromises)"},
    {"unveil", janet_unveil, "(pledge/unveil path permissions)\n"
        "and (pledge/unveil) to commit and lock"},
    {NULL, NULL, NULL}
};

JANET_MODULE_ENTRY(JanetTable *env) {
    janet_cfuns(env, "pledge", cfuns);
}
