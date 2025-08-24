#ifndef LPUSIGN_HEADER_PARAM_H
#define LPUSIGN_HEADER_PARAM_H

#include "prelude.h"

struct lpu_command;
struct lpu_param;

typedef int (*lpu_cmd_handler)(char* flags, struct lpu_param* params);

struct lpu_command {
    struct lpu_command* next; /* Linked list */

    const char* command;
    lpu_cmd_handler callback;
    
    struct lpu_command* sub_commands;
};

struct lpu_param {
    struct lpu_param* next; /* Linked list */

    char* name;
    int32_t index;

    char* value;
};

struct lpu_command* lpu_new_command(struct lpu_command* command, const char* cmd, lpu_cmd_handler handler);
int lpu_execute(struct lpu_command* root, int argc, char* argv[]);

bool lpu_flag(char* flags, char flag);
bool lpu_flag_param(struct lpu_param* params, char* flags);
char* lpu_param_at(struct lpu_param* params, int32_t index);
char* lpu_param_named(struct lpu_param* params, const char* name);
uint32_t lpu_params_count(struct lpu_param* params);

#define LpuNewCliApp(handler) struct lpu_command* root = lpu_new_command(NULL, NULL, handler ? (lpu_cmd_handler) __lpu_cli_root_handler__ : NULL);
#define LpuCommandHandler(command) static int __lpu_cli_##command##_handler__(char* flags, struct lpu_param* params)
#define LpuCommand(base, command) struct lpu_command* base##_##command = lpu_new_command(base, #command, (lpu_cmd_handler) __lpu_cli_##base##_##command##_handler__);
#define LpuFlag(flag) lpu_flag(flags, flag)
#define LpuFlagParam(flag) lpu_flag_param(params, flag)
#define LpuParamAt(index) lpu_param_at(params, index)
#define LpuParam(name) lpu_param_named(params, name)
#define LpuParams() lpu_params_count(params)
#define LpuRunCliApp() return lpu_execute(root, argc, &argv[1]);

#endif
