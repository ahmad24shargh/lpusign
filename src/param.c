
#include "param.h"

static inline bool lpu_i8_inrange(char num, char min, char max) {
    return num >= min && num <= max;
}

struct lpu_command* lpu_new_command(struct lpu_command* command, const char* cmd, lpu_cmd_handler handler) {
    struct lpu_command* new_cmd = LpuAllocateStruct(lpu_command);
    new_cmd->callback = handler;
    new_cmd->command = cmd;

    if (command == NULL) {
        return new_cmd;
    }

    struct lpu_command* curr = command->sub_commands;

    if (curr != NULL) {
        while (curr->next != NULL) {
            curr = curr->next;
        }

        curr->next = new_cmd;
    } else {
        command->sub_commands = new_cmd;
    }


    return new_cmd;
}

static void lpu_command_free(struct lpu_command* root) {
    struct lpu_command* curr = root;

    while (curr != NULL) {
        struct lpu_command* next = curr->next;

        lpu_command_free(curr->sub_commands);

        free(curr);
        curr = next;
    }
}

static void lpu_param_free(struct lpu_param* root) {
    struct lpu_param* curr = root;
    
    while (curr != NULL) {
        struct lpu_param* next = curr->next;
        free(curr);
        curr = next;
    }
}

int call_handler(struct lpu_command* command, struct lpu_param* params, char* flags) {
    if (command == NULL) {
        return -1;
    }

    if (command->callback == NULL) {
        return -1;
    }

    return command->callback(flags, (struct lpu_param*) params);
}

int lpu_execute(struct lpu_command* root, int argc, char* argv[]) {
    if (--argc == 0) {
        int result = call_handler(root, NULL, NULL);
        lpu_command_free(root);

        return result;
    }

    struct lpu_param* params_root = LpuAllocateStruct(lpu_param);
    struct lpu_param* params = params_root;
    char* flags = (char*) lpu_allocate_safe(48);
    uint32_t flag_count = 0;
    uint32_t uparam_count = 0;

    struct lpu_command* cmd = root;
    bool found_subcommand = false;

    for (uint32_t i = 0; i < argc; i ++) {
        if (lpu_strstarts(argv[i], "-")) {
            if (lpu_strstarts(argv[i], "--")) {
                params->next = LpuAllocateStruct(lpu_param);
                params->index = -1;
                params->name = &argv[i][2];
                
                if (i + 1 < argc) {
                    params->value = argv[++ i];
                }

                params = params->next;
                continue;
            } else {
                size_t len = strlen(argv[i]) - 1;
                
                if (len <= 0 || len > 48) {
                    continue;
                }

                for (uint8_t j = 0; j < len; j ++) {
                    char fl = argv[i][1 + j];
                    if (lpu_i8_inrange(fl, 'A', 'Z')) {
                        flags[fl - 65] = fl;
                    } else if (lpu_i8_inrange(fl, 'a', 'z')) {
                        flags[fl - 97 + 24] = fl;
                    } else {
                        continue;
                    }
                }

                continue;
            }
        }

collect_param:
        if (found_subcommand) {
            params->next = LpuAllocateStruct(lpu_param);
            params->index = uparam_count ++;
            params->name = NULL;
            params->value = argv[i];

            params = params->next;

            goto next;
        }

        struct lpu_command* curr = cmd->sub_commands;
        found_subcommand = true;

        while (curr != NULL) {
            if (lpu_streq(curr->command, argv[i])) {
                cmd = curr;

                found_subcommand = false;
                goto next;
            }

            curr = curr->next;
        }

        goto collect_param;
next:        
        continue;
    }

    int result = call_handler(cmd, params_root, flags);

    /* Free allocated heap memories */
    lpu_command_free(root);
    lpu_param_free(params_root);
    free(flags);

    return result;
}

bool lpu_flag(char* flags, char fl) {
    if (flags == NULL) {
        return false;
    }

    if (lpu_i8_inrange(fl, 'A', 'Z')) {
        return flags[fl - 65] != 0;
    } else if (lpu_i8_inrange(fl, 'a', 'z')) {
        return flags[fl - 97 + 24] != 0;
    }

    return false;
}

bool lpu_flag_param(struct lpu_param* params, char* flag) {
    struct lpu_param* curr = params;

    while(curr != NULL) {
        if (lpu_streq(params->name, flag)) {
            return true;
        }

        curr = curr->next;
    }

    return false;
}

char* lpu_param_at(struct lpu_param* params, int32_t index) {
    struct lpu_param* curr = params;

    while(curr != NULL) {
        if (curr->index == index && curr->value != NULL) {
            return curr->value;
        }

        curr = curr->next;
    }

    return NULL;
}


char* lpu_param_named(struct lpu_param* params, const char* name) {
    struct lpu_param* curr = params;

    while(curr != NULL) {
        if (lpu_streq(curr->name, name)) {
            return curr->value;
        }

        curr = curr->next;
    }

    return NULL;
}

uint32_t lpu_params_count(struct lpu_param* params) {
    if (params == NULL) {
        return 0;
    }

    struct lpu_param* curr = params;
    uint32_t count = 0;

    while(curr != NULL) {
        if (curr->value != NULL) {
            count ++;
        }

        curr = curr->next;
    }

    return count;

}