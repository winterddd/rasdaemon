#ifndef __TRIGGER_H__
#define __TRIGGER_H__

#include "ras-record.h"

struct event_trigger {
        const char *event_name;
        const char *env;
        const char *path;
};

const char *trigger_check(const char *s);
void run_trigger(struct event_trigger *trigger, char *argv[], char **env);
void trigger_setup(void);

void run_mc_ce_trigger(struct ras_mc_event *ev);
void run_mc_ue_trigger(struct ras_mc_event *ev);
void run_mf_trigger(struct ras_mf_event *ev);
#endif
