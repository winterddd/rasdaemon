#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <sys/wait.h>
#include <unistd.h>
#include <string.h>

#include "ras-logger.h"
#include "trigger.h"


void run_trigger(struct event_trigger *trigger, char *argv[], char **env)
{
	pid_t child;
	int status;

	log(SYSLOG, LOG_INFO, "Running trigger `%s'\n", trigger->env);

	child = fork();
	if (child < 0) {
		log(SYSLOG, LOG_ERR, "Cannot create process for trigger");
		return;
	}

	if (child == 0) {
		execve(trigger->path, argv, env);
		_exit(127);
	} else {
		waitpid(child, &status, 0);
		if (WIFEXITED(status) && WEXITSTATUS(status)) {
			log(SYSLOG, LOG_INFO, "Trigger %s exited with status %d",
			    trigger->path, WEXITSTATUS(status));
		} else if (WIFSIGNALED(status)) {
			log(SYSLOG, LOG_INFO, "Trigger %s killed by signal %d",
			    trigger->path, WTERMSIG(status));
		}
	}
}

const char *trigger_check(const char *s)
{
	char *name;
	int rc;
	char *trigger_dir = getenv("TRIGGER_DIR");

	if (trigger_dir) {
		if (asprintf(&name, "%s/%s", trigger_dir, s) < 0)
			return NULL;
		s = name;
	}

	rc = access(s, R_OK | X_OK);

	if (!rc)
		return(s);

	return NULL;
}

struct event_trigger mc_ce_trigger = {"mc_event", "MC_CE_TRIGGER"};
struct event_trigger mc_ue_trigger = {"mc_event", "MC_UE_TRIGGER"};
struct event_trigger mf_trigger = {"memory_failure_event", "MEM_FAIL_TRIGGER"};

struct event_trigger *event_triggers[] = {
	&mc_ce_trigger,
        &mc_ue_trigger,
#ifdef HAVE_MEMORY_FAILURE
        &mf_trigger,
#endif
};

void trigger_setup(void)
{
        int i;
        struct event_trigger *trigger;
        const char *s;

        for (i = 0; i < ARRAY_SIZE(event_triggers); i++) {
                trigger = event_triggers[i];

                s = getenv(trigger->env);
                if (!s || !strcmp(s, ""))
		        continue;

                trigger->path = trigger_check(s);
                if (!trigger->path)
                        log(ALL, LOG_ERR, "Cannot access trigger `%s`\n", s);
                else
                        log(ALL, LOG_NOTICE, "Setup %s trigger `%s`\n",
                                                        trigger->event_name, s);
        }
}

#define MAX_ENV 30
static void run_mc_trigger(struct ras_mc_event *ev, struct event_trigger *trigger)
{
	char *env[MAX_ENV];
	int ei = 0, i;

	if (!trigger->path || !strcmp(trigger->path, ""))
		return;

	if (asprintf(&env[ei++], "PATH=%s", getenv("PATH") ?: "/sbin:/usr/sbin:/bin:/usr/bin") < 0)
		goto free;
	if (asprintf(&env[ei++], "TIMESTAMP=%s", ev->timestamp) < 0)
		goto free;
	if (asprintf(&env[ei++], "COUNT=%d", ev->error_count) < 0)
		goto free;
	if (asprintf(&env[ei++], "TYPE=%s", ev->error_type) < 0)
		goto free;
	if (asprintf(&env[ei++], "MESSAGE=%s", ev->msg) < 0)
		goto free;
	if (asprintf(&env[ei++], "LABEL=%s", ev->label) < 0)
		goto free;
	if (asprintf(&env[ei++], "MC_INDEX=%d", ev->mc_index) < 0)
		goto free;
	if (asprintf(&env[ei++], "TOP_LAYER=%d", ev->top_layer) < 0)
		goto free;
	if (asprintf(&env[ei++], "MIDDLE_LAYER=%d", ev->middle_layer) < 0)
		goto free;
	if (asprintf(&env[ei++], "LOWER_LAYER=%d", ev->lower_layer) < 0)
		goto free;
	if (asprintf(&env[ei++], "ADDRESS=%llx", ev->address) < 0)
		goto free;
	if (asprintf(&env[ei++], "GRAIN=%lld", ev->grain) < 0)
		goto free;
	if (asprintf(&env[ei++], "SYNDROME=%llx", ev->syndrome) < 0)
		goto free;
	if (asprintf(&env[ei++], "DRIVER_DETAIL=%s", ev->driver_detail) < 0)
		goto free;
	env[ei] = NULL;
	assert(ei < MAX_ENV);

	run_trigger(trigger, NULL, env);

free:
	for (i = 0; i < ei; i++)
		free(env[i]);
}

void run_mc_ce_trigger(struct ras_mc_event *ev)
{
        run_mc_trigger(ev, &mc_ce_trigger);
}

void run_mc_ue_trigger(struct ras_mc_event *ev)
{
        run_mc_trigger(ev, &mc_ue_trigger);
}

void run_mf_trigger(struct ras_mf_event *ev)
{
	char *env[MAX_ENV];
	int ei = 0;
	int i;
        struct event_trigger *trigger = &mf_trigger;

	if (!trigger->path || !strcmp(trigger->path, ""))
		return;

	if (asprintf(&env[ei++], "PATH=%s", getenv("PATH") ?: "/sbin:/usr/sbin:/bin:/usr/bin") < 0)
		goto free;
	if (asprintf(&env[ei++], "TIMESTAMP=%s", ev->timestamp) < 0)
		goto free;
	if (asprintf(&env[ei++], "PFN=%s", ev->pfn) < 0)
		goto free;
	if (asprintf(&env[ei++], "PAGE_TYPE=%s", ev->page_type) < 0)
		goto free;
	if (asprintf(&env[ei++], "ACTION_RESULT=%s", ev->action_result) < 0)
		goto free;

	env[ei] = NULL;
	assert(ei < MAX_ENV);

	run_trigger(trigger, NULL, env);

free:
	for (i = 0; i < ei; i++)
		free(env[i]);
}