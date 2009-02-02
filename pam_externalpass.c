#include <security/pam_modules.h>
#include <sys/types.h>
#include <security/pam_appl.h>
#include <stdlib.h>
#include <stdio.h>
#include <syslog.h>
#include <stdarg.h>
#include <string.h>


static const char*
getarg(const char *name, int argc, const char **argv)
{
	size_t len = strlen(name);
	while (argc) {
		if (strlen(*argv) > len &&
		    !strncmp(name, *argv, len) &&
		    (*argv)[len] == '=') {
			return *argv + len + 1;
		}
		argc--;
		argv++;
	}
	return 0;
}

static int
try_password(struct pam_conv *conv,
	     const char *username,
	     const char *prompt,
	     const char *external,
	     char **notice)
{
	struct pam_message msg;
	const struct pam_message *msgp;
	struct pam_response *respp = 0;
	const char *password;
	FILE *f;
	int ret = 0;

	*notice = 0;
	msg.msg_style = PAM_PROMPT_ECHO_OFF;
	msg.msg = (char*)prompt;
	msgp = &msg;
	conv->conv(1, &msgp, &respp, conv->appdata_ptr);
	password = respp[0].resp;

	/* exec auth program */
	syslog(LOG_WARNING, "Exec <%s>", external);
	if (!(f = popen(external, "r+"))) {
		syslog(LOG_WARNING, "popen() error\n");
		goto errout;
	}

	fprintf(f, "%s\n%s\n", username, password);
	
	/* get reply */
	{
		char buf[4096];
		memset(buf, 0, sizeof(buf));
		fread(buf, sizeof(buf), 1, f);
		if (!strcmp(buf, "OK\n")) {
			ret = 1;
		}
		char *noticestr = "NOTICE ";
		if (!strncmp(buf, noticestr, strlen(noticestr))) {
			*notice = strdup(buf + strlen(noticestr));
		}
	}
	fclose(f);
 errout:
	free(respp);
	return ret;
}

static const char *
getPrompt(int argc, const char **argv)
{
	const char *promptArg = getarg("prompt", argc, argv);
	char *prompt;
	if (promptArg) {
		prompt = strdup(promptArg);
		if (!prompt) {
			syslog(LOG_WARNING, "strdup(<%s>) failed", promptArg);
			return 0;
		}
		char *p;
		for (p = prompt; *p; p++) {
			if (*p == '_') {
				*p = ' ';
			}
		}
	} else {
		prompt = strdup("External password: ");
	}
	return prompt;
}


static int
passwordLoop(struct pam_conv *item, const char *username,
	     const char *prompt, const char *external)
{
	int ret = PAM_AUTH_ERR;
	/*  */
	char *notice = 0;
	do {
		char *fullprompt;
		if (notice) {
			fullprompt = malloc(strlen(notice) + strlen(prompt)+2);
			if (!fullprompt) {
				free(notice);
				goto errout;
			}
			strcpy(fullprompt, notice);
			strcat(fullprompt, prompt);
			free(notice);
			notice = 0;
		} else {
			fullprompt = strdup(prompt);
			if (!fullprompt) {
				goto errout;
			}
		}
		if (try_password(item,
				 username,
				 fullprompt,
				 external,
				 &notice)) {
			ret = PAM_SUCCESS;
		}
		free(fullprompt);
		fullprompt = 0;
	} while (notice);
 okout:
	return ret;
 errout:
	ret = PAM_AUTH_ERR;
	goto okout;
}


PAM_EXTERN
int pam_sm_authenticate(pam_handle_t *pamh,
			int flags __attribute__((unused)),
			int argc, const char **argv)

{
	struct pam_conv *item;
	const char *username = 0;
	const char *prompt = 0;
	int rv = PAM_AUTH_ERR;

	openlog("pam_externalpass", LOG_PID, LOG_AUTH);

	/* get prompt */
	if (!(prompt = getPrompt(argc, argv))) {
		goto errout;
	}
	
	/* get conv ptr */
	if (pam_get_item(pamh, PAM_CONV, (const void**)&item) != PAM_SUCCESS) {
		syslog(LOG_WARNING, "Couldn't get pam_conv");
		goto errout;
	}

	/* get username */
	if (pam_get_user(pamh, &username, 0) != PAM_SUCCESS) {
		syslog(LOG_WARNING, "Couldn't get username");
		goto errout;
	}

	if (PAM_SUCCESS == passwordLoop(item,
					username,
					prompt,
					getarg("exec", argc, argv))) {
		rv = PAM_SUCCESS;
	}

 out:	
	closelog();
	free((char*)prompt);
	return rv;

 errout:
	rv = PAM_AUTH_ERR;
	goto out;
}

PAM_EXTERN int pam_sm_setcred(pam_handle_t *pamh __attribute__((unused)),
			      int flags __attribute__((unused)),
                              int argc __attribute__((unused)),
			      const char **argv __attribute__((unused)))
{
	return PAM_SUCCESS;
}
