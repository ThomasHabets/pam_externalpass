/** pam_externalpass/pam_externalpass.c
 *
 */
#include <stdlib.h>
#include <stdio.h>
#include <syslog.h>
#include <stdarg.h>
#include <string.h>
#include <errno.h>
#include <pwd.h>
#include <unistd.h>
#include <limits.h>

#include <sys/types.h>
#include <sys/time.h>
#include <sys/resource.h>
#include <sys/wait.h>
#include <sys/types.h>

#include <security/pam_appl.h>
#include <security/pam_modules.h>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

static const char *version = VERSION;

static const char *userconf_envname = "PAM_EXTERNALPASS_USERCONF";

/**
 *
 */
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

/**
 *
 */
static void
popen2(const char *cmdline, FILE **fin, FILE **fout, pid_t *rpid)
{
        pid_t pid;
        int fdin[2];
        int fdout[2];
        *fin = *fout = 0;
        *rpid = 0;

        if (pipe(fdin)) {
                return;
        }
        if (pipe(fdout)) {
                close(fdin[0]);
                close(fdin[1]);
                return;
        }

        if (0 > (pid = fork())) {
                close(fdin[0]);
                close(fdin[1]);
                close(fdout[0]);
                close(fdout[1]);
                syslog(LOG_WARNING, "conv() error");
                return;
        }
        if (!pid) {
                dup2(fdin[0], 0);
                dup2(fdout[1], 1);
                close(fdin[1]);
                close(fdout[0]);
                execl("/bin/sh", "sh", "-c", cmdline, NULL);
                syslog(LOG_WARNING, "execl(%s) failed: %s", cmdline,
                       strerror(errno));
                exit(1);
        }
        close(fdin[0]);
        close(fdout[1]);
        if (!(*fin = fdopen(fdin[1], "w"))) {
                syslog(LOG_WARNING, "fdopen(fdin) failed: %s",
                       strerror(errno));
                close(fdin[1]);
                close(fdout[0]);
                wait4(pid, NULL, 0, NULL);
                return;
        }
        if (!(*fout = fdopen(fdout[0], "r"))) {
                syslog(LOG_WARNING, "fdopen(fdin) failed: %s",
                       strerror(errno));
                fclose(*fin);
                close(fdout[0]);
                *fin = 0;
                wait4(pid, NULL, 0, NULL);
                return;
        }
        *rpid = pid;

        return;
}

/**
 *
 */
static void
pclose2(FILE *f1, FILE *f2, pid_t pid)
{
        if (f1) {fclose(f1);}
        if (f2) {fclose(f2);}
        wait4(pid, NULL, 0, NULL);
}

/**
 *
 */
static int
try_password(struct pam_conv *conv,
	     const char *username,
	     const char *prompt,
	     const char *external,
             const char *user_conf_file,
	     char **notice)
{
	struct pam_message msg;
	const struct pam_message *msgp;
	struct pam_response *respp = 0;
	const char *password;
	FILE *fin, *fout;
	int ret = 0;
        int pid;

	*notice = 0;
	msg.msg_style = PAM_PROMPT_ECHO_OFF;
	msg.msg = (char*)prompt;
	msgp = &msg;
	if (PAM_SUCCESS != (ret = conv->conv(1,
                                             &msgp,
                                             &respp,
                                             conv->appdata_ptr))) {
                syslog(LOG_WARNING, "conv() error");
                return ret;
        }
        
	password = respp[0].resp;

        /*  */
        unsetenv(userconf_envname);
        if (user_conf_file) {
                if (0 > setenv("userconf_envname", user_conf_file, 1)) {
                        syslog(LOG_WARNING, "Unable to set conf file parm "
                               "%s to <%s>",
                               userconf_envname,
                               user_conf_file);
                        return ret;
                }
        }

	/* exec auth program */
	syslog(LOG_DEBUG, "Exec <%s>", external);
        popen2(external, &fin, &fout, &pid);
        unsetenv(userconf_envname);
	if (!fin) {
		goto errout;
	}

	fprintf(fin, "%s\n%s\n", username, password);
        fclose(fin);
        fin = 0;
	//syslog(LOG_WARNING, "User <%s> pass <%s>", username, password);

	/* get reply */
	{
		char buf[4096];
		memset(buf, 0, sizeof(buf));
		fread(buf, sizeof(buf), 1, fout);
		if (!strcmp(buf, "OK\n")) {
			ret = 1;
		}
		char *noticestr = "NOTICE ";
		if (!strncmp(buf, noticestr, strlen(noticestr))) {
			*notice = strdup(buf + strlen(noticestr));
		}
	}
	pclose2(fin, fout, pid);
 errout:
	free(respp);
	return ret;
}

/**
 * return a strdup():ed prompt. Caller frees.
 */
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
		if (!prompt) {
			syslog(LOG_WARNING, "strdup(<small string>) failed",
			       promptArg);
			return 0;
		}
	}
	return prompt;
}

/**
 * Loop while the authenticator program returns a NOTICE (as opposed to
 * OK or FAIL.
 */
static int
passwordLoop(struct pam_conv *item, const char *username,
	     const char *prompt, const char *external,
             const char *user_conf_file)
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
                                 user_conf_file,
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


/**
 *
 */
PAM_EXTERN
int pam_sm_authenticate(pam_handle_t *pamh,
			int flags __attribute__((unused)),
			int argc, const char **argv)

{
	struct pam_conv *item;
	const char *username = 0;
	const char *prompt = 0;
	const char *user_conf_file = 0;
	const char *expanded_user_conf_file = 0;
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

        user_conf_file = getarg("userconf", argc, argv);
        if (user_conf_file) {
                char buf[PATH_MAX + 1];
                struct passwd pw;
                struct passwd *ppw;
                char pwbuf[1024];
                memset(buf, 0, sizeof(buf));

                getpwnam_r(username, &pw, pwbuf, sizeof(pwbuf), &ppw);
                if (!ppw) {
                        syslog(LOG_WARNING, "getpwnam_r(%s) failed", username);
                        goto errout;
                }
                /* FIXME: change to pattern like:
                 * %h/.yubikeys
                 * /etc/yubikeys/%u
                 */
                snprintf(buf,
                         sizeof(buf),
                         "%s/%s", ppw->pw_dir, user_conf_file);

                /* check exist */
                if (access(buf, R_OK)) {
                        syslog(LOG_INFO,
                               "User %s has no conf file %s (%s), "
                               "or it's not readable",
                               username,
                               user_conf_file,
                               buf);
                        goto errout;
                }
                expanded_user_conf_file = user_conf_file;
        }


	if (PAM_SUCCESS == passwordLoop(item,
					username,
					prompt,
					getarg("exec", argc, argv),
                                        expanded_user_conf_file)) {
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

/**
 *
 */
PAM_EXTERN int
pam_sm_setcred(pam_handle_t *pamh __attribute__((unused)),
               int flags __attribute__((unused)),
               int argc __attribute__((unused)),
               const char **argv __attribute__((unused)))
{
        return PAM_SUCCESS;
}

/* ---- Emacs Variables ----
 * Local Variables:
 * c-basic-offset: 8
 * indent-tabs-mode: nil
 * End:
 */
