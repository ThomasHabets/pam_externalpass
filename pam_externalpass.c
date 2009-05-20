/** pam_externalpass/pam_externalpass.c
 *
 * pam_externalpass
 *
 * By Thomas Habets <thomas@habets.pp.se> 2009
 *
 * Call an external program from PAM authentication.
 *
 */
/*
 *  Copyright (C) 2009 Thomas Habets <thomas@habets.pp.se>
 *
 *  This library is free software; you can redistribute it and/or
 *  modify it under the terms of the GNU General Public
 *  License as published by the Free Software Foundation; either
 *  version 2 of the License, or (at your option) any later version.
 *
 *  This library is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 *  General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License along
 *  with this program; if not, write to the Free Software Foundation, Inc.,
 *  51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
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
 * return pointer into existing data (or 0 if ENOENT).
 * Caller does NOT free the results.
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
 * like popen(), but give access to *both* stdin and stdout. Just like in
 * python.
 *
 * on error, *fin, *fout and *rpid will be 0
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
                syslog(LOG_WARNING, "pipe() error: %s", strerror(errno));
                return;
        }
        if (pipe(fdout)) {
                syslog(LOG_WARNING, "pipe() error: %s", strerror(errno));
                close(fdin[0]);
                close(fdin[1]);
                return;
        }

        if (0 > (pid = fork())) {
                syslog(LOG_WARNING, "fork() error: %s", strerror(errno));
                close(fdin[0]);
                close(fdin[1]);
                close(fdout[0]);
                close(fdout[1]);
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
                /* the theory is that when childs stdin closes it will die
                   pretty quickly */
                wait4(pid, NULL, 0, NULL);
                return;
        }
        if (!(*fout = fdopen(fdout[0], "r"))) {
                syslog(LOG_WARNING, "fdopen(fdin) failed: %s",
                       strerror(errno));
                fclose(*fin);
                close(fdout[0]);
                *fin = 0;
                /* the theory is that when childs stdin closes it will die
                   pretty quickly */
                wait4(pid, NULL, 0, NULL);
                return;
        }
        *rpid = pid;

        return;
}

/**
 * close two FILEs and wait for a pid.
 */
static void
pclose2(FILE *f1, FILE *f2, pid_t pid)
{
        if (f1) {fclose(f1);}
        if (f2) {fclose(f2);}
        wait4(pid, NULL, 0, NULL);
}

/**
 * return PAM_SUCCESS if authenticator said "OK"
 * set "notice" if authenticator returned "NOTICE" and return PAM_AUTH_ERR
 * else set "notice" to NULL and return PAM_AUTH_ERR
 *
 * May return other non-PAM_AUTH_ERR on error if that is what conv() returned.
 * Never PAM_SUCCESS on error though.
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
	int ret = PAM_AUTH_ERR;
        int tret;
        int pid;

	*notice = 0;
	msg.msg_style = PAM_PROMPT_ECHO_OFF;
	msg.msg = (char*)prompt;
	msgp = &msg;
	if (PAM_SUCCESS != (tret = conv->conv(1,
                                             &msgp,
                                             &respp,
                                             conv->appdata_ptr))) {
                syslog(LOG_WARNING, "conv() error");
                return tret;
        }
        
	password = respp[0].resp;

        /*  */
        unsetenv(userconf_envname);
        if (user_conf_file) {
                if (0 > setenv(userconf_envname, user_conf_file, 1)) {
                        syslog(LOG_WARNING,
                               "Unable to set conf file parm %s to <%s>",
                               userconf_envname,
                               user_conf_file);
                        return PAM_AUTH_ERR;
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
	/* syslog(LOG_WARNING, "User <%s> pass <%s>", username, password); */

	/* get reply */
        ret = PAM_AUTH_ERR;
	{
		char buf[4096];
		memset(buf, 0, sizeof(buf));
		fread(buf, sizeof(buf), 1, fout);
		if (!strcmp(buf, "OK\n")) {
			ret = PAM_SUCCESS;
		}
		char *noticestr = "NOTICE ";
		if (!strncmp(buf, noticestr, strlen(noticestr))) {
			*notice = strdup(buf + strlen(noticestr));
		}
	}
	pclose2(fin, fout, pid);
 out:
	free(respp);
        return ret;
 errout:
        if (ret == PAM_SUCCESS) {
                ret = PAM_AUTH_ERR;
        }
        goto out;
}

/**
 * return a strdup():ed prompt. Caller frees. Return 0 on failure.
 *
 * replace '_' with ' ' in prompt arg
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
		if (PAM_SUCCESS == try_password(item,
                                                username,
                                                fullprompt,
                                                external,
                                                user_conf_file,
                                                &notice)) {
			ret = PAM_SUCCESS;
                        syslog(LOG_WARNING, "Got OK for user <%s>",
                               username);
		} else if (notice) {
                        syslog(LOG_WARNING, "Got NOTICE for user <%s>",
                               username);
                } else {
                        syslog(LOG_WARNING, "Got FAIL for user <%s>",
                               username);
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
 * turn %h/.foo into /home/bob/.foo, and /etc/foo/%u into /etc/foo/bob
 *
 * return 1 on fail. Fail is any weirdness at all. Return 0 un success.
 */
static int
fixupUserConfString(char *buf, size_t maxlen,
                    const char *user_conf_file,
                    struct passwd *pw)
{
        char *d;
        const char *s;
        char *tbuf = 0;

        memset(buf, 0, maxlen);

        if (!(tbuf = calloc(1, maxlen+1))) {
                goto errout;
        }
        
        s = user_conf_file;
        d = buf;
        while(*s) {
                if (*s == '%') {
                        s++;
                        switch(*s) {
                        case 'h':
                                snprintf(tbuf, maxlen, "%s%s",
                                         buf, pw->pw_dir);
                                strncpy(buf,tbuf,maxlen-1);
                                break;
                        case 'u':
                                snprintf(tbuf, maxlen, "%s%s",
                                         buf, pw->pw_name);
                                strncpy(buf,tbuf,maxlen-1);
                                break;
                        default:
                                syslog(LOG_WARNING,
                                       "userconf format error: "
                                       "unknown escape code <%%%c>", *s);
                                goto errout;
                        }
                        d = index(buf, 0);
                        s++;
                } else {
                        if (d - buf >= maxlen-1) {
                                syslog(LOG_WARNING,
                                       "userconf filename became too long: "
                                       "%u characters", d - buf);
                                goto errout;
                        }
                        *d++ = *s++;
                }
        }

        free(tbuf);
        return 0;
 errout:
        free(tbuf);
        return 1;
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

                getpwnam_r(username, &pw, pwbuf, sizeof(pwbuf), &ppw);
                if (!ppw) {
                        syslog(LOG_WARNING, "getpwnam_r(%s) failed", username);
                        goto errout;
                }
                if (fixupUserConfString(buf, sizeof(buf),
                                        user_conf_file, ppw)) {
                        syslog(LOG_WARNING, "Error in userconf format");
                        goto errout;
                }

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
                expanded_user_conf_file = strdup(buf);
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
        /* user_conf_file is not mallocated, do not free */
        free((char*)expanded_user_conf_file);
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
