#include <security/pam_modules.h>
#include <stdlib.h>
#include <stdio.h>
#include <syslog.h>
#include <stdarg.h>

/* pam arguments are normally of the form name=value.  This gets the
 * 'value' corresponding to the passed 'name' from the argument
 * list. */
static const char*
getarg(const char *name, int argc, const char **argv)
{
	int len = strlen(name);
	while (argc) {
		if (strlen(*argv) > len &&
		    !strncmp(name, *argv, len) &&
		    (*argv)[len] == '=') {
			return *argv + len + 1;  /* 1 for the = */
		}
		argc--;
		argv++;
	}
	return 0;
}

PAM_EXTERN
int pam_sm_authenticate(pam_handle_t *pamh, int flags, int argc,
                        const char **argv)

{
	struct pam_conv *item;
	struct pam_message msg;
	const struct pam_message *msgp;
	struct pam_response *respp;
	const char *username;
	const char *password;
	FILE *f;
	FILE *logfile;
	int rv = PAM_AUTH_ERR;

	openlog("pam_externalpass", LOG_PID, LOG_AUTH);
	//syslog(LOG_WARNING, "pam_externalpass init");

	msgp = &msg;
	
	msg.msg_style = PAM_PROMPT_ECHO_OFF;
	msg.msg = "Press enter if you don't have a hardware token: ";
	
	if (pam_get_item(pamh, PAM_CONV, (const void**)&item) != PAM_SUCCESS) {
		syslog(LOG_WARNING, "Couldn't get pam_conv");
		return PAM_AUTH_ERR;
	}
	
	if (pam_get_user(pamh, &username, 0) != PAM_SUCCESS) {
		syslog(LOG_WARNING, "Couldn't get username");
		return PAM_AUTH_ERR;
	}

	item->conv(1, &msgp, &respp, item->appdata_ptr);
	password = respp[0].resp;

	if (!(f = popen(getarg("exec", argc, argv), "r+"))) {
		syslog(LOG_WARNING, "popen() error\n");
		return PAM_AUTH_ERR;
	}

	//syslog(LOG_WARNING, "spawning <%s>", getarg("exec", argc, argv));
	fprintf(f, "%s\n%s\n", username, password);
	{
		char buf[32];
		fread(buf, sizeof(buf), 1, f);
		buf[sizeof(buf)-1] = 0;
		if (!strcmp(buf, "OK\n")) {
			rv = PAM_SUCCESS;
		}
	}
	fclose(f);
	//syslog(LOG_WARNING, "fail? %d\n", rv);
	
	memset(respp[0].resp, '\0', strlen(respp[0].resp));
	free(respp);
	
	return rv;
}

PAM_EXTERN int pam_sm_setcred(pam_handle_t *pamh, int flags,
                              int argc, const char **argv)
{
	return PAM_SUCCESS;
}
