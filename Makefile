all:
	gcc -W -Wall -fPIC -shared pam_externalpass.c -o pam_externalpass.so
