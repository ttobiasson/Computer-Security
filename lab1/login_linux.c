/* $Header: https://svn.ita.chalmers.se/repos/security/edu/course/computer_security/trunk/lab/login_linux/login_linux.c 585 2013-01-19 10:31:04Z pk@CHALMERS.SE $ */

/* gcc -std=gnu99 -Wall -g -o mylogin login_linux.c -lcrypt */

#include <stdlib.h>
#include <unistd.h>
#include <stdio.h>
#include <stdio_ext.h>
#include <string.h>
#include <signal.h>
#include <pwd.h>
#include <sys/types.h>
#include <crypt.h>
/* Uncomment next line in step 2 */
#include "pwent.h"

#define TRUE 1
#define FALSE 0
#define LENGTH 16

void sighandler() {

	/* add signalhandling routines here */
	/* see 'man 2 signal' */
}

int main(int argc, char *argv[]) {

	mypwent *passwddata; /* this has to be redefined in step 2 */
	/* see pwent.h */
	char important1[LENGTH] = "**IMPORTANT 1**";

	char user[LENGTH];

	char important2[LENGTH] = "**IMPORTANT 2**";

	
	char prompt[] = "password: ";
	char *user_pass;
	char *crypt_pass;

	sighandler();

	while (TRUE) {
		/* check what important variable contains - do not remove, part of buffer overflow test */
		printf("Value of variable 'important1' before input of login name: %s\n",
				important1);
		printf("Value of variable 'important2' before input of login name: %s\n",
				important2);

		printf("login: ");
		fflush(NULL); /* Flush all  output buffers */
		__fpurge(stdin); /* Purge any data in stdin buffer */

		if (fgets(user, LENGTH, stdin) == NULL) /* gets() is vulnerable to buffer */
			exit(0); /*  overflow attacks.  */

		/* check to see if important variable is intact after input of login name - do not remove */
		printf("Value of variable 'important 1' after input of login name: %*.*s\n",
				LENGTH - 1, LENGTH - 1, important1);
		printf("Value of variable 'important 2' after input of login name: %*.*s\n",
		 		LENGTH - 1, LENGTH - 1, important2);
		user_pass = getpass(prompt);
		crypt_pass = crypt(user_pass, "AA");
		passwddata = mygetpwnam(strtok(user, "\n"));
		printf("%s", crypt_pass);

		if (passwddata != NULL) {
			int i;
			char *pw;

			if(passwddata->pwfailed > 3){
				printf("This account has been locked due to security reasons\n");
			return 0;	
			}
			
			/* You have to encrypt user_pass for this to work */
			/* Don't forget to include the salt */
			if (!strcmp(crypt_pass, passwddata->passwd)) {
				printf(" You're in !\n");
				printf("Failed login attempts: %d\n", passwddata->pwfailed);
				fprintf(fopen("passdb", "r+"), "%s:%d:%s:%s:%d:%d\n",
					passwddata->pwname, passwddata->uid, passwddata->passwd, passwddata->passwd_salt,
					passwddata->pwfailed = 0, passwddata->pwage +1);
				
			if(passwddata->pwage > 10){
				printf("You need to change your password\n");
				printf("If you want to change password, press 1, otherwise 2\n");
				__fpurge(stdin); /* Purge any data in stdin buffer */
				scanf("%d\n", &i);
				if(i == 1){
					__fpurge(stdin); /* Purge any data in stdin buffer */
					pw = getpass(prompt);
					passwddata->pwfailed = 0;
					passwddata->pwage = 0;
					passwddata->passwd = crypt(pw, passwddata->passwd_salt);
					passwddata->passwd_salt = "AA";
					mysetpwent(passwddata->pwname=strtok(user, "\n"), passwddata);
					
				}
			}
				/*  check UID, see setuid(2) */
				/*  start a shell, use execve(2) */
				//printf("I would run a a shell!");
				return 0;

				

			}
			else {
				printf("Login Incorrect \n");
				fprintf(fopen("passdb", "r+"), "%s:%d:%s:%s:%d:%d\n",
					passwddata->pwname, passwddata->uid, passwddata->passwd, passwddata->passwd_salt,
					passwddata->pwfailed +1, passwddata->pwage);

			} 
			
		}else printf("Perhaps wrong login details \n");
		
	}
	return 0;
}

