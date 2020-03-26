#include <stdlib.h>
#include <unistd.h>
#include <stdio.h>
#include <stdio_ext.h>
#include <string.h>
#include <signal.h>
#include <pwd.h>
#include <sys/types.h>
#include <crypt.h>
#include <time.h>
/* Uncomment next line in step 2 */
#include "pwent.h"
 
#define TRUE 1
#define FALSE 0
#define LENGTH 16

volatile sig_atomic_t flag = 0;

void signalhandler(int signum) {
    flag = signum;
}

char* generatesalt(){
    int index;
    time_t t;
	char* salt = malloc(20);
	const char characters[] =
		"0123456789"
		"ABCDEFGHIJKLMNOPQRSTUVWXYZ"
		"abcdefghijklmnopqrstuvwxyz";
    
    srand(time(&t));
    
	for(int i = 0; i < 20; i++){
		index = rand() % (sizeof(characters) -1);
        salt[i] = characters[index];		
	}
	return salt;
}

void getuser_checkbuffer(char* user){
       char important1[LENGTH] = "**IMPORTANT 1**";
       char important2[LENGTH] = "**IMPORTANT 2**";
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
}
void initSignals(){
    if(signal(SIGINT, signalhandler) == SIG_ERR){
       printf("Cannot init signal SIGINT");
       return 0;
   }
   if(signal(SIGTSTP, signalhandler) == SIG_ERR){
       printf("Cannot init signal SIGTSTP");
       return 0;
   }
   if(signal(SIGQUIT, signalhandler) == SIG_ERR){
       printf("Cannot init signal SIGQUIT");
       return 0;
   }
}
int main(int argc, char *argv[]) {
   
   initSignals();

   char *SIG_MSG = malloc(24);

   mypwent *passwddata;
   
   char user[LENGTH];
   char prompt[] = "password: ";
   
   getuser_checkbuffer(user);

   char *user_pass;
   char *crypt_pass;
   char *const parmList[2] = {"LlLL",NULL};
   char *const arg[] = {"/bin/sh"};
 
  
   while (TRUE) {

       if (flag) {
          strcpy(SIG_MSG, "Signal caught\n");
          fputs(SIG_MSG, stderr);
       }
       
       user_pass = getpass(prompt);
       passwddata = mygetpwnam(strtok(user, "\n"));

       if (passwddata != NULL) {
           int i;
           char *pw;
		   crypt_pass = crypt(user_pass, passwddata->passwd_salt);

           if(passwddata->pwfailed > 3){
               printf("This account has been locked due to security reasons\n");
               return 0;  
           }

           if (!strcmp(crypt_pass, passwddata->passwd)) {
               printf(" You're in !\n");
               printf("Failed login attempts: %d\n", passwddata->pwfailed);
               passwddata->pwage++;
               passwddata->pwfailed = 0;
               if(mysetpwent(passwddata->pwname, passwddata) == -1){
                   printf("Cannot update user info");
                   return 0;
               }
              
           if(passwddata->pwage > 10){
               printf("You need to change your password\n"
                      "If you want to change password, press 1, otherwise 2\n");

               __fpurge(stdin); /* Purge any data in stdin buffer */
               scanf("%d", &i);
               if(i == 1){
                   __fpurge(stdin); /* Purge any data in stdin buffer */
                   pw = getpass(prompt);
                   passwddata->pwfailed = 0;
                   passwddata->pwage = 0;
				   passwddata->passwd_salt = generatesalt();
                   passwddata->passwd = crypt(pw, passwddata->passwd_salt);
                   if(mysetpwent(passwddata->pwname, passwddata) == -1){
                       printf("Cannot update user info");
                       return 0;
                   }
                  
               }
           }
           int code = setuid(passwddata->uid);
           if (code < 0) {
               printf("Setuid failed\n");
               exit(code);
           }
           if(execve(arg[0], parmList, NULL) == -1){
               printf("Error in running execve\n");
               return 0;
           }
           }
           else {
               printf("Login Incorrect \n");
               passwddata->pwfailed++;
               if(mysetpwent(passwddata->pwname, passwddata) == -1){
                   printf("Cannot update user info");
                   return 0;
               }
           }
       }else printf("Perhaps wrong login details \n");
   }
   return 0;
}