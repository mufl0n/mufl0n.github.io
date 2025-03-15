/*
$ checksec --file=TerminalMate
RELRO       STACK CANARY  NX          PIE          RPATH     RUNPATH     Symbols     FORTIFY  Fortified  Fortifiable
Full RELRO  Canary found  NX enabled  PIE enabled  No RPATH  No RUNPATH  75 Symbols  No       0          4
*/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

typedef struct {
  char *text;
  long len;
} Message;

typedef struct {
  char name[20];
  char title[36];
  Message *message;
} Employee;

long    randomSeed;  // 4440h
int     HAS_PREMIUM; // 4448h
char    *main_user;  // 4450h
Message *so;         // 4458h

Employee EMPLOYEES[16] = {
  { .name = "Alex",    .title = "Software Engineer",                .message = NULL },
  { .name = "Taylor",  .title = "Data Scientist",                   .message = NULL },
  { .name = "Jordan",  .title = "Product Manager",                  .message = NULL },
  { .name = "Ryan",    .title = "Marketing Coordinator",            .message = NULL },
  { .name = "Sam",     .title = "Human Resources Specialist",       .message = NULL },
  { .name = "Casey",   .title = "Financial Analyst",                .message = NULL },
  { .name = "Jamie",   .title = "Graphic Designer",                 .message = NULL },
  { .name = "Chris",   .title = "Customer Service Representative",  .message = NULL },
  { .name = "Bailey",  .title = "Project Manager",                  .message = NULL },
  { .name = "Avery",   .title = "Accountant",                       .message = NULL },
  { .name = "Dakota",  .title = "Sales Associate",                  .message = NULL },
  { .name = "Harper",  .title = "Operations Manager",               .message = NULL },
  { .name = "Reese",   .title = "Administrative Assistant",         .message = NULL },
  { .name = "Rowan",   .title = "Business Development Manager",     .message = NULL },
  { .name = "Skyler",  .title = "Quality Assurance Tester",         .message = NULL },
  { .name = "Phoenix", .title = "UX/UI Designer",                   .message = NULL }
};

/* gedgets:
 *   0x55.......329  endbr64
 *   0x55.......32d  push     rbp
 *   0x55.......32e  mov      rbp, rsp
 *   0x55.......331  pop      rax
 *   0x55.......332  retnthe message is: messagetouser7

 *   0x55.......337  pop      rbp
 *   0x55.......338  retn
 */

void mannheim_srand(long seed) {
  randomSeed = seed;
}

long mannheim_random() {
  randomSeed = 0x5851F42D4C957F2DLL * randomSeed + 0x14057B7EF767814FLL;
  return randomSeed;
}

char *create_user(const char *name) {
  char *result; // [rsp+18h] [rbp-8h]
  result = malloc(8);
  strncpy(result, name, 8);
  return result;
}

void delete_user(char *name) {
  free(name);
}

Message *create_message(const char *text) {
  int len;         // [rsp+1Ch] [rbp-14h]
  Message *result; // [rsp+20h] [rbp-10h]
  char *dest;      // [rsp+28h] [rbp-8h]

  result = malloc(sizeof(Message));
  len = strlen(text);
  dest = malloc(len + 1);
  strncpy(dest, text, len);
  dest[len] = 0;
  result->text = dest;
  result->len = len;
  return result;
}

void delete_message(Message *msg) {
  if ( msg ) {
    free(msg->text);
    free(msg);
  }
}

void gdpr_menu(char *my_user_name) {
  char sel;         // [rsp+13h] [rbp-Dh] BYREF
  int i;            // [rsp+14h] [rbp-Ch]
  long stackCanary; // [rsp+18h] [rbp-8h]

  puts("1. See data");
  puts("2. Delete data");
  printf("Enter your choice: ");
  scanf(" %c", &sel);
  if ( sel == '1' ) {
    printf("Your name: %8s\n", my_user_name);
    for ( i = 0; i <= 15; ++i ) {
      if ( EMPLOYEES[i].message != NULL ) {
        printf("You have sent a message to %s.\n", EMPLOYEES[i].name);
        printf("the message is: %s\n", EMPLOYEES[i].message->text);
      }
    }
  } else if ( sel == '2' ) {
    // BUG! use-after-free on my_user_name
    delete_user(my_user_name);    
    if ( so )
      delete_message(so);
    puts("Your data has been deleted.");
  } else {
    puts("Invalid choice.");
  }
}

void chusr_menu(char *user) {
  char buf[8];      // [rsp+10h] [rbp-10h] BYREF
  long stackCanary; // [rsp+18h] [rbp-8h]

  printf("Enter your new name: ");
  read(0, buf, 8);
  strncpy(user, buf, 8);
  printf("Your name has been changed to %.8s.\n", user);
}

void update_message(Message *msg, const char *new_text, size_t len) {
  short n;         // [rsp+8h] [rbp-18h]

  n = len;
  memcpy(msg->text, new_text, len);
  msg->len = n;
}

void chat_edit_menu(Employee *emp) {
  char sel;         // [rsp+1Fh] [rbp-21h] BYREF
  size_t _dummy;    // [rsp+20h] [rbp-20h] BYREF
  char *lineptr;    // [rsp+28h] [rbp-18h] BYREF
  size_t len;       // [rsp+30h] [rbp-10h]
  long stackCanary; // [rsp+38h] [rbp-8h]

  printf("You have already sent a message to %s.\n", emp->name);
  printf("the message is: %s\n", emp->message->text);
  printf("Do you want to edit the message? (y/n): ");
  scanf(" %c", &sel);
  if ( sel == 'y' ) {
    printf("Enter your new message: ");
    _dummy = 0;
    lineptr = NULL;
    while ( getchar() != '\n' )
      ;
    len = getline(&lineptr, &_dummy, stdin);
    if ( !len )
      exit(1);
    lineptr[len - 1] = 0;
    if ( len > emp->message->len ) {
      delete_message(emp->message);
      emp->message = create_message(lineptr);
      puts("Your message has been updated.");
    } else {
      update_message(emp->message, lineptr, len);
    }
  }
}

void chat_create_menu(Employee *employee) {
  size_t n;         // [rsp+10h] [rbp-20h] BYREF
  char *lineptr;    // [rsp+18h] [rbp-18h] BYREF
  long input_len;   // [rsp+20h] [rbp-10h]
  long stackCanary; // [rsp+28h] [rbp-8h]

  printf("You matched with %s!\n", employee->name);
  printf("Send your first message: ");
  n = 0;
  lineptr = NULL;
  while ( getchar() != '\n' )
    ;
  input_len = getline(&lineptr, &n, stdin);
  if ( !input_len )
    exit(1);
  lineptr[input_len - 1] = 0;
  employee->message = create_message(lineptr);
  puts("Your message has been sent.");
}

void chat_menu(Employee *emp) {
  if ( emp->message )
    chat_edit_menu(emp);
  else
    chat_create_menu(emp);
}

void print_employee(Employee emp) {
  printf("Name: %s\n", emp.name);
  printf("Job Title: %s\n", emp.title);
  putchar('\n');
}

void swipe() {
  char sel;         // [rsp+3h] [rbp-Dh] BYREF
  int user_num;     // [rsp+4h] [rbp-Ch]
  long stackCanary; // [rsp+8h] [rbp-8h]

  while ( 1 ) {
    do {
      user_num = rand() % 16;
      printf("Employee #%d:\n", user_num + 1);
      print_employee(EMPLOYEES[user_num]);
      printf("Swipe left, right or start chatting (l/r/c): ");
      scanf(" %c", &sel);
    }
    while ( sel == 'r' );
    if ( sel > 'r' )
      break;
    if ( sel == 'c' ) {
      if ( HAS_PREMIUM )
        chat_menu(&EMPLOYEES[user_num]);
      else
        puts("You need premium to chat.");
    } else if ( sel != 'l' ) {
      break;
    }
  }
  puts("Invalid direction.");
}

void get_premium() {
  long code_input;      // [rsp+0h] [rbp-30h] BYREF
  long code;            // [rsp+8h] [rbp-28h]
  char card_number[24]; // [rsp+10h] [rbp-20h] BYREF
  long stackCanary;     // [rsp+28h] [rbp-8h]

  puts("Try our premium features!");
  puts("Verify your account and get 10 minutes of free premium.");
  printf("Enter your credit card number and we will send you a verification code: ");
  scanf("%10s", card_number);
  code = mannheim_random();
  printf("Enter the verification code: ");
  scanf("%lu", &code_input);
  if ( code_input == code ) {
    puts("Congratulations! You now have 10 minutes of free premium.");
    HAS_PREMIUM = 1;
  } else {
    puts("Invalid verification code.");
    printf("It should have been %lu.\n", code);
    puts("Verification code is now invalid.");
    HAS_PREMIUM = 0;
  }
}

void menu_loop() {
  char sel;         // [rsp+7h] [rbp-9h] BYREF
  long stackCanary; // [rsp+8h] [rbp-8h]

  while ( 1 ) {
    putchar('\n');
    printf("%.8s, what would you like to do?\n", main_user);
    puts("1. Start swiping");
    puts("2. Change user name");
    puts("3. Get Premium");
    puts("4. GDPR");
    puts("5. Exit");
    printf("Enter your choice: ");
    scanf(" %c", &sel);
    switch ( sel ) {
      case '1': swipe(); break;
      case '2': chusr_menu(main_user); break;  // Another use after free!
      case '3': get_premium(); break;
      case '4': gdpr_menu(main_user); break;
      case '5': return;
      default:  puts("Invalid choice."); break;
    }
  }
}

void main() {
  long seed;        // [rsp+Ch] [rbp-14h] BYREF
  char name[8];     // [rsp+10h] [rbp-10h] BYREF
  long stackCanary; // [rsp+18h] [rbp-8h]

  setvbuf(stdout, NULL, _IONBF, 0);
  mannheim_srand((long)&seed);
  puts(
    "                                                                                \n"
    ",--------.                       ,--.                ,--.,--.   ,--.          ,--.          \n"
    "'--.  .--',---. ,--.--.,--,--,--.`--',--,--,  ,--,--.|  ||   `.'   | ,--,--.,-'  '-. ,---.  \n"
    "   |  |  | .-. :|  .--'|        |,--.|      \\' ,-.  ||  ||  |'.'|  |' ,-.  |'-.  .-'| .-. : \n"
    "   |  |  \\   --.|  |   |  |  |  ||  ||  ||  |\\ '-'  ||  ||  |   |  |\\ '-'  |  |  |  \\   --. \n"
    "   `--'   `----'`--'   `--`--`--'`--'`--''--' `--`--'`--'`--'   `--' `--`--'  `--'   `----' \n"
    "                                                                                            ");
  puts("Welcome to TerminalMate, we guarantee you a match <3.");
  printf("Enter your name (8 chars): ");
  read(0, name, 8);
  main_user = create_user(name);
  menu_loop();
}

