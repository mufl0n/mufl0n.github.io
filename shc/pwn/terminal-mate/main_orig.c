#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <stdint.h>
#include <inttypes.h>
#include <time.h>

typedef struct
{
    char *text;
    int16_t text_len;
} chat_message;

typedef struct
{
    char name[20];
    char job_title[32];
    chat_message *msg;
} employee_t;

typedef struct
{
    char name[0x08];
} user_t;

employee_t EMPLOYEES[16] = {
    {"Alex", "Software Engineer", NULL},
    {"Taylor", "Data Scientist", NULL},
    {"Jordan", "Product Manager", NULL},
    {"Ryan", "Marketing Coordinator", NULL},
    {"Sam", "Human Resources Specialist", NULL},
    {"Casey", "Financial Analyst", NULL},
    {"Jamie", "Graphic Designer", NULL},
    {"Chris", "Customer Service Representative", NULL},
    {"Bailey", "Project Manager", NULL},
    {"Avery", "Accountant", NULL},
    {"Dakota", "Sales Associate", NULL},
    {"Harper", "Operations Manager", NULL},
    {"Reese", "Administrative Assistant", NULL},
    {"Rowan", "Business Development Manager", NULL},
    {"Skyler", "Quality Assurance Tester", NULL},
    {"Phoenix", "UX/UI Designer", NULL}};

int64_t state;
int HAS_PREMIUM = 0;

void gedgets()
{
    asm("pop %rax; ret;");
    asm("syscall; ret;");
}

void mannheim_srand(int64_t seed)
{
    state = seed;
}

int64_t mannheim_random()
{
    state = ((state * 6364136223846793005U) + 1442695040888963407U);
    return state;
}

user_t *u;
chat_message *so = NULL;

user_t *create_user(const char *name)
{
    user_t *u = (user_t *)malloc(sizeof(user_t));
    strncpy(u->name, name, sizeof(u->name));
    return u;
}

void delete_user(user_t *u)
{
    free(u);
}

chat_message *create_message(
    const char *name)
{
    chat_message *new_so = (chat_message *)malloc(sizeof(chat_message));
    int len_name = strlen(name);
    char *new_so_name = (char *)malloc(len_name + 1);
    strncpy(new_so_name, name, len_name);
    new_so_name[len_name] = '\0';
    new_so->text = new_so_name;
    new_so->text_len = len_name;
    return new_so;
}

void delete_message(chat_message *so)
{
    if (so == NULL)
    {
        return;
    }

    free(so->text);
    free(so);
}

void gdpr_menu(user_t *u)
{
    char choice;
    printf("1. See data\n");
    printf("2. Delete data\n");
    printf("Enter your choice: ");
    scanf(" %c", &choice);
    switch (choice)
    {
    case '1':
        printf("Your name: %.8s\n", u->name);
        for (int i = 0; i < 16; i++)
        {
            if (EMPLOYEES[i].msg != NULL)
            {
                printf("You have sent a message to %s.\n", EMPLOYEES[i].name);
                printf("the message is: %s\n", EMPLOYEES[i].msg->text);
            }
        }
        break;
    case '2':
        delete_user(u);
        if (so)
        {
            delete_message(so);
        }
        printf("Your data has been deleted.\n");
        break;
    default:
        printf("Invalid choice.\n");
        break;
    }
}

void chusr_menu(user_t *u)
{
    char new_name[0x08];
    printf("Enter your new name: ");
    read(0, new_name, 0x08);
    strncpy(u->name, new_name, sizeof(u->name));
    printf("Your name has been changed to %.8s.\n", u->name);
}

void update_message(chat_message *msg, char *text, size_t len)
{
    memcpy(msg->text, text, len);
    msg->text_len = len;
}

void chat_edit_menu(employee_t *employee)
{
    printf("You have already sent a message to %s.\n", employee->name);
    printf("the message is: %s\n", employee->msg->text);

    printf("Do you want to edit the message? (y/n): ");
    char choice;
    scanf(" %c", &choice);
    if (choice == 'y')
    {
        printf("Enter your new message: ");

        size_t n = 0;
        char *message = NULL;
        while (getchar() != '\n')
            ;
        size_t len_message = getline(&message, &n, stdin);
        if (len_message <= 0)
        {
            exit(1);
        }
        message[len_message - 1] = '\0';

        // reuse message buffer if possible
        if (employee->msg->text_len >= len_message)
        {
            update_message(employee->msg, message, len_message);
            return;
        }

        delete_message(employee->msg);
        employee->msg = create_message(message);

        printf("Your message has been updated.\n");
    }
}

void chat_create_menu(employee_t *employee)
{
    printf("You matched with %s!\n", employee->name);
    printf("Send your first message: ");

    size_t n = 0;
    char *message = NULL;
    while (getchar() != '\n')
        ;
    size_t len_message = getline(&message, &n, stdin);
    if (len_message <= 0)
    {
        exit(1);
    }
    message[len_message - 1] = '\0';

    employee->msg = create_message(message);

    printf("Your message has been sent.\n");
}

void chat_menu(employee_t *employee)
{
    if (employee->msg != NULL)
    {
        chat_edit_menu(employee);
    }
    else
    {
        chat_create_menu(employee);
    }
}

void print_employee(employee_t emp)
{
    printf("Name: %s\n", emp.name);
    printf("Job Title: %s\n", emp.job_title);
    printf("\n");
}

void swipe()
{
    while (1)
    {
        int index = rand() % 16;
        printf("Employee #%d:\n", index + 1);
        print_employee(EMPLOYEES[index]);
        printf("Swipe left, right or start chatting (l/r/c): ");

        char direction;
        scanf(" %c", &direction);

        switch (direction)
        {
        case 'l':
        case 'r':
            break;
        case 'c':
            if (HAS_PREMIUM == 0)
            {
                printf("You need premium to chat.\n");
                break;
            }
            chat_menu(&EMPLOYEES[index]);
            break;
        default:
            printf("Invalid direction.\n");
            return;
        }
    }
}

void get_premium()
{
    printf("Try our premium features!\n");
    printf("Verify your account and get 10 minutes of free premium.\n");
    printf("Enter your credit card number and we will send you a verification code: ");
    char credit_card[20];
    scanf("%10s", credit_card);

    // dont actually send any verification code
    int64_t verification_code = mannheim_random();
    printf("Enter the verification code: ");
    int64_t entered_code;
    scanf("%" SCNu64, &entered_code);
    if (entered_code != verification_code)
    {
        printf("Invalid verification code.\n");
        printf("It should have been %" PRIu64 ".\n", verification_code);
        printf("Verification code is now invalid.\n");
        HAS_PREMIUM = 0;
        return;
    }

    printf("Congratulations! You now have 10 minutes of free premium.\n");
    HAS_PREMIUM = 1;
}

void menu_loop(void)
{
    char choice;
    while (1)
    {
        printf("\n");
        printf("%.8s, what would you like to do?\n", u->name);
        printf("1. Start swiping\n");
        printf("2. Change user name\n");
        printf("3. Get Premium\n");
        printf("4. GDPR\n");
        printf("5. Exit\n");
        printf("Enter your choice: ");
        scanf(" %c", &choice);
        switch (choice)
        {
        case '1':
            swipe();
            break;
        case '2':
            chusr_menu(u);
            break;
        case '3':
            get_premium();
            break;
        case '4':
            gdpr_menu(u);
            break;
        case '5':
            return;
        default:
            printf("Invalid choice.\n");
            break;
        }
    }
}

int main()
{
    setvbuf(stdout, NULL, _IONBF, 0);
    int deref_random_seed = 0;
    mannheim_srand((int64_t)&deref_random_seed);

    printf("                                                                                \n"
           ",--------.                       ,--.                ,--.,--.   ,--.          ,--.          \n"
           "'--.  .--',---. ,--.--.,--,--,--.`--',--,--,  ,--,--.|  ||   `.'   | ,--,--.,-'  '-. ,---.  \n"
           "   |  |  | .-. :|  .--'|        |,--.|      \\' ,-.  ||  ||  |'.'|  |' ,-.  |'-.  .-'| .-. : \n"
           "   |  |  \\   --.|  |   |  |  |  ||  ||  ||  |\\ '-'  ||  ||  |   |  |\\ '-'  |  |  |  \\   --. \n"
           "   `--'   `----'`--'   `--`--`--'`--'`--''--' `--`--'`--'`--'   `--' `--`--'  `--'   `----' \n"
           "                                                                                            \n");

    printf("Welcome to TerminalMate, we guarantee you a match <3.\n");
    printf("Enter your name (8 chars): ");
    char name[0x08];
    read(0, name, 0x08);
    u = create_user(name);

    menu_loop();

    return 0;
}
