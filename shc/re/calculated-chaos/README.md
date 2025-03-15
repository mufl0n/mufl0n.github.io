# calculated-chaos

[library.m0unt41n.ch/challenges/calculated-chaos](https://library.m0unt41n.ch/challenges/calculated-chaos) ![](../../resources/re.svg) ![](../../resources/medium.svg) 

# TL;DR

We get a binary, that can be reverse-engineered to a sort of recursive
expression parser / builder / evaluator. Which, if the expression evaluates
to the right value, will print the flag from a file.

# Decompilation

This was really 99% of the work here. IDA did a reasonable first approximation
and I polished it a bit further. It doesn't quite **work** when compiled &#128578;
but gives a good idea about the program.

<details>
  <summary>[<b>Click here to see full source</b>]</summary>

```c
#include <ctype.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <regex.h>

#define EXPR_ADD 0
#define EXPR_SUB 1
#define EXPR_MUL 2
#define EXPR_DIV 3
#define EXPR_NUM 4
#define EXPR_STR 5

int globalCount;

union NumberOrString {
  int num;
  char *str;
};

struct Expression {
  int type;
  union NumberOrString val;
  struct Expression *left;
  struct Expression *right;
};

struct Expression *initExpression(int type) {
  struct Expression *exp = (struct Expression *)malloc(sizeof(exp));
  exp->type = type;
  exp->left = NULL;
  exp->right = NULL;
  return exp;
}

void freeExpression(struct Expression *exp) {
  if (exp != NULL) {
    freeExpression(exp->left);
    freeExpression(exp->right);
    if (exp->type == EXPR_STR)
      free(exp->val.str);
    free(exp);
  }
}

char **tokenize(const char *input, int *numTokens) {
  char **token;
  char buf[256];
  int v5;

  char **tokenArray = (char **)malloc(8192);
  *numTokens = 0;
  memset(buf, 0, sizeof(buf));
  int v9 = 0;
  for (int i=0; i<strlen(input); i++) {
    char c = input[i];
    if (isspace(c)) {
      if (v9>0) {
        tokenArray[*numTokens] = strdup(buf);
        ++*numTokens;
        v9 = 0;
        buf[0] = 0;
      }
    } else if (strchr("+-*/", c)) {
      if (v9>0) {
        tokenArray[*numTokens] = strdup(buf);
        ++*numTokens;
        buf[0] = 0;
      }
      buf[0] = c;
      buf[1] = 0;
      tokenArray[*numTokens] = strdup(buf);
      ++*numTokens;
      v9 = 0;
      buf[0] = 0;
    } else {
      int v5 = v9++;
      buf[v5] = c;
      buf[v9] = 0;
    }
  }
  if (v9>0) {
    tokenArray[*numTokens] = strdup(buf);
    ++*numTokens;
  }
  return tokenArray;
}

int isValidIdentifierName(const char *arg) {
  regex_t preg;
  regcomp(&preg, "^[a-zA-Z_][a-zA-Z0-9_]*$", 1);
  int res = regexec(&preg, arg, 0, 0, 0);
  regfree(&preg);
  return res == 0;
}

struct Expression *parseNumOrStr(char **tokenArray, int numTokens, int *idxPtr) {
  char *endptr;

  globalCount++;
  if (numTokens<=*idxPtr)
    return NULL;
  char *str = tokenArray[*idxPtr];
  struct Expression *exp = initExpression(EXPR_NUM);
  int val = strtoul(str, &endptr, 10);
  if (*endptr) {
    if (!isValidIdentifierName(str)) {
      free(exp);
      return NULL;
    }
    exp->type = EXPR_STR;
    exp->val.str = strdup(str);
  } else {
    exp->val.num = val;
  }
  ++*idxPtr;
  return exp;
}

struct Expression *parseMulDiv(char **tokenArray, int numTokens, int *idxPtr, struct Expression *expArg) {
  int type;

  globalCount++;
  if (numTokens<=*idxPtr)
    return expArg;
  char *token = tokenArray[*idxPtr];
  if (strcmp(token, "*") && strcmp(token, "/"))
    return expArg;
  if (!strcmp(token, "*"))
    type = EXPR_MUL;
  else
    type = EXPR_DIV;
  ++*idxPtr;
  struct Expression *expParsed = parseNumOrStr(tokenArray, numTokens, idxPtr);
  if (!expParsed)
    return NULL;
  struct Expression *expNew = initExpression(type);
  expNew->left = expArg;
  expNew->right = expParsed;
  return parseMulDiv(tokenArray, numTokens, idxPtr, expNew);
}

struct Expression *parseNumStrMulDiv(char **tokenArray, int numTokens, int *idxPtr) {
  globalCount++;
  struct Expression *exp = parseNumOrStr(tokenArray, numTokens, idxPtr);
  if (exp)
    return parseMulDiv(tokenArray, numTokens, idxPtr, exp);
  else
    return NULL;
}

struct Expression *parseAddSub(char **tokenArray, int numTokens, int *idxPtr, struct Expression *left) {
  globalCount++;
  if (numTokens<=*idxPtr)
    return left;
  char *token = tokenArray[*idxPtr];
  if (strcmp(token, "+") && strcmp(token, "-"))
    return left;
  int type = (strcmp(token, "+") != 0);
  ++*idxPtr;
  struct Expression *right = parseNumStrMulDiv(tokenArray, numTokens, idxPtr);
  if (!right)
    return NULL;
  struct Expression *exp = initExpression(type);
  exp->left = left;
  exp->right = right;
  return parseAddSub(tokenArray, numTokens, idxPtr, exp);
}

struct Expression *parseAny(char **tokenArray, int numTokens, int *idxPtr) {
  globalCount++;
  struct Expression *exp = parseNumStrMulDiv(tokenArray, numTokens, idxPtr);
  if (exp)
    return parseAddSub(tokenArray, numTokens, idxPtr, exp);
  else
    return NULL;
}

struct Expression *incGlobalCountAndParseMore(char **tokenArray, int numTokens, int *indexPtr) {
  globalCount++;
  return parseAny(tokenArray, numTokens, indexPtr);
}

struct Expression *parseTokenArray(char **tokenArray, int numTokens) {
  int indexPtr = 0;
  struct Expression *exp = incGlobalCountAndParseMore(tokenArray, numTokens, &indexPtr);
  if ((!exp) || (numTokens == indexPtr))
    return exp;
  freeExpression(exp);
  return NULL;
}

int validateTokenArray(char **tokenArray, int numTokens) {
  char *endptr;

  int nVars = 0;                                    // Number of non-numeric tokens
  int nNums = 0;                                    // Number of numeric tokens
  for (int i=0; i<numTokens; i++) {
    char *token = tokenArray[i];
    endptr = NULL;
    int val = strtoul(token, &endptr, 10);
    if (*endptr) {                              // endptr points to a non-zero char, say it's non-num
      if (endptr) {                             // extra safety, should not happen (we just dereferenced it)
        if (isValidIdentifierName(token)) {
          nVars++;
          if (strcmp(token, "var")) {           // if (token != "var")
            if ( strcmp(token, "flag") && strcmp(token, "secret"))  // if (token != "flag" && token != "secret)
              return 0;
          }
        }
      }
    } else {                                    // token is a num
      nNums++;
      if (val>16)
        return 0;
    }
  }
  // True if
  // - exactly five of 'var', 'flag' or 'secret'
  // - some amount of '+', '-', '*', '/'
  // - <=9 numbers <=16 each
  return (nVars==5) && (nNums<=9);
}

int calculateTreeSize(struct Expression *expr) {
  if (expr==NULL)
    return 0;
  return calculateTreeSize(expr->left)+1+calculateTreeSize(expr->right);
}

int validateExpression(struct Expression *exp) {
  return (!exp) || (calculateTreeSize(exp)<=30);
}

int stringToMagic(const char *str) {
  int sum = 0;
  for (int i=0; i<strlen(str); i++)
    sum += str[i];
  if (sum==784) return 0x00101010LL;
  if (sum==646) return 0x00505500LL;  // 'secret'
  if (sum==623) return 0x13371337LL;
  if (sum==555) return 0x10111000LL;
  if (sum==410) return 0x01010011LL;  // 'flag'
  if (sum==400) return 0x01001100LL;
  if (sum==329) return 0x20000001LL;  // 'var'
  if (sum==393) return 0x11001000LL;
  return 0xDEADC0DELL;
}

int evalExpression(struct Expression *exp) {
  if (exp==NULL)
    return 0;
  switch (exp->type) {
    case EXPR_ADD:
      return evalExpression(exp->left) + (unsigned int)evalExpression(exp->right);
    case EXPR_SUB:
      return evalExpression(exp->left) - (unsigned int)evalExpression(exp->right);
    case EXPR_MUL:
      return evalExpression(exp->left) * (unsigned int)evalExpression(exp->right);
    case EXPR_DIV:
      return evalExpression(exp->left) / (unsigned int)evalExpression(exp->right);
    case EXPR_NUM:
      return exp->val.num;
    case EXPR_STR:
      return stringToMagic(exp->val.str);
  }
  return 0;
}

void main(int argc, char **argv, char **envp) {
  int numTokens;
  char **tokenArray;
  struct Expression *exp;
  char flagBuf[64], userInput[264];

  while (1) {
    while (1) {
      // Read user input
      while (1) {
        puts("Hello");
        if (fgets(userInput, 256, stdin))
          break;
        puts("Error while reading input...");
      }
      // Tokenize string into tokenArray
      globalCount = 0;
      tokenArray = tokenize(userInput, &numTokens);
      // Check if token array has:
      // - exactly five of 'var', 'flag' or 'secret'
      // - some amount of '+', '-', '*', '/'
      // - <=9 numbers <=16 each
      if (validateTokenArray(tokenArray, numTokens)) {
        // Create expression tree from token array
        exp = parseTokenArray(tokenArray, numTokens);
        if (exp!=NULL) {
          if (validateExpression(exp))
            break;
        }
      }
    }
    // Evaluate expression tree
    int res = evalExpression(exp) - globalCount;
    if (res==0xAAAAAAAA) {
      FILE *file = fopen("flag.txt", "r");
      if (file!=NULL) {
        puts("Error while reading flag...");
        exit(1);
      }
      fgets(flagBuf, 64, file);
      fclose(file);
      printf("Congratulations! You have found the flag!\n%s", flagBuf);
      exit(0);
    }
    printf("nope\n%x\n", res);
    freeExpression(exp);
    for (int i=0; i<numTokens; i++)
      free(tokenArray[i]);
    free(tokenArray);
  }
}
```
</details>

The code is a rather simple expression parser and consists of:

## Expression definition:

```c
union NumberOrString {
  int num;
  char *str;
};

struct Expression {
  int type;
  union NumberOrString val;
  struct Expression *left;
  struct Expression *right;
};
```

## Main parsing and evaluation logic:

*   `tokenize()` - split the string into a sequence of identifiers (digits,
    arithmetic ops, variables))
*   `parseTokenArray()` - most of the complexity is here. It turns a list of
    identifiers built by `tokenize()` into a tree-like structure of an arithmetic expression. It uses few nested functions, not all of which I fully
    understood:
    *   `incGlobalCounterAndParseMore()` - what it says
        *   `parseAny()`
            *   `parseNumStrMulDiv()`
                *   `parseNumOrStr()`
                *   `parseMulDiv()`
            *   `parseAddSub()`
                *   (Might call `parseNumStrMulDiv()` above)

    Parsing results in setting `globalCount` variable to something that *roughly* -
    but not exactly - corresponds to number of terms in the expression. That is
    important for getting the flag later.
*   `evalExpression()` - a simple recursive evaluator. The only
    function it uses is `stringToMagic()` which, depending on "variable"
    name, returns a fixed integer value.

## Additional / helper functions

*   `isValidIdentifierName()` - checks `^[a-zA-Z_][a-zA-Z0-9_]*$` regex.
*   `validateTokenArray()` - ensures that the expression consists of:
    *   *exactly* five of: `var`, `flag` or `secret`
    *   *some* amount of `+`, `-`, `*` and `/`
    *   *nine or less* integer numbers, *less than 16* each
*   `fnitExpression()` / `freeExpression()` - managing memory

The program will return the flag if `evalExpression()` returns `0xAAAAAAAA` plus
`globalCount`.

# Looking closer at `stringToMagic()`

```c
int stringToMagic(const char *str) {
  int sum = 0;
  for (int i=0; i<strlen(str); i++)
    sum += str[i];
  if (sum==784) return 0x00101010LL;
  if (sum==646) return 0x00505500LL;
  if (sum==623) return 0x13371337LL;
  if (sum==555) return 0x10111000LL;
  if (sum==410) return 0x01010011LL;
  if (sum==400) return 0x01001100LL;
  if (sum==329) return 0x20000001LL;
  if (sum==393) return 0x11001000LL;
  return 0xDEADC0DELL;
}
```

This simply adds ASCII codes of the characters in the string (from the context:
the string is an identifier). And, it just so happens that sum is:

*   `646` for `secret` (yielding `0x00505500`)
*   `410` for `flag` (yielding `0x01010011`)
*   `329` for `var` (yielding `0x20000001`)

Even more so: the hex values of these "variables" seem very friendly to getting
`0xAAAAAAAA` as a result (`2*5`, `5*2`, `A*1`). The only problem is that
annoying `globalCount` which is *subtracted* from the result. And I couldn't
get the exact logic of that variable (it's not simple a number of terms or
tree depth).

But, with some trial and error:

*   Starting with something roughly correct and ticking the requirements (see
    how we use the above numbers, to get them to sum up to `A` at every
    nibble):

    ```
    Hello
    5*var+10*flag+2*secret+var-var
    nope
    aaaaaa93
    ```

*   OK, need more, let's add 16 (maximum number)

    ```
    Hello
    5*var+10*flag+2*secret+var-var+16
    nope
    aaaaaa9f
    ```

*   Still not enough (and note that the value added was not 16):

    ```
    Hello
    5*var+10*flag+2*secret+var-var+16+16
    nope
    aaaaaaab
    ```

*   That's one too much, make it 15:

    ```
    Hello
    5*var+10*flag+2*secret+var-var+16+15
    Error while reading flag...
    ```

Success!

Sending that last expression to the remote instance yielded the flag.

---

## `stairctf{gR4mm4rs_4r3_w1111ld}`



<hr>

&copy; [muflon77](https://library.m0unt41n.ch/players/805ae1c8-9fe4-5816-b4a4-5057fa6eedb1)
