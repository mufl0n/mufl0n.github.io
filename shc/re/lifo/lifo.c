int success1, success2;
char buf[128];

int isArg7EqualArg8Plus1(int a1, int a2, int a3, int a4, int a5, int a6, int a7, int a8) { return a7 + 2 == a8 + 3; }
int isArg7EqualArg8Plus1(int a1, int a2, int a3, int a4, int a5, int a6, int a7, int a8) { return a7 + 2 == a8 + 3; }
int isArg7EqualArg8Minus2(int a1, int a2, int a3, int a4, int a5, int a6, int a7, int a8) { return a7 == a8 - 2; }
int isArg7EqualArg8Minus53(int a1, int a2, int a3, int a4, int a5, int a6, int a7, int a8) { return a8 - 53 == a7; }
int isPtrArg1EqualArg2Plus9(int *a1, int a2) { return *a1 == a2 + 9; }
int isArg1EqualArg7(int a1, int a2, int a3, int a4, int a5, int a6, int a7) { return a7 == a1; }
int is95(int a1) { return a1 == 95; }
int isArg7ArgArg9Equal0x463777(int a1, int a2, int a3, int a4, int a5, int a6, int a7, int a8, int a9) { return a9 + ((a8 + (a7 << 8)) << 8) == 0x463777; }
int isArgEqual31337(int arg) { return arg + 8983 == factorial(8); }

int factorial(int arg) {
  if (arg == 1) return 1;
           else return arg * factorial(arg - 1);
}

int readFromStdIn(char *buf, size_t count) {
  int bytesRead = sys_read(0, buf, count);
  if (bytesRead < 0) exit(0);
  return bytesRead;
}

int writeToStdOut(const char *buf, size_t count) {
  int bytesWritten = sys_write(1, buf, count);
  if (bytesWritten < 0) exit(1);
  return bytesWritten;
}

void writeOneChar(char c) {
  writeToStdOut(&c, 1);
}

int readOneCharIntoBuf() {
  readFromStdIn(buf, 1);
  return buf[0];
}

void writeChars()   { writeOneChar('c'); writeOneChar('h'); writeOneChar('a'); writeOneChar('r'); writeOneChar('s'); }
void writeFlag()    { writeOneChar('F'); writeOneChar('l'); writeOneChar('a'); writeOneChar('g'); }
void writePlease()  { writeOneChar('p'); writeOneChar('l'); writeOneChar('e'); writeOneChar('a'); writeOneChar('s'); writeOneChar('e'); }
void writeWithout() { writeOneChar('w'); writeOneChar('i'); writeOneChar('t'); writeOneChar('h'); writeOneChar('o'); writeOneChar('u'); writeOneChar('t'); }
void writeShc()     { writeOneChar('s'); writeOneChar('h'); writeOneChar('c'); }
void writeWrong()   { writeOneChar('w'); writeOneChar('r'); writeOneChar('o'); writeOneChar('n'); writeOneChar('g'); }
void writeSuccess() { writeOneChar('s'); writeOneChar('u'); writeOneChar('c'); writeOneChar('c'); writeOneChar('e'); writeOneChar('s'); writeOneChar('s'); }

int readSignedIntFromStdIn() {
  char *ptr = buf;
  char *endOfString = &buf[readFromStdIn(buf, 128)];
  int resultIsNegative = 0;
  if (buf != endOfString && buf[0] == '-') {
    ptr = &buf[1];
    resultIsNegative = 1;
  }
  int result = 0;
  while (ptr != endOfString && (unsigned char)(*ptr - '0') <= 9)
    result = (unsigned char)(*ptr++ - '0') + 10 * result;
  return resultIsNegative?-result:result;
}

int writeSignedIntToStdout(int arg) {
  int absVal = arg, isNegative = 0;
  char *ptr = &buf[128];
  if (arg < 0) {
    absVal = -arg;
    isNegative = 1;
  }
  do {
    int tmpToKeepLowDigit = absVal;
    absVal = (unsigned int)absVal / (__int128)10;
    *--ptr = (unsigned int)tmpToKeepLowDigit % (__int128)10 + '0';
  } while (absVal);
  if (isNegative)
    *--ptr = '-';
  return writeToStdOut(ptr, &buf[128] - ptr);
}

void exit(int code) {
  sys_exit(code);
}

void doAllThings() {
  long chars[11];
  success1 = success2 = 0;

  chars[10] = readOneCharIntoBuf();
  chars[9] = readOneCharIntoBuf();
  chars[8] = readOneCharIntoBuf();
  chars[7] = readOneCharIntoBuf();
  chars[6] = readOneCharIntoBuf();
  chars[5] = readOneCharIntoBuf();
  if (isArg7EqualArg8Plus1(1, 3, 3, 7, 4, 2, chars[10], 'r')) {                       // chars[10] = 'r'+1 = 's'
    if (isArg7EqualArg8Minus2(1, 3, 3, 7, 4, 2, chars[9], 'v')) {                     // chars[9] = 'v'-2 = 't'
      if (isArg7EqualArg8Minus53(1, 3, 3, 7, 4, 2, chars[8], 'i')) {                  // chars[8] = 'i'-53 = '4'
        if (isPtrArg1EqualArg2Plus9(&chars[7], 'Z')                                   // chars[7] = 'Z'+7 = 'c'
          && isArg1EqualArg7(chars[6], 'Z', _dummy1, _dummy2, _dummy3, _dummy4, 'K')  // chars[6] = 'K'
          && is95(chars[5]) ) {                                                       // chars[5] = '_'
          success1 = 1;
        }
      }
    }
  }

  chars[3] = readOneCharIntoBuf();
  chars[2] = readOneCharIntoBuf();
  chars[1] = readOneCharIntoBuf();
  chars[4] = readOneCharIntoBuf();
  chars[0] = readSignedIntFromStdIn();

  if ( isArg7Arg8Arg9Equal0x463777(chars[0], probablyDummy, _dummy5, _dummy6, _dummy7, _dummy8, chars[3], chars[2], chars[1])
                                      // chars[3] = 0x46 = 'F'
                                      // chars[2] = 0x37 = '7'
                                      // chars[1] = 0x77 = 'w'
       && is95(chars[4])              // chars[4] = 95 = '_'
       && isArgEqual31337(chars[0]) ) // remaining chars are '31337'
         success2 = 1;
  // Flag: shc2022{st4cK_F7w_31337}

  if (success1 & success2) writeSuccess();
                      else writeWrong();
}

void start() {
  writeFlag();
  writeOneChar(' ');
  writePlease();
  writeOneChar(' ');
  writeOneChar('(');
  writeSignedIntToStdout(15);
  writeOneChar(' ');
  writeChars();
  writeOneChar(',');
  writeOneChar(' ');
  writeWithout();
  writeOneChar(' ');
  writeShc();
  writeSignedIntToStdout(2022);
  writeOneChar('{');
  writeOneChar('}');
  writeOneChar(')');
  writeOneChar(':');
  writeOneChar(' ');
  doAllThings();
  exit(0);
}


