#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

char unb64[256] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x3E, 0x00, 0x00, 0x00, 0x3F,
    0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x3A, 0x3B, 0x3C, 0x3D, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E,
    0x0F, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F, 0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28,
    0x29, 0x2A, 0x2B, 0x2C, 0x2D, 0x2E, 0x2F, 0x30, 0x31, 0x32, 0x33, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
};

char b64[64] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

int base64integrity(char *str, int len) {
  int i;

  if ( (len & 3) != 0 )
    return 0LL;
  for ( i = 0; i < len - 2; ++i ) {
    if ( (str[i] <= '/' || str[i] > '9')
      && (str[i] <= '@' || str[i] > 'Z')
      && (str[i] <= '`' || str[i] > 'z')
      && str[i] != '+'
      && str[i] != '/' ) {
      printf("ERROR in base64integrity at chr %d [%c]. String is NOT valid base64.\n", i, (unsigned int)str[i]);
      return 0;
    }
  }
  if ( str[i] == '=' ) {
    if ( str[i + 1] != '=' ) {
      printf(
        "ERROR in base64integrity at chr %d.\n"
        "If the 2nd last chr is '=' then the last chr must be '=' too.\n"
        " String is NOT valid base64.", i);
      return 0;
    }
  } else if ( (str[i] <= '/' || str[i] > '9')
           && (str[i] <= '@' || str[i] > 'Z')
           && (str[i] <= '`' || str[i] > 'z')
           && str[i] != '+'
           && str[i] != '/' ) {
    printf("ERROR in base64integrity at chr %d (2nd last chr). String is NOT valid base64.\n", i);
    return 0;
  }
  int pos = i + 1;
  if ( str[pos] == '='
    || str[pos] > '/' && str[pos] <= '9'
    || str[pos] > '@' && str[pos] <= 'Z'
    || str[pos] > '`' && str[pos] <= 'z'
    || str[pos] == '+'
    || str[pos] == '/' )
  {
    return 1;
  }
  printf("ERROR in base64integrity at chr %d (last chr). String is NOT valid base64.\n", pos);
  return 0;
}

char *base64(char *str, int len, int *newLen) {
  int i;
  int padLen = (2 * (len % 3)) & 2 | ((len % 3) >> 1) & 1;
  *newLen = 4 * (len + padLen) / 3;
  char *buf = malloc(*newLen + 1);
  if ( buf )   {
    int pos = 0;
    for ( i = 0; i < len - 2; i += 3 ) {
      char c1 = str[i];
      char c2 = str[i + 1];
      char c3 = str[i + 2];
      buf[pos] = b64[c1 >> 2];
      buf[pos + 1] = b64[(16 * c1) & 0x30 | (c2 >> 4)];
      buf[pos + 2] = b64[(4 * c2) & 0x3C | (c3 >> 6)];
      buf[pos + 3] = b64[c3 & 0x3F];
      pos += 4;
    }
    if ( padLen == 1 ) {
      char c4 = str[i];
      char c5 = str[i + 1];
      buf[pos] = b64[c4 >> 2];
      buf[pos + 1] = b64[(16 * c4) & 0x30 | (c5 >> 4)];
      buf[pos + 2] = b64[(4 * c5) & 0x3C];
      buf[pos + 3] = '=';
      pos += 4;
    } else if ( padLen == 2 ) {
      char c6 = str[i];
      buf[pos] = b64[c6 >> 2];
      buf[pos + 1] = b64[(16 * c6) & 0x30];
      buf[pos + 2] = '=';
      buf[pos + 3] = '=';
      pos += 4;
    }
    buf[pos] = 0;
    return buf;
  } else {
    puts("ERROR: base64 could not allocate enough memory.");
    puts("I must stop because I could not get enough");
    return NULL;
  }
}

char *unbase64(char *str, int len, int *newLen) {
  int i;
  char *res;

  if ( !base64integrity(str, len) )
    return 0;
  int padLen = 0;
  if ( len > 1 ) {
    padLen = str[len - 1] == '=';
    if ( str[len - 2] == '=' )
      ++padLen;
  }
  *newLen = 3 * (len / 4) - padLen;
  if ( *newLen < 0 )
    *newLen = 0;
  res = (char *)malloc(*newLen);
  if ( res ) {
    int pos = 0;
    for ( i = 0; i <= len - 4 - padLen; i += 4 ) {
      char c1 = unb64[str[i + 1]];
      char c2 = unb64[str[i + 2]];
      char c3 = unb64[str[i + 3]];
      res[pos] = (c1 >> 4) | (4 * unb64[str[i]]);
      res[pos + 1] = (c2 >> 2) | (16 * c1);
      res[pos + 2] = c3 | (c2 << 6);
      pos += 3;
    }
    if ( (len & 3) == 0 ) {
      if ( padLen == 1 ) {
        char c4 = unb64[str[i + 1]];
        char c5 = unb64[str[i + 2]];
        res[pos] = (c4 >> 4) | (4 * unb64[str[i]]);
        res[pos + 1] = (c5 >> 2) | (16 * c4);
      } else if ( padLen == 2 ) {
        res[pos] = ((int)unb64[str[i + 1]] >> 4) | (4 * unb64[str[i]]);
      }
    }
    return res;
  } else {
    puts("ERROR: unbase64 could not allocate enough memory.");
    puts("I must stop because I could not get enough");
    return NULL;
  }
}


int fetchIntAndAddToVal(char *str, unsigned int val) {
  for ( int i = 0; i < strlen(str); ++i ) {
    char c = str[i];
    val += c << (8 * (strlen(str) - (i + 1)));
  }
  return val;
}

void parseIntIntoTempString(char *str, int val) {
  char dest[1000];
  strcpy(dest, str);
  for ( int i = 0; i < strlen(str); ++i )
    dest[i] = val >> (8 * (strlen(str) - (i + 1)));
}

void xorStringWith0x2A(char *str) {
  for ( int i = 0; i < strlen(str); ++i )
    str[i] ^= 0x2A;
}

void cycleRngManyTimes() {
  int n = 0;
  while ( n <= 131336 ) {
    if ( !(rand() % 31357) )
      ++n;
  }
}

void stringToBase64(char *str) {
  int resLen;
  char *res = base64(str, strlen(str), &resLen);
  strcpy(str, res);
}

void base64ToString(char *str) {
  int newLen;
  char *res = unbase64(str, strlen(str), &newLen);
  strcpy(str, res);
}

void appendLiquidSnake(char *str) {
  sleep(313376969u);
  strcpy((char *)&str[strlen(str)], "liquid-snake");
}

void expandCharsFourWay(char *str) {
  char sprintfBuf[5];
  char dest[16];
  char buf[984];

  memset(dest, 0, sizeof(dest));
  memset(buf, 0, sizeof(buf));
  for ( int i = 0; i < strlen(str); ++i ) {
    sprintf(sprintfBuf, "%c%c%c%c",
            str[i], (str[i] ^ 0x23),
            (str[i] - 12), (str[i] + 125));
    strcat(dest, sprintfBuf);
  }
  strcpy(str, dest);
}

void shuffleString52(char *str) {
  char src[56];

  if ( strlen(str) <= 0x57 ) {
    strcpy(str, "!!SPY DETECTED!!");
  } else {
    src[0] = 99;
    src[1] = str[68];
    src[2] = 104;
    src[3] = str[13];
    src[4] = str[47];
    src[5] = str[77];
    src[6] = str[85];
    src[7] = str[4];
    src[8] = str[47];
    src[9] = str[14];
    src[10] = 116;
    src[11] = str[30];
    src[12] = str[47];
    src[13] = str[84];
    src[14] = str[41];
    src[15] = str[36];
    src[16] = str[64];
    src[17] = str[78];
    src[18] = str[32];
    src[19] = 111;
    src[20] = str[47];
    src[21] = str[2];
    src[22] = str[6];
    src[23] = 105;
    src[24] = str[47];
    src[25] = str[14];
    src[26] = str[41];
    src[27] = str[53];
    src[28] = str[62];
    src[29] = str[17];
    src[30] = str[11];
    src[31] = str[4];
    src[32] = str[25];
    src[33] = str[64];
    src[34] = str[16];
    src[35] = str[84];
    src[36] = str[64];
    src[37] = str[78];
    src[38] = str[48];
    src[39] = 111;
    src[40] = str[47];
    src[41] = str[5];
    src[42] = str[9];
    src[43] = str[4];
    src[44] = str[47];
    src[45] = str[14];
    src[46] = str[41];
    src[47] = str[53];
    src[48] = str[60];
    src[49] = str[56];
    src[50] = str[87];
    src[51] = str[86];
    src[52] = 0;
    strcpy(str, src);
  }
}

void makeRandomStringOfSimilarLength(char *src, char *dest) {
  char buf[1000];

  strcpy(buf, src);
  for ( int i = 0; i < strlen(src); ++i ) {
    for ( int j = 0x7A69 * rand(); j > 0; --j )
      buf[i] = rand() % 0x7D;
  }
  strcpy(dest, buf);
}

int checkForDuplicateCharacters(char *str) {
  for ( int i = 0; i < strlen(str) - 1; ++i ) {
    for ( int j = i + 1; j < strlen(str); ++j ) {
      if ( str[i] == str[j] ) {
        printf("Duplicate character detected: %c\n", (unsigned int)str[i]);
        return 1;
      }
    }
  }
  return 0;
}

int main(int argc, char **argv, char **envp) {
  char input[6];
  char string1[52];
  char buf1000[1000];

  sleep(1);
  srand(time(0));
  strcpy(string1, "duckslovelettuce");
  string1[17] = 0;
  *(short *)&string1[18] = 0;
  *(int *)&string1[20] = 0;
  *(long *)&string1[24] = 0;
  memset(&string1[32], 0, 968);
  memset(buf1000, 0, sizeof(buf1000));
  int val = 0;
  printf("Please enter the arguments: ");
  fflush(stdout);
  if ( fgets(input, 6, stdin) ) {
    input[strcspn(input, "\r\n")] = 0;   // This just strips CR/LF
    if ( checkForDuplicateCharacters(input) ) {
      puts("No duplicate input allowed.");
      usleep(100000);
      return 1;
    } else {
      int pos = 0;
      while ( 1 ) {
        if ( pos < strlen(input) ) {
          char option = input[pos];
          switch ( option ) {
            case 'a':
              val = fetchIntAndAddToVal(string1, val);
              goto CHECK_AND_CONTINUE;
            case 'b':
              parseIntIntoTempString(string1, val);
              goto CHECK_AND_CONTINUE;
            case 'c':
              xorStringWith0x2A(string1);
              goto CHECK_AND_CONTINUE;
            case 'd':
              cycleRngManyTimes();
              goto CHECK_AND_CONTINUE;
            case 'e':
              stringToBase64(string1);
              goto CHECK_AND_CONTINUE;
            case 'f':
              base64ToString(string1);
              goto CHECK_AND_CONTINUE;
            case 'g':
              appendLiquidSnake(string1);
              goto CHECK_AND_CONTINUE;
            case 'h':
              expandCharsFourWay(string1);
              goto CHECK_AND_CONTINUE;
            case 'i':
              shuffleString52(string1);
              goto CHECK_AND_CONTINUE;
            case 'j':
              makeRandomStringOfSimilarLength(string1, buf1000);
CHECK_AND_CONTINUE:
              if ( !strncmp(string1, "shc2023{", 8) ) {
                printf("I think you solved it: %s\n", string1);
                printf("Also, you deserve to know the initial string, just for the memes: %s\n", "duckslovelettuce");
                puts(
                  "Great now to the mission briefing. Infiltrate the enemy fortress, Outer Heaven, and destroy Metal Gear"
                  ", the final weapon! Our spies have found a vulnerable door near the hangar, exploit it, enter the fort"
                  "ress and learn about the Metal Gear.");
                usleep(100000);
              }
              ++pos;
              continue;
            default:
              printf("Invalid option %c\n", (unsigned int)option);
              usleep(100000);
              return 1;
          }
        }
        return 0;
      }
    }
  } else {
    puts("Could not read input :(");
    usleep(100000);
    return 1;
  }
}
