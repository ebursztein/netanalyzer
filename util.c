/*
* NetAnalyzer -multithreaded portable statefull Network passive analyzer
* Project page: http://code.google.com/p/netanalyzer/
* Author: Elie Bursztein LSV, ENS-Cachan, CNRS, INRIA
* Email: elie@bursztein.eu
* Licence: GPL v2 
*
* netAnalyzer is (C) Copyright 2008  by Elie Bursztein 
*/
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <ctype.h>
#include <stdarg.h>
#include <assert.h>
#include "headers/structure.h"
#include "headers/structure.h"
#include "headers/constant.h"
#include "headers/function.h"
#include "headers/protocol.h"

/*!
 *       \file util.c
 *       \brief Utility functions used in the analyzer.
 *
 *       Various standard utility function such as die or xmalloc
 *       \author  Elie
 *       \version 1.0
 *       \date    July 2006
 */

extern	t_option 	option;
extern	fd_set 		active_fd_set;

/*!
 * compute a int from a char* used for speed comparaison
 * @param str the string to hash
 * @return an unsigned long
 * \version 1
 * \date    Feb 2007
 * \author Elie
 * \attention
 * \todo
 */
_u64	crc(char  *str)
{
	_u64 hash = 5381;
	_u32 c;
	if (!str)
		return 1;
	
	while ((c = *str++))
		hash = ((hash << 5) + hash) + c; /* hash * 33 + c */
	
	assert(hash);
	return hash;
}
//fixeme ip local 127 10.0 etc
_u8		ip_is_broadcast(_u32 ip)
{
	//ip are in big endian
	//0.0.0.0
	if (ip == 0)
		return 1;
	//x.x.x.255
	if ((ip >> 24) == 255)
		return 1;
	//255.255.255.x
	if ((ip<<8) & 0xffffff00)
		return 1;
	
		return 0;
}
/*
#define ASIZE 256
void preBmBc(char *x, int m, int bmBc[]) {
   int i;

   for (i = 0; i < ASIZE; ++i)
      bmBc[i] = m;
   for (i = 0; i < m - 1; ++i)
      bmBc[(int)(x[i])] = m - i - 1;
}

//Fast Boyer Moore matching algorithm
int match(char *x, int m, char *y, int n) {
   int j, k, shift, bmBc[ASIZE];

   // Preprocessing
   preBmBc(x, m, bmBc);
   shift = bmBc[(int)(x[m - 1])];
   bmBc[(int)(x[m - 1])] = 0;
   memset(y + n, x[m - 1], m);

   // Searching
   j = 0;
   while (j < n) {
      k = bmBc[(int) (y[j + m -1])];
      while (k !=  0) {
         j += k; k = bmBc[(int)(y[j + m -1])];
         j += k; k = bmBc[(int)(y[j + m -1])];
         j += k; k = bmBc[(int)(y[j + m -1])];
      }
      if (memcmp(x, y + j, m - 1) == 0 && j < n)
         return (j);
      j += shift;                          //
   }
   return NULL;
}*/

/*!
 * pattern match return start pos et end pos of a substring (if exist) 
 * @param str the string
 * @param begin the char that start the substring
 * @param end the char that end the substring
 * @return ch containt two pointer one for the beginning of the substring and one for the end
 * \version 1.0
 * \date    2006
 * \author Elie
 */ 
t_chunk chunk(char *str, char *begin, char *end)
{
        t_chunk ch;

        ch.start = ch.end = NULL;
        //FIXME is it possible to improve matching perf ? BM ? or other ?
        if (!str || !begin || !end)
                return ch;
        if((ch.start = strstr(str, begin)) == 0)
                return ch;
        ch.start += strlen(begin);
        if((ch.end = strstr(ch.start, end)) == 0)
                ch.start = NULL;
        return ch;
}

/*
//pattern match : return start pos et end pos of a substring (if exist)
t_chunk chunkn(char *str, char *begin, char *end, int len)
{
        t_chunk ch;

        ch.start = ch.end = NULL;
        //FIXME is it possible to improve matching perf ? BM ? or other ?
        if (!str || !begin || !end || len == 0)
                return ch;
        if((ch.start = strnstr(str, begin, len)) == 0)
                return ch;
        ch.start += strlen(begin);
        len -= strlen(ch.start);
        if((ch.end = strnstr(ch.start, end, len)) == 0)
                ch.start = NULL;
        return ch;
} */
//anti_evasion humf no use 
t_pkt *anti_evasion(t_pkt *entry)
{
    char prev = 'a';
    int i,j;

    //cleaning
    for(i = j = entry->decoded_len; i < entry->len; i++)
    {
        switch (entry->buf[i]) {
            case ' ':
                if (prev != ' ')
                    entry->buf[j++] = prev = ' ';
            case '\t':
                    if (prev != ' ')
                    entry->buf[j++] = prev = ' ';
                break;
            case '\r':
                    if (prev != ' ')
                    entry->buf[j++] = prev = ' ';
                break;
            case '\n':
                    if (prev != ' ')
                    entry->buf[j++] = prev = ' ';
                break;
            case '\0':
                break;
            default :
                entry->buf[j++] = prev = entry->buf[i];
        }
    }
    //filling with \0
    for(;j < entry->len ; j++)
        entry->buf[j] = '\0';
    //returning a nice washed packet
    return entry;
}
#if defined(__NetBSD__) || defined(__FreeBSD__) || defined(__OpenBSD__) || defined(__APPLE__)
//compatiblity piss me of


/* GNU libc getline() compatibility */

int
getline(char** line, size_t* size, FILE* fp)
{
        static const size_t line_grow_by = 80; /* in most texts line fits console */
        int ch;
        size_t i;

        if (line == NULL || size == NULL || fp == NULL) { /* illegal call */
                errno = EINVAL;
                return -1;
        }
        if (*line == NULL && *size) { /* logically incorrect */
                errno = EINVAL;
                return -1;
        }

        i = 0;
        while (1) {
                ch = fgetc(fp);
                if (ch == EOF)
                        break;
                /* ensure bufer still large enough for ch and trailing null */
                if ((*size - i) <= 1) {
                        *line = (char*)realloc(*line, *size += line_grow_by);
                        if (*line == NULL) {
                                errno = ENOMEM;
                                return -1;
                        }
                }
                *(*line + i++) = (char)ch;
                if (ch == '\n')
                        break;
        }
        
        *(*line + i) = 0;
        
        return ferror(fp) ? -1 : i;
}

#endif


//portable strndup 
char *my_strndup(char *str, unsigned int n) {
	char *rv = NULL;
	if(n == 0)
		return rv; 
	rv = malloc(n + 1);
	memset(rv, 0, n + 1);
	memcpy(rv, str, n); 
	return rv; 
}


/*!
 * secure malloc 
 *
 * check the size and be sure malloc is working
 * @param size of malloc
 * \version 1.0
 * \date    2006
 * \author Elie
 */
void *xmalloc(size_t size)
{
	void *mem;
	if ((int) size < 0) 
		die("mallocing negative amount of memory");
	mem = malloc(size);
	if (mem == NULL)
		warning("Malloc failed, Probably out of space.");
	return mem;
}


// A simple function to form a character from 2 hex digits in ASCII form
static unsigned char hex2char(char a, char b)
{
	int val;
	if (!isxdigit(a) || !isxdigit(b)) return 0;
	a = tolower(a);
	b = tolower(b);
	if (isdigit(a))
		val = (a - '0') << 4;
	else val = (10 + (a - 'a')) << 4;

	if (isdigit(b))
		val += (b - '0');
	else val += 10 + (b - 'a');

	return (unsigned char) val;
}

/* Convert a string in the format of a roughly C-style string literal
   (e.g. can have \r, \n, \xHH escapes, etc.) into a binary string.
   This is done in-place, and the new (shorter or the same) length is
   stored in newlen.  If parsing fails, NULL is returned, otherwise
   str is returned. */
char *cstring_unescape(char *str, unsigned int *newlen) {
	char *dst = str, *src = str;
	char newchar;

	while(*src) {
		if (*src == '\\' ) {
			src++;
			switch(*src) {
				case '0':
					newchar = '\0'; src++; break;
				case 'a': // Bell (BEL)
					newchar = '\a'; src++; break;	
				case 'b': // Backspace (BS)
					newchar = '\b'; src++; break;	
				case 'f': // Formfeed (FF)
					newchar = '\f'; src++; break;	
				case 'n': // Linefeed/Newline (LF)
					newchar = '\n'; src++; break;	
				case 'r': // Carriage Return (CR)
					newchar = '\r'; src++; break;	
				case 't': // Horizontal Tab (TAB)
					newchar = '\t'; src++; break;	
				case 'v': // Vertical Tab (VT)
					newchar = '\v'; src++; break;	
				case 'x':
					src++;
					if (!*src || !*(src + 1)) return NULL;
					if (!isxdigit(*src) || !isxdigit(*(src + 1))) return NULL;
					newchar = hex2char(*src, *(src + 1));
					src += 2;
					break;
				default:
					if (isalnum(*src))
						return NULL; // I don't really feel like supporting octals such as \015
	// Other characters I'll just copy as is
					newchar = *src;
					src++;
					break;
			}
			*dst = newchar;
			dst++;
		} else {
			if (dst != src)
				*dst = *src;
			dst++; src++;
		}
	}

	*dst = '\0'; // terminated, but this string can include other \0, so use newlen
	if (newlen) *newlen = dst - str;
	return str;
}
