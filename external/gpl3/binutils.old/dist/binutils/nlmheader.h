/* A Bison parser, made by GNU Bison 2.3.  */

/* Skeleton interface for Bison's Yacc-like parsers in C

   Copyright (C) 1984, 1989, 1990, 2000, 2001, 2002, 2003, 2004, 2005, 2006
   Free Software Foundation, Inc.

   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 2, or (at your option)
   any later version.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program; if not, write to the Free Software
   Foundation, Inc., 51 Franklin Street, Fifth Floor,
   Boston, MA 02110-1301, USA.  */

/* As a special exception, you may create a larger work that contains
   part or all of the Bison parser skeleton and distribute that work
   under terms of your choice, so long as that work isn't itself a
   parser generator using the skeleton or a modified version thereof
   as a parser skeleton.  Alternatively, if you modify or redistribute
   the parser skeleton itself, you may (at your option) remove this
   special exception, which will cause the skeleton and the resulting
   Bison output files to be licensed under the GNU General Public
   License without this special exception.

   This special exception was added by the Free Software Foundation in
   version 2.2 of Bison.  */

/* Tokens.  */
#ifndef YYTOKENTYPE
# define YYTOKENTYPE
   /* Put the tokens into the symbol table, so that GDB and other debuggers
      know about them.  */
   enum yytokentype {
     CHECK = 258,
     CODESTART = 259,
     COPYRIGHT = 260,
     CUSTOM = 261,
     DATE = 262,
     DEBUG_K = 263,
     DESCRIPTION = 264,
     EXIT = 265,
     EXPORT = 266,
     FLAG_ON = 267,
     FLAG_OFF = 268,
     FULLMAP = 269,
     HELP = 270,
     IMPORT = 271,
     INPUT = 272,
     MAP = 273,
     MESSAGES = 274,
     MODULE = 275,
     MULTIPLE = 276,
     OS_DOMAIN = 277,
     OUTPUT = 278,
     PSEUDOPREEMPTION = 279,
     REENTRANT = 280,
     SCREENNAME = 281,
     SHARELIB = 282,
     STACK = 283,
     START = 284,
     SYNCHRONIZE = 285,
     THREADNAME = 286,
     TYPE = 287,
     VERBOSE = 288,
     VERSIONK = 289,
     XDCDATA = 290,
     STRING = 291,
     QUOTED_STRING = 292
   };
#endif
/* Tokens.  */
#define CHECK 258
#define CODESTART 259
#define COPYRIGHT 260
#define CUSTOM 261
#define DATE 262
#define DEBUG_K 263
#define DESCRIPTION 264
#define EXIT 265
#define EXPORT 266
#define FLAG_ON 267
#define FLAG_OFF 268
#define FULLMAP 269
#define HELP 270
#define IMPORT 271
#define INPUT 272
#define MAP 273
#define MESSAGES 274
#define MODULE 275
#define MULTIPLE 276
#define OS_DOMAIN 277
#define OUTPUT 278
#define PSEUDOPREEMPTION 279
#define REENTRANT 280
#define SCREENNAME 281
#define SHARELIB 282
#define STACK 283
#define START 284
#define SYNCHRONIZE 285
#define THREADNAME 286
#define TYPE 287
#define VERBOSE 288
#define VERSIONK 289
#define XDCDATA 290
#define STRING 291
#define QUOTED_STRING 292




#if ! defined YYSTYPE && ! defined YYSTYPE_IS_DECLARED
typedef union YYSTYPE
#line 113 "nlmheader.y"
{
  char *string;
  struct string_list *list;
}
/* Line 1529 of yacc.c.  */
#line 128 "nlmheader.h"
	YYSTYPE;
# define yystype YYSTYPE /* obsolescent; will be withdrawn */
# define YYSTYPE_IS_DECLARED 1
# define YYSTYPE_IS_TRIVIAL 1
#endif

extern YYSTYPE yylval;

