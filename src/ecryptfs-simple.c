/*
Copyright (C) 2012-2016  Xyne

This program is free software; you can redistribute it and/or
modify it under the terms of the GNU General Public License
(version 2) as published by the Free Software Foundation.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program; if not, write to the Free Software
Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
*/



/*
  # 2012-06-25
  Ok, scratch that. Upstream decided to move things around without even
  mentioning it in a changelog. The library is simply not dependable and I am
  beginning to doubt the wisdom of using eCryptfs for important files. Hopefully
  this will be stable or at least not too difficult to maintain.

  # 2012-06-17
  The original implemention was much simpler than this because it called
  mount.ecryptfs externally. That did not allow for option extraction and I was
  left with 2 choices: either hook directly into the mount.ecryptfs source files
  or use functions in ecryptfs.h to re-implement the functionality myself.

  I chose the former because I do not have a complete understanding of
  everything that mount.ecryptfs does (e.g. I still haven't looked at how it
  manages keyrings) and I did not have the time to go through all of it, which I
  would have to do in detail to make sure that I did not inadvertantly open up a
  security hole. My assumption was and still is that the code in mount.ecryptfs
  has been vetted enough to provide a reasonable expectation of security.

  Of course, writing this ended up taking much more time that I had expected
  (most things usually do). The code in mount.ecryptfs is a tangled mess in some
  places and there are many things in there and the files it includes that
  should be cleaned up and added to the main ecryptfs library. Given the state
  of the code below, I can't really say much about it, but it was frustrating to
  work with nevertheless.

  A lot of the code below was written just to manipulate the option string. The
  options need to be in a given order, "default" options need to be specified
  when using passphrases because the interactive prompt cannot fill them in
  automatically while still requesting a passphrase, etc.

  In the end, I probably should have just implemented my own mounting code, and
  I probably will if the current approach becomes difficult to maintain.
  Nevertheless, this works and it should be as secure as mount.ecryptfs.


  TODO
  * Consider statically linking code for stability.
  * Clean up the code when I have some time.
  * Centralize stdout messages.
  * Maybe use return codes instead of exiting on failure to make code re-usable.
  * Finish adding debug_print commands.
*/




// define this so gcc doesn't complain about ecryptfs using asprintf
// #define _GNU_SOURCE
#include <stdio.h>
#include <grp.h>
#include <sys/types.h>
#include <unistd.h>
#include <limits.h>
#include <linux/limits.h>
#include <stdlib.h>
#include <alloca.h>
#include <sys/mount.h>
#include <argp.h>
#include <assert.h>
#include <ecryptfs.h>
#include <errno.h>
#include <gcrypt.h>
#include <libmount/libmount.h>
#include <signal.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <termios.h>
#include <unistd.h>

// #include "mount.ecryptfs.c"
#include "ecryptfs_options.h"

#ifndef _GNU_SOURCE
typedef int (* comparison_fn_t)(const void *, const void *);
#endif


#define FS_TYPE "ecryptfs"
#define MAX_OPTS_STR_LEN 0x400
#define MAX_INPUT_STR_LEN 255
#define NAME "ecryptfs-simple"
#include "version.h"


#define SHA512LEN 64
#define SHA512(input, output) gcry_md_hash_buffer(GCRY_MD_SHA512, output, input, strlen(input))

// Options
#define YES_OPTION "y"
#define NO_OPTION "n"
#define FNEK_SIG_OPTIONS "ecryptfs_fnek_sig"
#define FNE_OPTION "ecryptfs_enable_filename_crypto"

static char * excluded_options = NULL;


/*******************************************************************************
 Debugging
*******************************************************************************/


#define USE_COLOR
// #undef USE_COLOR
#ifndef DEBUG
  #define DEBUG 0
#endif

static int INDENT_LEVEL = 0;

#define UNUSED(x) if(x){}

// Nested debug messages to facilitate tracing.
#ifdef DEBUG
void
__cyg_profile_func_enter(void * this_fn, void * call_site)
{
  UNUSED(this_fn);
  UNUSED(call_site);
  INDENT_LEVEL += 1;
}

void
__cyg_profile_func_exit(void * this_fn, void * call_site)
{
  UNUSED(this_fn);
  UNUSED(call_site);
  INDENT_LEVEL -= 1;
}
#endif

#ifdef USE_COLOR
  #define FILENAME_COLOR "\033[34m"
  #define LINENUMBER_COLOR "\033[36m"
  #define FUNCTIONNAME_COLOR "\033[35m"
  #define RESET_COLOR "\033[0m"
#else
  #define FILENAME_COLOR ""
  #define LINENUMBER_COLOR ""
  #define FUNCTIONNAME_COLOR ""
  #define RESET_COLOR ""
#endif

#ifndef DEBUG_FD
  #define DEBUG_FD stderr
#endif

// With indentation

#define debug_print_prefix \
  int i = INDENT_LEVEL; \
  while(i--) \
  { \
    fprintf(stderr, "  "); \
  } \
  fprintf(\
    DEBUG_FD, \
    "%s%s %s%d %s%s(): %s", \
    FILENAME_COLOR, \
    __FILE__, \
    LINENUMBER_COLOR, \
    __LINE__, \
    FUNCTIONNAME_COLOR, \
    __func__, \
    RESET_COLOR \
  )

/*
#define debug_print_prefix \
  fprintf(\
    DEBUG_FD, \
    "%s%s %s%d %s%s(): %s", \
    FILENAME_COLOR, \
    __FILE__, \
    LINENUMBER_COLOR, \
    __LINE__, \
    FUNCTIONNAME_COLOR, \
    __func__, \
    RESET_COLOR \
  )
*/

#define debug_print(fmt, ...) \
do \
{ \
  if (DEBUG) \
  { \
    debug_print_prefix; \
    fprintf(\
      DEBUG_FD, \
      fmt, \
      __VA_ARGS__ \
    ); \
  } \
} while (0)

#define debug_print0(msg) \
do \
{ \
  if (DEBUG) \
  { \
    debug_print_prefix; \
    fprintf(\
      DEBUG_FD, \
      msg \
    ); \
  } \
} while (0)




/*******************************************************************************
 Message Handling
*******************************************************************************/

/*
  Centralized error message handling in case I decide to implement logging
  later.
*/
void
die_v(char * msg, va_list args)
{
  vfprintf(stderr, msg, args);
  exit(EXIT_FAILURE);
}

void
die(char * msg, ...)
{
  va_list args;
  va_start(args, msg);
  die_v(msg, args);
  va_end(args);
}

void
warning(const char * msg)
{
  puts(msg);
}


/*******************************************************************************
 Privilege Management
*******************************************************************************/

// http://www.gnu.org/software/hello/manual/libc.html#How-Change-Persona
static uid_t euid, ruid;
static gid_t egid, rgid;

void
initialize_uids(void)
{
  ruid = getuid();
  euid = geteuid();
  rgid = getgid();
  egid = getegid();
  debug_print("ruid: %u, euid: %u, rgid: %u, egid: %u\n", ruid, euid, rgid, egid);
}

void
resume_privileges (void)
{
  int status;
  if (ruid == euid && rgid == egid)
  {
    return;
  }
#ifdef _POSIX_SAVED_IDS
  status = seteuid (euid) + setegid(egid);
#else
  status = setreuid (ruid, euid) + setregid(rgid, egid);
#endif
  if (status < 0)
  {
    die("error: failed to resume privileges\n");
  }
  debug_print("euid: %u, egid: %u\n", euid, egid);
}


void
drop_privileges (void)
{
  int status;
  if (ruid == euid && rgid == egid)
  {
    return;
  }
#ifdef _POSIX_SAVED_IDS
  status = setegid(rgid) + seteuid (ruid);
#else
  status = setregid(egid, rgid) + setreuid (euid, ruid);
#endif
  if (status < 0)
  {
    die("error: failed to drop privileges\n");
  }
  debug_print("euid: %u, egid: %u\n", euid, egid);
}





/*******************************************************************************
 Substitute declarations for things in mount.ecryptfs.c
*******************************************************************************/

int opts_str_contains_option(char * str, char * option)
{
  debug_print("needle: \"%s\", haystack: \"%s\"\n", option, str);
  int i, j, k;
  if (option[0] == '\0')
  {
    return 1;
  }
  if (str[0] == '\0')
  {
    return 0;
  }
  i = 0;
  while (str[i] != '\0')
  {
    j = 0;
    k = i;
    while(
      str[k] == option[j] &&
      str[k] != '\0' &&
      option[j] != '\0'
    )
    {
      j ++;
      k ++;
    }
    if (
      option[j] == '\0' &&
      (str[k] != '\0' || str[k] != '=' || str[k] != ',')
    )
    {
      return 1;
    }
    i ++;
  }
  return 0;
}

// This really should be included in the ecryptfs.h header.
struct val_node {
  void *val;
  struct val_node *next;
};

typedef struct {
  char * value;
  size_t size;
}Buffer;

/*******************************************************************************
 Copied From Synclinks
*******************************************************************************/

mode_t S_ALL = S_IRWXU | S_IRWXG | S_IRWXO;

/*
  Get the current umask.
*/
mode_t
read_umask (void)
{
  mode_t mask = umask (0);
  umask (mask);
  return mask;
}

/*
  Create missing parent directories.
*/
int
mkdir_p(char * path)
{
  int i, l, e=0;
  mode_t mode, mask;
  mask = umask (0);
  umask(mask);
  /*
    Only proceed if the target does not exist and the path is not empty.
  */
  if (access(path, F_OK) && (l = strlen(path)))
  {
    // find first existing parent
    for (i = l-1; i >= 0; i--)
    {
      if (path[i] == '/')
      {
        path[i] = '\0';
        if (! access(path, F_OK))
        {
          break;
        }
      }
    }
    // Climb back up, creating dirs as we go.
    for (; i < l; i++)
    {
      if (path[i] == '\0')
      {
        path[i] = '/';
        mode = S_ALL & (~ mask);
        // Last one.
        if (l - i == 1)
        {
          mode &= (~ (S_IRWXG | S_IRWXO));
        }
        if (mkdir(path, mode))
        {
          if (errno != EEXIST)
          {
            e = 1;
          }
        }
      }
    }
  }
  return e;
}









/*
  Digest the input string.
*/
void
sha512_hexdigest(char * digest, const char * input)
{
  char * cursor;
  int i;

  cursor = digest + SHA512LEN;
  SHA512(input, cursor);
  for (i=0; i<SHA512LEN; i++)
  {
    sprintf(digest +(i * 2), "%02x", (unsigned char) cursor[i]);
  }
}



/*
  Join path components to a single path. If b is an absolute path, a is ignored.
  A trailing slash is added to a if b is NULL. a may not be NULL.
*/
void
join_paths(Buffer * e, const char * b)
{
  size_t i = 0;
  char * a = e->value;

  if (b != NULL && b[0] == '/')
  {
    snprintf(e->value, e->size, "%s", b);
    return;
  }

  while (a[i] != '\0')
  {
    if (i == e->size - 1)
    {
       die( "error: buffer overflow detected");
    }
    else
    {
       i ++;
    }
  }
  if (i > 0 && a[i-1] != '/')
  {
    a[i] = '/';
  }
  if (b != NULL)
  {
    snprintf(a + i, e->size - i, "%s", b);
  }
}


/*
  Get the path of the configuration file directory.
*/
void
get_config_dir(Buffer * path)
{
  char * value;
  value = getenv("XDG_CONFIG_HOME");
  if (value  != NULL)
  {
    snprintf(path->value, path->size,"%s",value);
  }
  else
  {
    value = getenv("HOME");
    snprintf(path->value, path->size,"%s", value);
    join_paths(path, ".config");
  }

  join_paths(path, NAME);

  drop_privileges();

  if (mkdir_p(path->value))
  {
    die("error: failed to create configuration directory (%s)\n", strerror(errno));
  }
  resume_privileges();
}


/*
  Return the path to a parameter file in the configuration directory. The name
  of the file will be the hashed input path. The input path must exist.
*/
void
get_parameter_filepath(Buffer * output_path, char * source_path, char * input_path)
{
  char * fullpath;
  if (input_path != NULL)
  {
    if (input_path[0] == '/' && input_path[1] == '/')
    {
      snprintf(output_path->value, output_path->size, "%s%s",source_path, input_path+1);
    }
    else
    {
      snprintf(output_path->value, output_path->size, "%s", input_path);
    }
    return;
  }
  get_config_dir(output_path);
  join_paths(output_path, NULL);
  fullpath = realpath(source_path, NULL);
  if (fullpath == NULL)
  {
    die(
      "error: failed to canonicalize path (%s: %s)\n",
      source_path,
      strerror(errno)
    );
  }
  sha512_hexdigest(output_path->value + strlen(output_path->value), fullpath);
  free(fullpath);
}



/*
  Ensure that the path is an accessible directory.
*/
void
ensure_accessible_directory(char * path)
{
  struct stat st;
  if (stat(path, &st))
  {
    die("error: failed to stat %s (%s)\n", path, strerror(errno));
  }
  if (! S_ISDIR(st.st_mode))
  {
    die("error: %s is not a directory\n", path);
  }
  if (access(path, R_OK | W_OK | X_OK))
  {
    die("error: insufficient permissions on %s\n", path);
  }
  return;
}



/*******************************************************************************
 Mounting
*******************************************************************************/


/*
  Check if the path is a mountpoint.
*/
int
is_mountpoint(char * path, int ensure_ecryptfs)
{
  // See mountpoint.c
  struct libmnt_table * tb = mnt_new_table_from_file("/proc/self/mountinfo");
  struct libmnt_fs * fs;
  struct libmnt_cache * cache;
  const char * fstype;

  cache = mnt_new_cache();
  mnt_table_set_cache(tb, cache);
  fs = mnt_table_find_target(tb, path, MNT_ITER_BACKWARD);

  mnt_free_table(tb);
  mnt_free_cache(cache);


  if (fs)
  {
    if (ensure_ecryptfs)
    {
      fstype = mnt_fs_get_fstype(fs);
      return (strcmp(fstype, FS_TYPE) == 0);
    }
    return 1;
  }
  return 0;
}



int
mnt_match_source(struct libmnt_fs * fs, void * path)
{
  const char * mnt_path;
  mnt_path = mnt_fs_get_srcpath(fs);
  return (
           strcmp(mnt_path, (char *) path) == 0 &&
           strcmp(mnt_fs_get_fstype(fs), FS_TYPE) == 0
         );
}



int
mnt_match_target(struct libmnt_fs * fs, void * path)
{
  const char * mnt_path;
  mnt_path = mnt_fs_get_target(fs);
  return (
           strcmp(mnt_path, (char *) path) == 0 &&
           strcmp(mnt_fs_get_fstype(fs), FS_TYPE) == 0
         );
}



void
unmount_target(const char * path)
{
  printf("unmounting %s\n", path);
  if (umount2(path, 0))
  {
    die("error: failed to unmount %s (%s)\n", path, strerror(errno));
  }
}



int
unmount_simple(char * path)
{
  //http://www.kernel.org/pub/linux/utils/util-linux/v2.21/libmount-docs/index.html
  struct libmnt_table * tb = mnt_new_table_from_file("/proc/self/mountinfo");
  struct libmnt_fs * fs;
  struct libmnt_cache * cache;
  struct libmnt_iter * iter;
  const char * target;
  int did_something;

  did_something = 0;
  cache = mnt_new_cache();
  mnt_table_set_cache(tb, cache);
  iter = mnt_new_iter(MNT_ITER_BACKWARD);

  while (
    ! mnt_table_find_next_fs(tb, iter, mnt_match_source, (void *) path, &fs) &&
    fs != NULL
  )
  {
    target = mnt_fs_get_target(fs);
    if (target != NULL)
    {
      unmount_target(target);
      did_something = 1;
    }
  }

  mnt_reset_iter(iter, MNT_ITER_BACKWARD);

  while (
    ! mnt_table_find_next_fs(tb, iter, mnt_match_target, (void *) path, &fs) &&
    fs != NULL
  )
  {
    target = mnt_fs_get_target(fs);
    if (target != NULL)
    {
      unmount_target(target);
      did_something = 1;
    }
  }

  mnt_free_table(tb);
  mnt_free_cache(cache);
  mnt_free_iter(iter);


  if (did_something)
  {
    printf("You may now remove leftover keys with keyctl if you are done.\n");
    return EXIT_SUCCESS;
  }
  else
  {
    printf("No matching " FS_TYPE " mountpoints found.\n");
    return EXIT_FAILURE;
  }
}



/*******************************************************************************
 Parameter Handling
*******************************************************************************/

/*
  Remove whitespace and empty options from an options string. This assumes that
  no options will contain whitespace in them.

  TODO
  Reconsider assumption and keep whitespace where necessary.
*/
void
clean_opts_str(char * str)
{
  int i, j;

  debug_print("cleaning options string: \"%s\" (%zi)\n", str, strlen(str));

  i = 0;
  j = 0;
  while(str[j] == ',' || str[j] == ' ' || str[j] == '\n')
  {
    j ++;
  }
//   debug_print("skipped %d character(s)\n", j);
  do
  {
    if
    (
      // Skip whitespace.
      str[j] != ' ' &&
      str[j] != '\n' &&
      // Skip empty options (",,")
      (
	str[j] != ',' ||
	(i > 0 && str[i-1] != ',')
      )
    )
    {
      str[i] = str[j];
      i ++;
    }
    j ++;
  }
  while(str[j] != '\0');
  // Add terminating null character and strip any trailing commas.
  do
  {
    str[i] = '\0';
  }
  while(i > 0 && str[--i] == ',');
  debug_print("output string: \"%s\" (%zi)\n", str, strlen(str));
}

/*
  Insert a null character into a parameter string to faciliate name comparisons.
*/
int
maybe_insert_eq(char * param)
{
  int i;

//   debug_print("input string: \"%s\"\n", param);

  i = 0;
  while(param[i] != '\0')
  {
    if (param[i] == '=')
    {
      param[i] = '\0';
//       debug_print("output string: \"%s\"\n", param);
      return i;
    }
    i ++;
  }
//   debug_print("output string: \"%s\"\n", param);
  return -1;
}

/*
  Compare option names and overwrite existing options in the array, otherwise
  append the new one.

  Returns 1 if the parameter was appended, 0 otherwise.
*/
int
arr_maybe_append_parameter(char * * arr, char * param)
{
  int a, b, same;
  char * elem;

//   debug_print("param: \"%s\"\n", param);
  b = maybe_insert_eq(param);

  // Skip excluded options.
  if (
    excluded_options != NULL &&
    opts_str_contains_option(excluded_options, param)
  )
  {
    if (b >= 0)
    {
      param[b] = '=';
    }
    debug_print("ignoring excluded parameter \"%s\"\n", param);
    return 0;
  }
  while ((elem = arr[0]) != NULL)
  {
    a = maybe_insert_eq(elem);
//     debug_print("comparing \"%s\" to \"%s\"\n", param, elem);
    same = (strcmp(elem, param) == 0);
    if (a >= 0)
    {
      elem[a] = '=';
    }
    if (same)
    {
      arr[0] = param;
      if (b >= 0)
      {
	param[b] = '=';
      }
      debug_print("overwrote \"%s\" to \"%s\"\n", elem, param);
      return 0;
    }
    arr ++;
  }
  arr[0] = param;
  if (b >= 0)
  {
    param[b] = '=';
  }
  debug_print("appended \"%s\"\n", param);
  return 1;
}


int
str_maybe_append_parameter(char * target, char * dirty_param, int i)
{
  char param[MAX_OPTS_STR_LEN]={0};
  int j;

  if (i < 0)
  {
    i = strlen(target);
  }
  snprintf(param, sizeof(param),"%s",dirty_param);
  clean_opts_str(param);
  debug_print("target: \"%s\", param: \"%s\", pos: %d\n", target, param, i);
  if (param[0] == '\0')
  {
    debug_print0("skipping empty parameter\n");
    return i;
  }
  if (i > 0)
  {
    // Room needed for null character and comma.
    if (MAX_OPTS_STR_LEN - i < 2)
    {
      die(
      "error: maximum option string length exceeded (%u/%u)\n",
       i + 2,
       MAX_OPTS_STR_LEN
      );
    }
    target[i++] = ',';
    target[i] = '\0';
    debug_print("added comma: \"%s\"\n", target);
  }
  for (j=0; param[j] != '\0'; ++j)
  {
    if (MAX_OPTS_STR_LEN - i < 2)
    {
      die(
       "error: maximum option string length exceeded (%u/%u)\n",
       i + 2,
       MAX_OPTS_STR_LEN
      );
    }
    target[i] = param[j];
    i ++;
  }
  target[i] = '\0';
  debug_print("output string: \"%s\"\n", target);
  return i;
}


/*
  Some options are not detected if they are not in the right order. Use the
  ecryptfs_options array to order the given options string. Options not in the
  array are appended at the end.
*/
void
sort_opts_str(Buffer * opts_str_buffer)
{
  size_t i, j, k, n, start;
  char sorted_str[MAX_OPTS_STR_LEN];
  char * * opts_arr;
  char * opts_str = opts_str_buffer->value;

  debug_print("input string: \"%s\"\n", opts_str);
  clean_opts_str(opts_str);

  if (opts_str[0] == '\0')
  {
    debug_print0("nothing to sort\n");
    return;
  }

  /*
    Determine how many options are in the string by counting commas. Replace
    the commas by null characters to enable string operations on separate
    options below.
  */
  i = 0;
  n = 0;
  start = 0;
  while (opts_str[i] != '\0')
  {
    if (opts_str[i] == ',')
    {
      opts_str[i] = '\0';
      if (i > start)
      {
        n ++;
      }
      start = i + 1;
    }
    i++;
  }
  if (i > start)
  {
    n ++;
  }

  debug_print("detected %d options\n", (int)n);

  /*
    Create a temporary array to hold these options. Each array element will
    point to a location in the original options string.
  */
  opts_arr = (char * *) alloca(n * sizeof(char *));
  memset(opts_arr, 0, n * sizeof(char *));

  /*
    Populate the array.
  */
  start = 0;
  i = 0;
  while(n > 0)
  {
    i += arr_maybe_append_parameter(opts_arr, opts_str + start);
    // Find end of current string.
    while((opts_str + start)[0] != '\0')
    {
      start ++;
    }
    // Next string starts after end of current.
    start ++;
    n --;
  }

  // n now holds the number of options in the array.
  n = i;


  start = 0;
  /*
    This is not the most efficient method but it works.
  */
  /*
    Loop through the ordered options and insert them into the ordered options
    string if they are found in the array.
  */
  for (i=0; i<sizeof(ecryptfs_options)/sizeof(char *) && n > 0; i++)
  {
    // Loop through the options array built from the input string.
    for (j=0; j<n; j++)
    {
      // Add a comma separator if this is not the first parameter.
      if (start)
      {
        sorted_str[start++] = ',';
      }
      k = 0;
      while (
        ecryptfs_options[i][k] != '\0' &&
        opts_arr[j][k] != '\0' &&
        ecryptfs_options[i][k] == opts_arr[j][k]
      )
      {
        // Anticipatory copying.
        sorted_str[start + k] = opts_arr[j][k];
        k++;
      }
      if (
        ecryptfs_options[i][k] == '\0' &&
        (opts_arr[j][k] == '\0' || opts_arr[j][k] == '=')
      )
      {
        while (opts_arr[j][k] != '\0')
        {
          sorted_str[start + k] = opts_arr[j][k];
          k++;
        }
        sorted_str[start + k] = '\0';
        start += k;
        // Remove the option from the array.
        opts_arr[j] = opts_arr[n-1];
        n --;
        // The last option is now located at the current index, so reloop.
        j --;
//         debug_print("updated: \"%s\"\n", sorted_str);
      }
      // Remove added comma if no added paramter.
      else if (start)
      {
        start --;
      }
    }
  }

  /*
    Handle remaining options, i.e. the ones not included in the ordered array.
  */
  // Ensure consistent order.
  qsort(opts_arr, n, sizeof(char *), (comparison_fn_t) strcmp);
  for (i=0; i<n; i++)
  {
    j = 0;
    if (start)
    {
      sorted_str[start++] = ',';
    }
    while(opts_arr[i][j] != '\0')
    {
      sorted_str[start++] = opts_arr[i][j++];
    }
    sorted_str[start] = '\0';
    debug_print("updated: \"%s\"\n", sorted_str);
  }

  snprintf( opts_str_buffer->value, opts_str_buffer->size, "%s", sorted_str);
  debug_print("output string: \"%s\"\n", opts_str_buffer->value);
}



struct default_parameter
{
  char * name;
  char * value;
};

// Easier to just duplicate the name than concatenate everything later.
struct default_parameter default_parameters[] =
{
  {
    .name="ecryptfs_passthrough",
    .value="ecryptfs_passthrough"
  },
  {
    .name=FNE_OPTION,
    .value=FNE_OPTION "=" NO_OPTION
  }
};



void
concatenate_mnt_params(
  char * str,
  struct val_node * mnt_params
)
{
  debug_print("input: %s\n", str);
  int i, j;
  char * param;
  i = 0;
  while(str[i] != '\0')
  {
    i++;
  }
  while (mnt_params != NULL)
  {
    if (mnt_params->val != NULL)
    {
      if (i > 0)
      {
        str[i++] = ',';
      }
      j = 0;
      param = (char *) mnt_params->val;
      debug_print("adding %s\n", param);
      while(param[j] != '\0')
      {
        str[i++] = param[j++];
      }
      str[i] = param[j];
    }
    mnt_params = mnt_params->next;
  }
  debug_print("output: %s\n", str);
}



int
concatenate_parameters(
  Buffer * concatenated_opts_str_buffer,
  struct val_node * mnt_params,
  char * opts_str
)
{
  char * concatenated_opts_str = concatenated_opts_str_buffer->value;
  size_t i;
  int length = -1;
  char c, * param, tmp_str[MAX_OPTS_STR_LEN];
  debug_print("input string: \"%s\"\n", concatenated_opts_str);

  while (mnt_params != NULL)
  {
    if (mnt_params->val != NULL)
    {
      i = 0;
      param = (char *) mnt_params->val;
      debug_print("adding %s\n", param);
      do {
        c = param[i];
        tmp_str[i] = c;
        i ++;
      } while(c != '\0' && c != '=');
      if (c == '=')
      {
        tmp_str[i-1] = '\0';
      }
      debug_print("copied %s\n", tmp_str);
      if (! opts_str_contains_option(concatenated_opts_str, tmp_str))
      {
        length = str_maybe_append_parameter(
		   concatenated_opts_str,
                   (char *) mnt_params->val,
                   length
                 );
      }
      /*
        Add the file name encryption option if a file name encryption key is
        passed.
      */
      if (! strcmp(tmp_str, FNEK_SIG_OPTIONS))
      {
        debug_print("adding %s\n", FNE_OPTION);
        length = str_maybe_append_parameter(
		   concatenated_opts_str,
                   FNE_OPTION "=" YES_OPTION,
                   length
                 );
      }
    }
    mnt_params = mnt_params->next;
  }
  debug_print("with mnt_params: \"%s\"\n", concatenated_opts_str);

  // Add missing default parameters.
  for (i=0; i<sizeof(default_parameters)/sizeof(struct default_parameter); i++)
  {
    if (! opts_str_contains_option(concatenated_opts_str, default_parameters[i].name))
    {
      length = str_maybe_append_parameter(
                 concatenated_opts_str,
                 default_parameters[i].value,
                 length
               );
    }
  }
  debug_print("with default_parameters: \"%s\"\n", concatenated_opts_str);

  // Add these last to enable overriding.
  if (opts_str != NULL)
  {
    length = str_maybe_append_parameter(
	       concatenated_opts_str,
               opts_str,
               length
             );
  }

  debug_print("with opts_str: \"%s\"\n", concatenated_opts_str);

  sort_opts_str(concatenated_opts_str_buffer);
  debug_print("output string: \"%s\"\n", concatenated_opts_str);
  return length;
}


/*
 Save options to a file. Options are assumed to be in order.
*/
void
save_parameters(char * opts_str, char * filepath)
{
  char old_opts_str[MAX_OPTS_STR_LEN];
  mode_t old_mode;
  FILE * f;

  old_opts_str[0] = '\0';

  debug_print("saving options to %s\n", filepath);

  // Ensure restrictive permission on the created file just in case.
  drop_privileges();
  old_mode = umask(S_IRWXG | S_IRWXO);
  f = fopen(filepath, "a+b");
  if (f == NULL)
  {
    die("error: failed to open %s for writing (%s)\n", filepath, strerror(errno));
  }
  UNUSED(fgets(old_opts_str, MAX_OPTS_STR_LEN, f));

  debug_print("new options: \"%s\"\n", opts_str);
  debug_print("old options: \"%s\"\n", old_opts_str);
  if (strcmp(opts_str, old_opts_str) != 0)
  {
    UNUSED(ftruncate(fileno(f), 0));
//     fseek(f, 0, SEEK_SET);
    fputs(opts_str, f);
    debug_print0("saved\n");
  }
  fclose(f);
  umask(old_mode);
  resume_privileges();
}



void
load_parameters(Buffer * opts_str, char * filepath)
{
  char tmp_str[MAX_OPTS_STR_LEN];
  tmp_str[0] = '\0';

  if (! access(filepath, R_OK))
  {
    debug_print("reading options from %s\n", filepath);
    FILE * f = fopen(filepath, "rb");
    if (f == NULL)
    {
      die("error: failed to open %s for reading (%s)\n", filepath, strerror(errno));
    }
    UNUSED(fgets(tmp_str, MAX_OPTS_STR_LEN, f));
    fclose(f);
    clean_opts_str(tmp_str);
    debug_print("options: %s\n", tmp_str);
    clean_opts_str(opts_str->value);
    if (str_maybe_append_parameter(tmp_str, opts_str->value, -1) > 0)
    {
      snprintf( opts_str->value, opts_str->size, "%s", tmp_str);
    }
  }
  debug_print("with CLI options: %s\n", opts_str->value);
  sort_opts_str(opts_str);
  debug_print("sorted: %s\n", opts_str->value);
}

/******************************************************************************/









/*******************************************************************************
 Terminal Handling
*******************************************************************************/

// This will hold the state of the terminal at startup.
struct termios initial_term;


// Restore initial terminal settings.
void
restore_terminal(void)
{
  if (tcsetattr(fileno(stdin), TCSANOW, &initial_term))
  {
    warning("warning: failed to restore terminal settings (try \"stty sane\" if there are any problems)\n");
  }
}



void
echo_off()
{
  struct termios tmp_term;
  if (tcgetattr(fileno(stdin), &tmp_term))
  {
    warning("warning: failed to retrieve terminal settings\n");
  }
  tmp_term.c_lflag &= ~ECHO;
  if (tcsetattr(fileno(stdin), TCSANOW, &tmp_term))
  {
    restore_terminal();
    warning("warning: failed to update terminal settings\n");
  }
}



void
echo_on()
{
  struct termios tmp_term;
  if (tcgetattr(fileno(stdin), &tmp_term))
  {
    //die("error: failed to retrieve terminal settings\n");
  }
  tmp_term.c_lflag |= ECHO;
  if (tcsetattr(fileno(stdin), TCSANOW, &tmp_term))
  {
    restore_terminal();
    //die("error: failed to update terminal settings\n");
  }
}



char *
prompt_string(char * prompt, int len, char * value, int disable_echo)
{
  int i, allocated;
  char c;

  allocated = 0;
  disable_echo = disable_echo && isatty(fileno(stdin));

  if (value == NULL)
  {
    value = malloc((len + 1) * sizeof(char));
  }
  if (value == NULL)
  {
    die("error: failed to allocate memory for input string\n");
  }
  if (disable_echo)
  {
    echo_off();
  }
  if (prompt != NULL)
  {
    printf("%s: ", prompt);
  }
  for(i=0; i<len; i++)
  {
    c = getchar();
    if (c == '\r' || c == '\n' || c == EOF)
    {
      break;
    }
    else
    {
      value[i] = c;
    }
  }
  value[i] = '\0';
  if (disable_echo)
  {
    echo_on();
  }
  if (allocated && i < len)
  {
    value = realloc(value, (i+1) * sizeof(char));
  }
  if (value == NULL)
  {
    die("error: failed to resize input string\n");
  }
  return value;
}


int
prompt_string_compatible(char * * val, char * prompt, int echo)
{
  * val = prompt_string(prompt, MAX_INPUT_STR_LEN, NULL, ! echo);
  return 0;
}



/*******************************************************************************
 Signal Handling
*******************************************************************************/

// Handle signals.
void
sigint_handler(int sig)
{
  if (sig == SIGINT)
  {
    restore_terminal();
    exit(EXIT_SUCCESS);
  }
  else
  {
//     perror("unexpected signal: %d\n", sig);
    exit(EXIT_FAILURE);
  }
}






/*******************************************************************************
 Argument Parsing
*******************************************************************************/


const char * argp_program_version = NAME " " VERSION;
// const char *argp_program_bug_address = "<bug-gnu-utils@gnu.org>";

static char doc[] = "Mount and unmount arbitrary directories with eCryptfs. " NAME " will check that the real user has full permissions to both the source and the target directories before proceeding.";

static char args_doc[] = "[<source dir> <target dir> | <source dir> | <target dir>]";

enum
{
  PRINT_CONFIG_PATH_KEY = -1,
} option_keys;

static struct argp_option options[] =
{
  {
    "automount",
    'a',
    NULL,
    0,
    "Automatically mount the directory using saved parameters. The user will be prompted for parameters as usual the first time this is invoked, but subsequent calls will re-use the previously supplied parameters. Parameters are stored in a file in the configuration directory. The name of the file is a SHA512 hash of the source directory's full path.",
    0
  },
  {
    NULL,
    'o',
    "<name>=<value>[,<name>=<value>...]",
    0,
    "Mount options to pass to eCryptfs. See \"man ecryptfs\" for a full list of options. Example: \"-o key=passphrase,ecryptfs_cipher=aes,ecryptfs_key_bytes=16\"",
    0
  },
  {
    "reset",
    'r',
    NULL,
    0,
    "Resets previously saved parameters associated with the given source directory by removing the parameter file.",
    0
  },
  {
    "unmount",
    'u',
     NULL,
     0,
     "Unmount the given directory. If the source directory is given, an attempt will be made to unmount all associated mountpoints.",
     0
  },
  {
    "exclude",
    'x',
    "<name>[,<name>...]",
    0,
    "Exclude the given options from the parameter file when automatically mounting. Use an alias or script to avoid giving this option each time " NAME " is invoked.",
    0
  },
  {
    "config",
    'c',
    "<path>",
    0,
    "Set a custom configuration file path. If <path> begins with \"//\" then it will be take as relative to the source directory.",
    0
  },
  {
    "print-config-path",
     PRINT_CONFIG_PATH_KEY,
     NULL,
     0,
    "Print the configuration file path for the given directory path.",
     0
  },
  {
    NULL,
    0,
    NULL,
    0,
    NULL,
    0
  }
};

struct arguments
{
  char * argv[2];
  int argc, unmount, automount, reset, print_config_path;
  char * mount_options, * excluded_options, * config_path;
};


#define ARGUMENTS(name) \
struct arguments arguments = \
{ \
  .argc = 0, \
  .automount = 0, \
  .reset = 0, \
  .print_config_path = 0, \
  .unmount = 0, \
  .mount_options = NULL, \
  .excluded_options = NULL, \
  .config_path = NULL \
}; \
assert(PRINT_CONFIG_PATH_KEY != ARGP_KEY_ARG); \
assert(PRINT_CONFIG_PATH_KEY != ARGP_KEY_END)

static error_t
parse_opt (int key, char * arg, struct argp_state * state)
{
  struct arguments * arguments = state->input;
  int i;

  switch (key)
  {
  case 'a':
    arguments->automount = 1;
    break;
  case 'o':
    arguments->mount_options = arg;
    break;
  case 'r':
    arguments->reset = 1;
    break;
  case 'u':
    arguments->unmount = 1;
    break;
  case 'x':
    arguments->excluded_options = arg;
    break;
  case 'c':
    arguments->config_path = arg;
    break;

  case PRINT_CONFIG_PATH_KEY:
    arguments->print_config_path = 1;
    break;

  case ARGP_KEY_ARG:
    if (state->arg_num >= 2)
    {
      argp_usage(state);
    }
    // Strip trailing slash
    i = 0;
    while(arg[i] != '\0')
    {
      i ++;
    }
    if (arg[--i] == '/')
    {
      arg[i] = '\0';
    }
    arguments->argv[state->arg_num] = arg;
    (arguments->argc) ++;
    break;

  case ARGP_KEY_END:
    if (state->arg_num < 1)
    {
      argp_usage (state);
    }
    else if (
      arguments->argc == 1 &&
      ! arguments->reset &&
      ! arguments->unmount &&
      ! arguments->print_config_path
    )
    {
      argp_error(state, "additional options required when only one path is given");
    }
    break;

  default:
    return ARGP_ERR_UNKNOWN;
  }
  return 0;
}

static struct argp argp = { .options   = options,
			    .parser    = parse_opt,
			    .args_doc  = args_doc,
			    .doc       = doc } ;

/******************************************************************************/


// Initialize terminal settings, signal handlers, etc.
void
initialize(void)
{
  if (tcgetattr(fileno(stdin), &initial_term))
  {
    //warning("warning: failed to retrieve terminal settings\n");
  }


  if (signal(SIGINT, sigint_handler) == SIG_IGN)
  {
    signal(SIGINT, SIG_IGN);
  }

  if (mlockall(MCL_FUTURE))
  {
    die("error: failed to lock memory\n");
  }

  initialize_uids();
}



void
prompt_parameters(Buffer * opts_str_buffer, Buffer * mnt_params_str)
{
  int rc;
  char tmp_str[MAX_OPTS_STR_LEN] = {0};
  Buffer tmp_str_buffer = {tmp_str,sizeof(tmp_str)};
  struct val_node * mnt_params;
  struct ecryptfs_ctx ctx;
  uint32_t version;
  char * opts_str = opts_str_buffer->value;

  if (ecryptfs_get_version(&version))
  {
    die("error: failed to get eCryptfs version\n");
  }

  mnt_params = malloc(sizeof(struct val_node));
  memset(mnt_params, 0, sizeof(struct val_node));
  memset(&ctx, 0, sizeof(struct ecryptfs_ctx));
  ctx.get_string = &prompt_string_compatible;
  rc = ecryptfs_process_decision_graph(
    &ctx, &mnt_params, version, opts_str, ECRYPTFS_ASK_FOR_ALL_MOUNT_OPTIONS
  );
  if (rc)
  {
    die("error: failed to prompt for options\n");
  }

  concatenate_parameters(&tmp_str_buffer, mnt_params, opts_str);

  if (mnt_params_str != NULL)
  {
    //mnt_params_str[0] = '\0';
    snprintf(opts_str_buffer->value, opts_str_buffer->size, "%s", "ecryptfs_unlink_sigs");
    concatenate_mnt_params(mnt_params_str->value, mnt_params);
    sort_opts_str(mnt_params_str);
    debug_print("mnt_params_str: %s\n", mnt_params_str->value);
  }

  free(mnt_params);
  snprintf(opts_str_buffer->value, opts_str_buffer->size, "%s", tmp_str);
  debug_print("opts_str: %s\n", opts_str);
}




void
mount_ecryptfs(char * source_path, char * target_path, char * opts_str)
{
  debug_print(
    "mount(\"%s\", \"%s\", \"%s\", 0, \"%s\")\n",
    source_path, target_path, FS_TYPE, opts_str
  );
  if (mount(source_path, target_path, FS_TYPE, 0, opts_str))
  {
    die("error: mount failed (%s)\n", strerror(errno));
  }
}






int
main(int argc, char * * argv)
{
  ARGUMENTS(arguments);
  char * source_path = NULL;
  char * target_path = NULL;
  char path[PATH_MAX + 1] = {0};
  char opts_str[MAX_OPTS_STR_LEN] = {0};
  char mnt_params_str[MAX_OPTS_STR_LEN] = {0};
  uid_t uid = getuid();
  gid_t gid = uid;
  Buffer buffer_path           = {path,sizeof(path)};
  Buffer buffer_opts_str       = {opts_str,sizeof(opts_str)};
  Buffer buffer_mnt_params_str = {mnt_params_str,sizeof(mnt_params_str)};
  size_t size;

  resume_privileges();

  if ( setgroups( 1,&gid ) != 0 )
  {
      die ( "error: setgroups() failed" );
  }
  if ( setegid( uid ) != 0 )
  {
    die ( "error: setegid() failed" );
  }

  drop_privileges();

  if (gcry_control(GCRYCTL_INITIALIZATION_FINISHED_P) == 0)
  {
    gcry_check_version (NULL);
    gcry_control (GCRYCTL_INITIALIZATION_FINISHED, 0);
  }

  argp_parse (&argp, argc, argv, 0, 0, &arguments);

  /*
    Place this after argument parsing to prevent "failed to retrieve terminal
    settings" when parsing help output in scripts.
  */
  initialize();

  source_path = arguments.argv[0];
  target_path = arguments.argv[1];

  if (arguments.reset || arguments.print_config_path)
  {
    get_parameter_filepath(&buffer_path, source_path, arguments.config_path);
    if (arguments.print_config_path)
    {
      printf("%s\n", path);
      return EXIT_SUCCESS;
    }
    else
    {
      printf("Removing %s\n", path);
      if (unlink(path))
      {
        die("error: failed to remove %s (%s)\n", path, strerror(errno));
      }
    }
  }

  /*
    Anything after this point requires permissions on the first path.
  */
  ensure_accessible_directory(source_path);
  source_path = realpath(source_path, NULL);

  if (arguments.argc == 1 || arguments.unmount)
  {
    return unmount_simple(source_path);
  }



  /*
    Anything after this point requires permissions on the second path too.
  */
  ensure_accessible_directory(target_path);
  target_path = realpath(target_path, NULL);

  if (is_mountpoint(target_path, 0))
  {
    die("error: %s is already a mountpoint\n", target_path);
  }

  printf("Mounting %s on %s\n", source_path, target_path);

  // The string needs to be mutable for cleaning, so allocate memory.
  if (arguments.excluded_options != NULL)
  {
    size = strlen(arguments.excluded_options) * sizeof(char);

    excluded_options = realloc(excluded_options,size);

    if (excluded_options == NULL)
    {
      die("error: failed to allocate memory\n");
    }
    memset(excluded_options ,'\0', size);
    snprintf(excluded_options, size, "%s", arguments.excluded_options);
    clean_opts_str(excluded_options);
    debug_print("excluded options: \"%s\"\n", excluded_options);
  }




  if (arguments.mount_options != NULL)
  {
    snprintf(buffer_opts_str.value, buffer_opts_str.size, "%s", arguments.mount_options);
  }
  if (arguments.automount)
  {
    get_parameter_filepath(&buffer_path, source_path, arguments.config_path);
    load_parameters(&buffer_opts_str, path);
  }
  prompt_parameters(&buffer_opts_str, &buffer_mnt_params_str);
  mount_ecryptfs(source_path, target_path, mnt_params_str);
  if (arguments.automount)
  {
    printf("Saving to %s\n", path);
    save_parameters(buffer_opts_str.value, path);
  }
  return EXIT_SUCCESS;
}
