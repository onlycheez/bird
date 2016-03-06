/*
 *  BIRD -- Windows logging
 *
 *  Can be freely distributed and used under the terms of the GNU GPL.
 */

#include <stdio.h>
#include <time.h>
#include <windows.h>

#include "win-log.h"
#include "win-util.h"

/**
 * Logging under windows.
 *
 * When running on Windows/Cygwin, the code calling winapi cannot use BIRD's
 * common logger because it includes Unix system headers which collides with
 * WindowS/Cygwin system headers.
 */

#define DATETIME_FMT "%Y-%m-%d %H:%M:%S"
#define DATETIME_LENGTH 32
static char DATETIME_BUFFER[DATETIME_LENGTH];
static FILE *log_file = NULL;

static const char* _current_formatted_datetime(void)
{
  time_t t = time(NULL);
  struct tm *tm = localtime(&t);
  strftime(DATETIME_BUFFER, DATETIME_LENGTH, DATETIME_FMT, tm);
  return DATETIME_BUFFER;
}

/**
 * Retrieves string representation of error code. If error code isn't provided
 * (equals 0) it uses thread's last error code.
 */
static char* _winapi_error_string(DWORD retval)
{
  DWORD code = (retval == 0) ? GetLastError() : retval;
  LPSTR buffer = NULL;

  if (code == 0)
  {
    return strdup("No error message");
  }

  size_t size = FormatMessageA(
    FORMAT_MESSAGE_ALLOCATE_BUFFER |
    FORMAT_MESSAGE_FROM_SYSTEM |
    FORMAT_MESSAGE_IGNORE_INSERTS,
    NULL,
    code,
    MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
    (LPSTR) &buffer,
    0,
    NULL);

  char *msg = wmalloc(size + 1);
  memset(msg, 0, size + 1);
  memcpy(msg, buffer, size);

  LocalFree(buffer);

  return msg;
}

/**
 * Obtains error message for given retval and logs it together with
 * API function name using WLOG_ERROR log level.
 */
void win_log_api_error(const char *fc_name, DWORD retval)
{
  char *msg = _winapi_error_string(retval);
  wlog(WLOG_ERROR, "%s failed (0x%x). %s", fc_name, retval, msg);
  free(msg);
}

/**
 * Logs into file with specified log level.
 */
void wlog(enum Wlog_level level, const char *format, ...)
{
  static const char *LOG_FILE_LOCATION = "C:\\bird\\win.log";
  static FILE *log_file = NULL;
  if (!log_file)
  {
    log_file = fopen(LOG_FILE_LOCATION, "a");
  }

  fprintf(log_file, "%s ", _current_formatted_datetime());

  switch (level)
  {
    case WLOG_ERROR:
      fprintf(log_file, "<ERROR> ");
      break;
    case WLOG_WARN:
      fprintf(log_file, "<WARN> ");
      break;
    case WLOG_INFO:
      fprintf(log_file, "<INFO> ");
      break;
    case WLOG_DEBUG:
      fprintf(log_file, "<DEBUG> ");
      break;
    default:
      fprintf(log_file, "<???> ");
  }

  va_list ap;
  va_start(ap, format);
  vfprintf(log_file, format, ap);
  va_end(ap);

  fprintf(log_file, "\r\n");
  fflush(log_file);
}
