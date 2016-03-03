
#include <stdio.h>
#include <windows.h>

#include "win-log.h"
#include "win-util.h"

static FILE *log_file = NULL;

static char* get_error_msg(DWORD retval)
{
  DWORD code = (retval == 0) ? GetLastError() : retval;
  LPSTR buffer = NULL;
  size_t size = 0;

  if (code == 0)
  {
    size = 16;
    buffer = "No error message";
  }
  else
  {
    size = FormatMessageA(
      FORMAT_MESSAGE_ALLOCATE_BUFFER |
      FORMAT_MESSAGE_FROM_SYSTEM |
      FORMAT_MESSAGE_IGNORE_INSERTS,
      NULL,
      code,
      MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
      (LPSTR) &buffer,
      0,
      NULL);
  }

  char *msg = wmalloc(size + 1);
  memset(msg, 0, size + 1);
  memcpy(msg, buffer, size);

  LocalFree(buffer);

  return msg;
}

void log_winapi_error(const char *fc_name, DWORD retval)
{
  char *msg = get_error_msg(retval);
  wlog(WLOG_ERROR, "%s failed (0x%x). %s", fc_name, retval, msg);
  free(msg);
}

void wlog(enum Wlog_level level, const char *format, ...)
{
  static const char *LOG_FILE_LOCATION = "C:\\bird\\win.log";
  static FILE *log_file = NULL;
  if (!log_file)
  {
    log_file = fopen(LOG_FILE_LOCATION, "a");
  }

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
