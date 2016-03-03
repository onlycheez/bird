
#ifndef _BIRD_WIN_LOG_H_
#define _BIRD_WIN_LOG_H_

enum Wlog_level
{
  WLOG_ERROR = 0,
  WLOG_WARN,
  WLOG_INFO,
  WLOG_DEBUG
};

void wlog(enum Wlog_level level, const char *format, ...);
void log_winapi_error(const char *fc_name, DWORD retval);

#endif
