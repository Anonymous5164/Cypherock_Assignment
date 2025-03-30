/**
 * Simple logger for the MtA protocol implementation
 */

 #ifndef __LOGGER_H__
 #define __LOGGER_H__
 
 #include <stdio.h>
 
 // Log levels
 typedef enum {
     LOG_NONE = 0,   // No logging
     LOG_ERROR,      // Only errors
     LOG_INFO,       // General information
     LOG_DEBUG       // Detailed debug information
 } log_level_t;
 
 /**
  * Initialize the logger
  * 
  * @param level The logging level to use
  * @param logfile Path to the log file, NULL for no file logging
  * @return 0 on success, error code on failure
  */
 int logger_init(log_level_t level, const char *logfile);
 
 /**
  * Close the logger and free resources
  */
 void logger_close(void);
 
 /**
  * Set the current logging level
  * 
  * @param level The new logging level
  */
 void logger_set_level(log_level_t level);
 
 /**
  * Log a message with the specified level
  * 
  * @param level The logging level of this message
  * @param format The printf-style format string
  * @param ... Additional arguments for the format string
  */
 void log_message(log_level_t level, const char *format, ...);
 
 // Convenience macros
 #define LOG_ERROR(...) log_message(LOG_ERROR, __VA_ARGS__)
 #define LOG_INFO(...) log_message(LOG_INFO, __VA_ARGS__)
 #define LOG_DEBUG(...) log_message(LOG_DEBUG, __VA_ARGS__)
 
 #endif /* __LOGGER_H__ */