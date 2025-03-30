/*
  Implementation of the logger system
 */

 #include <stdio.h>
 #include <stdlib.h>
 #include <stdarg.h>
 #include <string.h>
 #include "logger.h"
 
 // Global logger state
 static struct {
     log_level_t level;
     FILE *logfile;
     int logfile_open;
 } logger = {
     .level = LOG_NONE,
     .logfile = NULL,
     .logfile_open = 0
 };
 
 int logger_init(log_level_t level, const char *logfile) {
     logger.level = level;
     
     // Close previous logfile if open
     if (logger.logfile_open && logger.logfile != NULL) {
         fclose(logger.logfile);
         logger.logfile = NULL;
         logger.logfile_open = 0;
     }
     
     // Open new logfile if specified
     if (logfile != NULL) {
         logger.logfile = fopen(logfile, "w");
         if (logger.logfile == NULL) {
             fprintf(stderr, "Error: Failed to open log file '%s'\n", logfile);
             return -1;
         }
         logger.logfile_open = 1;
     }
     
     return 0;
 }
 
 void logger_close(void) {
     if (logger.logfile_open && logger.logfile != NULL) {
         fclose(logger.logfile);
         logger.logfile = NULL;
         logger.logfile_open = 0;
     }
 }
 
 void logger_set_level(log_level_t level) {
     logger.level = level;
 }
 
 void log_message(log_level_t level, const char *format, ...) {
     // Skip if log level is too low
     if (level < logger.level) {
         return;
     }
     
     va_list args;
     
     // Get the prefix based on log level
     const char *prefix;
     switch (level) {
         case LOG_ERROR:
             prefix = "[ERROR] ";
             break;
         case LOG_INFO:
             prefix = "[INFO] ";
             break;
         case LOG_DEBUG:
             prefix = "[DEBUG] ";
             break;
         default:
             prefix = "";
             break;
     }
     
     // Write to stderr for ERROR level
     if (level == LOG_ERROR) {
         va_start(args, format);
         fprintf(stderr, "%s", prefix);
         vfprintf(stderr, format, args);
         fprintf(stderr, "\n");
         va_end(args);
     }
     
     // Write to stdout for INFO level
     if (level == LOG_INFO && logger.level <= LOG_INFO) {
         va_start(args, format);
         printf("%s", prefix);
         vprintf(format, args);
         printf("\n");
         va_end(args);
     }
     
     // Write to logfile if open
     if (logger.logfile_open && logger.logfile != NULL) {
         va_start(args, format);
         fprintf(logger.logfile, "%s", prefix);
         vfprintf(logger.logfile, format, args);
         fprintf(logger.logfile, "\n");
         va_end(args);
     }
 }