// Main Entry Point
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include "rand.h"
#include "logger.h"
#include "test/mta_test.h"

int main() {
    // Seed the random number generator
    srand(time(NULL));
    random_reseed(rand());
    
    // Initialize the logger - LOG_INFO for terminal, full debug in file
    logger_init(LOG_INFO, "activity.log");
    
    // Run the full MtA protocol test
    int result = run_mta_full_test();
    
    // Close the logger
    logger_close();
    
    return result;
}