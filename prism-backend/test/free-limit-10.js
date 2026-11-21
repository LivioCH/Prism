// Import this FIRST in a test that needs the old Free limit: ES imports run before the importing
// file's own statements, so the variable has to be set by a module that loads before ../src/config.js.
process.env.FREE_DAILY_SCAN_LIMIT = '10';
