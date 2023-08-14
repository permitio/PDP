# 3 is a magic Gunicorn error code signaling that the application should exit
GUNICORN_EXIT_APP = 3

# History:
#   1 - Didn't really exist, we pretend that was v1
#   2 - Implicitly assumed by the v2 backend for old PDPs that don't report a version
#   3 - Basic data-callback mechanism fully supported
#   4 - Pings and additional data-callback values, for full resilience feature to work
API_VERSION = 4
