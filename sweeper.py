# Runs constantly in the background sweeping up
# expired reservations and holds etc
import os
import lockfile
import daemon

from time import sleep

from config import ENV, CONFIG, REDIS, LOG, LOG_STREAM
from lua import stored_procedure

# main event loop
# release all the holds for domains and reservations which have expired

def run():
	LOG.info( "starting katipo sweeper" )
	while True:
		outcome = stored_procedure( 'release_holds' )
		LOG.info( outcome )
		sleep( 1 )

# setup the daemon context
if ENV == "production":
	with daemon.DaemonContext(
		    working_directory = os.getcwd(),
	    	umask=0o002,
		    pidfile = lockfile.FileLock( 'katipo-sweeper.pid' ),
		    files_preserve=[ LOG_STREAM ]
		):
		run()
else:
	run()