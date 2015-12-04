import os
import yaml
import redis
import logging


if os.environ.get( 'katipo' ):
	ENV = os.environ.get( 'katipo' )
else:
	ENV = 'development'

CONFIG = yaml.load( open("config.yml", 'r') )[ ENV ]

REDIS = redis.StrictRedis( **CONFIG[ 'redis' ] )

LOG = logging.getLogger()
LOG.setLevel(logging.DEBUG)
log_file = "log/sweeper.%s.log" % ENV 
file_handler = logging.FileHandler( log_file )
LOG.addHandler( file_handler )

LOG_STREAM = file_handler.stream