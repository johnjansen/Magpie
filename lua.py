import os.path
import glob

from config import LOG, REDIS

# load all the lua scripts into redis
# storing keys and sha's
LOG.info( "loading stored procedures" )

for script in glob.glob( os.path.join( 'lua', '*.lua' ) ):
	try:
		script_code = open( script, "r" ).read()
		script_name, script_type = os.path.splitext( script )
		script_name = os.path.basename( script_name )
		REDIS.set( 'lua_function:%s' % script_name, REDIS.register_script( script_code ).sha )
		LOG.debug( 'loaded %s' % script_name )
	except Exception as err:
		LOG.debug( '%s failed to load, with error %s' % (script_name, str(err)) )

def pairs_to_dictionary( array ):
	result = {}
	if len( array ) % 2 != 0:
		response = array.pop()
		if type( response ) == list:
			while len( response ) > 0:
				key = response.pop(0)
				value = response.pop(0)
				result[ key ] = value
	if len( array ) > 0:
		for key, value in pairs_to_dictionary([array]).iteritems():
			if value > 0:
				print "%s => %s\n" % ( key, value )
	return result

# call a named lua function stored in redis
# def stored_procedure( script_name, **kwargs ):
def stored_procedure( script_name, *args ):
	try:
		sha = REDIS.get( 'lua_function:%s' % script_name )
		return REDIS.evalsha( sha, len(args), *args )
	except Exception as err:
		LOG.debug( '%s failed to run stored procedure, with error %s and args %s' % (script_name, str(err), str(args)) )
		return str(err)

def stored_procedure_as_dict( script_name, *args ):
	d = stored_procedure( script_name, *args )
	return pairs_to_dictionary( d )