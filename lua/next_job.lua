local holds, reservations = 0, 0

-- get the next available domain from the list
local domain = redis.call( 'lpop', 'available_domains' )

if domain then
	-- remove the domain from the available list
	redis.call( "del", "available_domain:"..domain )

	-- add a hold for the domain
	redis.call( 'sadd', 'holds', domain )

	-- make sure that the hold expires when it should
	redis.call( 'setex', 'hold:' .. domain, 5, 1 )

	holds = holds + 1

	-- grab the next job off the queue for the domain
	local job = redis.call( 'lpop', 'queue:' .. domain )

	if job then

		-- get the actual job data from its hash
		local hash_key = 'url:' .. job
		local job_data = redis.call( 'hgetall', hash_key )
		redis.call( 'hincrby', hash_key, 'attempts', 1 )

		-- add the job to the reservations set
		redis.call( 'sadd', 'reservations', job )

		-- set a timeout for the reservation, i.e. how long the worker has before we revoke it
		redis.call( 'setex', 'reservation:'..job, 120, 1 )

		-- keep track of the total current reservations for the domain
		redis.call( 'incr', 'current_domain_reservations:' .. domain )

		reservations = reservations + 1

		-- return the job and some stats
		return { 'holds', holds, 'reservations', reservations, job_data }
	end
end

-- there were no domains or jobs available
-- just return stats
return { 'holds', holds, 'reservations', reservations, nil }