--- acknowledge the given job
local domain, url = unpack( KEYS )
local reservations_deleted, job_details_deleted = 0, 0
local job_key = domain .. '|' .. url
local hash_key = 'url:' .. job_key

-- remove the reservation
reservations_deleted = redis.call( 'srem', 'reservations', job_key )

-- keep track of the total current reservations for the domain
redis.call( 'decr', 'current_domain_reservations:' .. domain )

-- remove the hash for the domain | url pair
job_details_deleted = redis.call( 'del', hash_key )

return { 'reservations_deleted', reservations_deleted, 'job_details_deleted', job_details_deleted }