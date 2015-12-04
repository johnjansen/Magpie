-- this code should get called with 2 keys
-- KEYS[1] the domain and suffix
-- KEYS[2] the url to enqueue

local enqueues, rejected, over_limit = 0, 0, 0
local domain, page_limit, depth_limit, url, depth, referer, starting_point, batch, org_id = unpack(KEYS)
local seen = 'seen:' .. url
local hash_key = 'url:' .. domain .. '|' .. url

if (batch == "" or batch == nil) then
  batch = redis.call( "incr", "batch_index" )
end

-- check and set a seen flag for the full url
-- if the url has not already been seen, then proceed
-- TODO, add expiration by changing to 
-- SET key value [EX seconds] [PX milliseconds] [NX|XX] -- O(1)
if redis.call( 'setnx', seen, 1 ) == 1 then
  redis.call( 'expire', seen, 1209600 )

  -- check that the url is not in the queue
  if redis.call( 'exists', hash_key ) == 0 then

    local current_count = 0
    if redis.call( 'exists', 'url_count:' .. KEYS[1] ) == 1 then
      current_count = tonumber( redis.call( 'get', 'url_count:' .. KEYS[1] ) )
    end

    if ( current_count < tonumber( page_limit ) and ( tonumber( depth ) + 1 <= tonumber( depth_limit ) ) ) then

      -- keep track of the count of pages for this domain
      redis.call( 'incr', 'url_count:' .. domain )

      -- add the url to the queue for the domain -- O(1)
      redis.call( 'rpush', 'queue:' .. domain, domain .. '|' .. url )

      -- create a hash to hold the actual job data
      redis.call( 'hmset', hash_key, 'domain', domain, 'depth_limit', depth_limit, 'page_limit', page_limit, 'url', url, 'depth', depth, 'job_count', current_count, 'referer', referer, 'starting_point', starting_point, 'batch', batch, 'org_id', org_id, 'attempts', 0 )

      -- add the domain to the list of all domains, only if its not already in there -- O(1)
      if redis.call( 'sadd', 'domains', domain ) == 1 then

        -- check that the domain is not in the list of available domains -- O(1)
        if redis.call( "exists", "available_domain:" .. domain ) == 0 then
          -- its not there ?
          -- add the domain to the available domains queue -- O(1)
          redis.call( "rpush", "available_domains", domain )

          -- add it to the set of all available domains
          -- we only need to do this, so we can tell if the domain 
          -- already exists in the available domains list cheaply -- O(1)
          redis.call( "set", "available_domain:" .. domain, 1 )
        end
      end
      enqueues = enqueues + 1
    else
      over_limit = over_limit + 1
    end
  end
else
  rejected = rejected + 1
end

return { 'enqueues', enqueues, 'seen', rejected, 'over_limit', over_limit, 'batch', batch }
 No newline at end of file
