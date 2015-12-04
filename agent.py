#!/usr/bin/python
import os
import re
import sys
import json
import string
import signal
import hashlib
import random
import threading

import dns.resolver
import requests
import tldextract
import itertools

from time import sleep
from datetime import datetime
from email.utils import parsedate
from urlparse import urlparse, urlunparse, urljoin, urldefrag, urlsplit
from pyquery import PyQuery
from pymongo import MongoClient

from config import ENV, CONFIG, REDIS, LOG, LOG_STREAM
from lua import stored_procedure, stored_procedure_as_dict

SCRAPER_NAME, SCRAPER_VERSION = 'magpy', '1.0.0'
ACCEPTABLE_CONTENT_TYPES = [ "application/xhtml+xml", "text/html" ]
ACCEPTABLE_SCHEMES = [ "http", "https" ]
USER_AGENT =  "Magpie/1.0 (+http://dream-software.com/) Katipo/3.0.0"
BOILERPIPE_REMOVE_TAGS = [
    "a","address","area","aside","audio","base","bdi","bdo","button","canvas","cite","code","col","colgroup","command","data",
    "datagrid","datalist","del","embed","eventsource","figcaption","figure","footer","head","header","hgroup","hr","iframe",
    "img","input","kbd","keygen","label","legend","link","map","menu","meta","meter","nav","noscript","object","optgroup",
    "option","output","param","pre","progress","samp","script","select","source","style","textarea","var","video","wbr"
 ]


def domain( url ):
    '''  extract the second and first level domains from a url
        and return a string which represents a domain name
        as a human would expect
    '''
    d = tldextract.extract( url )
    return "%s.%s" % ( d.domain, d.tld )


def queue( url, org_id=None, batch=None ):
    ''' queue an item into the magpy queue
    '''
    stored_procedure_as_dict( "queue_job", domain( url ), 300, 6, url, 0, "", url, batch, org_id )


def safe_unicode( obj, *args ):
    ''' return the unicode representation of obj
    '''
    try:
        return unicode(obj, *args)
    except UnicodeDecodeError:
        # obj is byte string
        ascii_text = str(obj).encode('string_escape')
        return unicode(ascii_text)


def safe_str(obj):
    ''' return the byte string representation of obj 
    '''
    try:
        return str(obj)
    except UnicodeEncodeError:
        # obj is unicode
        return unicode(obj).encode('unicode_escape')


def _parse_http_datetime(s):
    ''' Parse a date sting in http format, returning a date object
    '''
    return datetime(*parsedate(s)[:6])


def safe( obj ):
    ''' make all the keys and values in a dictionary unicode safe (recursivley)
    '''
    result = {}
    for key, value in obj.items():
        if type(value) == str:
            result[ safe_unicode(key) ] = safe_unicode( value )
        elif type(value) == list:
            result[ safe_unicode(key) ] = [ safe(v) for v in value ]
        elif type(value) == dict:
            result[ safe_unicode(key) ] = safe( value )
        else:
            result[ safe_unicode(key) ] = value
    return result

# ---------------------------------------------------------------
# an agent thread
# ---------------------------------------------------------------
class MagpieAgentThread( threading.Thread ):

    def __init__( self, thread_id ):
        threading.Thread.__init__( self )
        self.thread_id = thread_id
        self.mongo = MongoClient( ).katipo.pages

    def next_job( self ):
        data = stored_procedure_as_dict( "next_job" )
        if len( data ) > 0:
            self.current_job = data
            return True
        else:
            self.current_job = None
            return False

    def process( self ):
        self.discovered_urls = set()
        self.basic_content_type = "text/html"
        self.message_stack = [ "-" * 80 ]

        # resolve the address
        uri = urlparse( self.current_job[ 'url' ] )
        answers = dns.resolver.query( uri.hostname, 'A' )
        for answer in answers:
            self.message_stack.append( "DNS) %s" % answer )

        try:
            self.current_response = requests.get( self.current_job[ 'url' ], stream=True )
            self.basic_content_type = self.current_response.headers[ 'content-type' ].split( ";" )[ 0 ]
        except:
            self.current_response = None
            self.basic_content_type = None

        if self.current_response:
            for r in self.current_response.history:
                self.message_stack.append( "-URL (%s) %s" % ( r.status_code, r.url ) )

            self.message_stack.append( "+URL (%s) %s" % ( self.current_response.status_code, self.current_response.url ) )
            self.message_stack.append( "BASIC CONTENT-TYPE) %s" % self.basic_content_type )
            self.message_stack.append( "CONTENT TYPE) %s" % self.current_response.headers['content-type'] )
            self.message_stack.append( "ENCODING) %s" % self.current_response.encoding )

            if self.basic_content_type in ACCEPTABLE_CONTENT_TYPES:
                # we need to handle the odd, but real case of the mystery <? palantir_blog_list('sidebar') ?> tag
                # tidy_response_text = re.sub( "<\?.*?\?>", "", self.current_response.text )
                tidy_response_text = re.sub( "<\?.*?\?>", "", self.current_response.text )
                tidy_response_text = re.sub( "<!--.*?-->", "", tidy_response_text )

                self.dom = PyQuery( tidy_response_text, parser='html' )

                self.titles = [ safe_str( title.text ) for title in self.dom("title") ]

                for a in self.dom('a'):
                    a = PyQuery(a)
                    new_url = PyQuery(a).attr.href
                    if new_url != None:
                        new_url = urldefrag( urljoin( self.current_response.url, new_url ) )[0]
                        self.discovered_urls.add( new_url )

                self.message_stack.append( "DISCOVERED) %s" % len( self.discovered_urls ) )

                # BOILERPIPE
                for excluded_tag in BOILERPIPE_REMOVE_TAGS:
                    self.dom( excluded_tag ).after( "\n" )
                    self.dom.remove( excluded_tag )

                # remove tags with style="display:none"
                # http://www.microsoft.com/en-us/legal/intellectualproperty/copyright/default.aspx          
                display_none_pattern = re.compile( "display: ?none" )

                for x in self.dom("*"):
                    try:
                        tag = PyQuery(x)
                        if not tag.attr("style") == None:
                            if re.match( display_none_pattern, tag.attr("style") ):
                                tag.remove()
                    except Exception as inst:
                        print type(inst)
                        print inst.args
                        print inst

                self.save()
            else:
                self.message_stack.append( "DISCARDED" )
        else:
            self.message_stack.append( "NO RESPONSE" )

    def save( self ):
        try:
            # if domain( self.current_response.url ) == domain( self.current_job['url'] ):
            scraper_name = SCRAPER_NAME
            if 'scraper_name' in self.current_job:
                scraper_name =  self.current_job[ 'scraper_name' ].lower()

            scraper_version = SCRAPER_VERSION
            if 'scraper_version' in self.current_job:
                scraper_version = self.current_job[ 'scraper_version' ]

            qid_base = "%s:%s:%s" % ( self.current_job[ 'starting_point' ], self.current_job[ 'url' ], scraper_name )

            qid_hash = hashlib.md5()
            qid_hash.update( qid_base )
            qid = qid_hash.hexdigest()

            headers = self.current_response.headers
            scraped_at = datetime.utcnow().strftime( r'%Y-%m-%dT%H:%M:%SZ' )
            last_modified = scraped_at
            if 'date' in headers:
                last_modified = _parse_http_datetime( headers['date'] ).strftime( r'%Y-%m-%dT%H:%M:%SZ' )

            quid_orgid = None
            if 'org_id' in self.current_job:
                quid_orgid = self.current_job[ 'org_id' ]

            alternative_urls = []
            if self.current_response.history != None:
                for x in self.current_response.history:
                    alternative_urls.append( x.url )

            content_type = "text/html"
            if "content-type" in headers:
                content_type = headers['content-type']

            content_type = content_type.split( ";" )[ 0 ]

            url_selection_rule = "(page_count < %s) && (depth <= %s)" % ( self.current_job[ 'page_limit' ], self.current_job[ 'depth_limit' ] )
            
            if len( alternative_urls ) > 0:
                print qid
                
            # sample tokenize
            tokens = []
            for token in re.compile( "\W", re.UNICODE).split( safe_unicode( self.dom.text().lstrip().rstrip() ) ):
                if token.lstrip().rstrip() != '':
                    tokens.append( token )

            # find any docs which already exist with this url
            matches = []
            for d in self.mongo.find( { "meta.data.source_urls" : self.current_response.url } ):
                matches.append( d["_id"] )

            print( "matches for %s\n%s" % ( self.current_response.url, matches ) )

            self.mongo.insert( 
                {
                   u"meta" : {
                       u"data" : {
                           u"qid" : qid,
                           u"qid_base" : qid_base,
                           u"content_encoding" : u"UTF-8",
                           u"content_type" : content_type,
                           u"source_url" : alternative_urls + [ self.current_response.url ], 
                           u"doc_type_name" : u"unstructured/web/WEBPAGE",
                           u"doc_type_version" : u"1.0.0",
                           u"scraper_name" : scraper_name,
                           u"scraper_version" : scraper_version,
                           u"scraped_at" : scraped_at,
                           u"date_publication" : last_modified,
                           u"quid_orgid" : quid_orgid,
                           u"katipo" : {
                               u"starting_url" : self.current_job[ 'starting_point' ],
                               u"last_modified" : last_modified,
                               u"domain" : self.current_job[ 'domain' ]
                           }
                        },
                       u"v" : 2,
                       u"id" : qid
                    },
                   u"raw" : {
                       u"data" : self.current_response.text,
                       u"v" : 2,
                       u"id" : qid
                    },
                   u"structured" : {
                       u"data" : {
                           u"http_headers" : headers,
                           u"page_depth" : self.current_job[ 'depth' ],
                           u"job_count" : self.current_job[ 'job_count' ],
                           u"url_selection_rule" : url_selection_rule,
                           u"meta_tags" : u'',
                           u"body_text" : self.dom.text().lstrip().rstrip(),
                           u"tokens" : tokens
                        },
                       u"v" : 2,
                       u"id" : qid
                    }
                }
            )

        except Exception as inst:
            self.message_stack.append( inst )
            # self.message_stack.append( self.dom.text() )
            print string.join( self.message_stack, "\n" )


    def acknowledge( self ):
        stored_procedure( "acknowledge_job", self.current_job['domain'], self.current_job['url'] )
        for url in self.discovered_urls:
            new_url_scheme = urlsplit( url )[0]
            if domain(url) == domain( self.current_job['url'] ) and new_url_scheme in ACCEPTABLE_SCHEMES:
                self.message_stack.append( "ACCEPT) %s"  % url )
                self.queue( url )
            else:
                self.message_stack.append( "REJECT) %s"  % url )
        self.message_stack.append( "ACK'd) %s" % self.current_job['url'] )

    def fail( self ):
        self.message_stack.append( "FAIL" )
        # self.acknowledge( )
        pass

    def queue( self, url ):
        j, d = self.current_job, ( int( self.current_job['depth'] ) + 1 )
        stored_procedure( "queue_job", j['domain'], j['page_limit'], j['depth_limit'], url, d, j['url'], j['starting_point'], j['batch'], j['org_id'] )


    def run( self ):
        for x in range( 3600 ):
            while self.next_job():
                try:
                    self.process()
                    self.acknowledge( )
                except Exception as inst:
                    print inst
                    self.fail()

                # print string.join( self.message_stack, "\n" )

            sleep( 1 )




seeds = [
    ["http://ironkey.com",2],
    ["http://insiteone.com",614],
    ["http://www.secureworks.com",615],
    ["http://linesider.net",725],
    ["http://www.ubicom.com",866],
    ["http://www.openet.com",1075],
    ["http://bluestripe.com",1084],
    ["http://cleversafe.com",1584],
    ["http://www.plianttechnology.com",1683],
    ["http://netronome.com",1686],
    ["http://www.cpacket.com",1714],
    ["http://www.apprenda.com",1741],
    ["http://www.epocrates.com",1771],
    ["https://www.barracudanetworks.com",1802],
    ["http://dttusa.com",1853],
    ["http://www.firehost.com",1944],
    ["http://venafi.com",2007],
    ["http://clickfree.com",2064],
    ["http://altornetworks.com",2130],
    ["http://www.adometry.com",2132],
    ["http://veracode.com",2224],
    ["http://accertify.com",2237],
    ["http://www.cloudera.com",2312],
    ["http://www.sipera.com",2317],
    ["http://www.adaptivecomputing.com",2498],
    ["http://mobixell.com",2525],
    ["http://www.vidient.com",2536],
    ["http://mementosecurity.com",2579],
    ["http://www.lumeta.com",2603],
    ["http://www.carbonite.com",2624],
    ["http://www.10gen.com",2628],
    ["http://masabi.com",2735],
    ["http://aveksa.com",2791],
    ["http://bungeelabs.com",2799],
    ["http://www.videoiq.com",2869],
    ["http://vssmonitoring.com",2938],
    ["http://www.actiance.com",2988],
    ["http://www.ncircle.com",2990],
    ["http://nimbula.com",3334],
    ["http://www.apriva.com",3410],
    ["http://www.datacastlecorp.com",3417],
    ["http://zimory.com",3431],
    ["http://www.garlik.com",3629],
    ["http://palantir.com",3708],
    ["http://www.cloudmark.com",3711],
    ["http://www.pervacio.com",3743],
    ["http://racemi.com",3908],
    ["http://www.payfone.com",3913],
    ["http://6wind.com",3947],
    ["http://paymate.co.in",3972],
    ["http://aviorcomputing.com",4015],
    ["http://www.flurry.com",4016],
    ["http://www.karmasphere.com",4068],
    ["http://www.basho.com",4143],
    ["http://www.lookout.com",4153],
    ["http://plurality.com",4160],
    ["http://www.rapid7.com",4163],
    ["http://britebill.com",4244],
    ["http://skytap.com",4248],
    ["http://coursehero.com",4264],
    ["http://www.webroot.com",4269],
    ["http://www.prevx.com",4272],
    ["http://coverity.com",4461],
    ["http://www.centrify.com",4487],
    ["http://www.fulcrummicro.com",4514],
    ["http://www.boxtone.com",4526],
    ["http://www.solicore.com",4676],
    ["http://www.symform.com",4679],
    ["http://www.freescale.com",4717],
    ["http://www.panologic.com",4736],
    ["http://www.q1labs.com",4797],
    ["http://www.alientechnology.com",4851],
    ["http://www.bluecava.com",4874],
    ["http://www.soluto.com",4883],
    ["http://smwsolutions.com",5059],
    ["http://opscode.com",5072],
    ["http://www.lifelock.com",5139],
    ["http://www.rainstor.com",5235],
    ["http://cloudkick.com",5398],
    ["http://www.fixmo.com",5400],
    ["http://www.intransa.com",5657],
    ["http://www.wisekey.com",5723],
    ["http://zenoss.com",5865],
    ["http://www.validityinc.com",5886],
    ["http://privacyanalytics.ca",5914],
    ["http://www.clairmail.com",5951],
    ["http://lancope.com",6039],
    ["https://www.trustedid.com",6142],
    ["http://www.lodosoftware.com",6159],
    ["http://www.couchbase.com",6169],
    ["http://redlambda.com",6284],
    ["http://mokafive.com",6285],
    ["http://www.jaspersoft.com",6305],
    ["http://eeye.com",6371],
    ["http://atlantiscomputing.com",6374],
    ["http://www.privasecurity.com",6389],
    ["http://bdna.com",6404],
    ["http://www.lineratesystems.com",6574],
    ["http://immunet.com",6651],
    ["http://credant.com",6666],
    ["http://www.netqin.com",6691],
    ["http://www.egnyte.com",6797],
    ["http://gigaspaces.com",6911],
    ["http://byallaccounts.com",6935],
    ["http://www.safecentral.com",6944],
    ["http://www.mocana.com",7014],
    ["http://www.ncomputing.com",7073],
    ["http://www.guardiananalytics.com",7154],
    ["http://www.damballa.com",7201],
    ["http://www.paloaltonetworks.com",7218],
    ["http://brslabs.com",7233],
    ["http://www.fidelissecurity.com",7243],
    ["http://exegy.com",7301],
    ["http://www.oculislabs.com",7308],
    ["https://www.yousendit.com",7314],
    ["http://www.imprivata.com",7319],
    ["http://www.traitwareid.com",7328],
    ["http://endgamesystems.com",7342],
    ["http://www.triumfant.com",7454],
    ["http://www.infoblox.com",7455],
    ["http://viewfinity.com",7464],
    ["http://xceedium.com",7482],
    ["http://www.zetta.net",7487],
    ["http://appzero.com",7563],
    ["http://www.privaris.com",7662],
    ["http://www.avg.com",7679],
    ["http://www.avgmobilation.com",7681],
    ["http://www.aventurahq.com",7772],
    ["http://vazata.com",7825],
    ["http://recordedfuture.com",7852],
    ["http://www.jumio.com",7956],
    ["http://iovation.com",8004],
    ["http://sensenetworks.com",8061],
    ["http://www.impinj.com",8099],
    ["http://clustrix.com",8144],
    ["http://the41.com",8195],
    ["http://palisadesystems.com",8218],
    ["http://www.paydivvy.com",8313],
    ["http://www.hoyosgroup.com",8329],
    ["http://www.percello.com",8363],
    ["http://www.sailpoint.com",8431],
    ["http://soonr.com",8621],
    ["http://www.vworldc.com",8638],
    ["http://controlscan.com",8735],
    ["http://insightix.com",8744],
    ["http://www.paraccel.com",8882],
    ["http://www.bluecatnetworks.com",8919],
    ["http://moneydesktop.com",8929],
    ["http://www.confidex.net",9009],
    ["http://gigatrust.com",9013],
    ["http://www.chelsio.com",9021],
    ["http://tensilica.com",9027],
    ["http://markmonitor.com",9040],
    ["http://doyenz.com",9083],
    ["http://www.dwavesys.com",9187],
    ["http://iptune.com",9286],
    ["http://www.fon.com",9348],
    ["http://trusteer.com",9353],
    ["http://desktone.com",9486],
    ["http://akorri.com",9535],
    ["http://ntrglobal.com",9540],
    ["http://idvault.com",9587],
    ["http://firetide.com",9641],
    ["http://soleranetworks.com",9675],
    ["http://www.rallydev.com",9738],
    ["http://secure64.com",9787],
    ["http://www.agiliance.com",9788],
    ["http://kaazing.com",9789],
    ["http://www.intelleflex.com",9796],
    ["http://www.okta.com",9814],
    ["http://www.adaptivemobile.com",9816],
    ["http://sendmail.com",9916],
    ["http://www.netwitness.com",9925],
    ["http://www.force10networks.com",9950],
    ["http://www.lemon.com",9963],
    ["http://pentaho.com",10020],
    ["http://3vr.com",10021],
    ["http://splunk.com",10029],
    ["http://skyboxsecurity.com",10089],
    ["http://metricstream.com",10167],
    ["http://www.embrane.com",10204],
    ["http://www.newnettechnologies.com",10217],
    ["http://www.aerohive.com",10409],
    ["http://www.bluesocket.com",10445],
    ["http://www.resilient-networks.com",10541],
    ["http://www.fireid.com",10559],
    ["http://www.exacttarget.com",10602],
    ["http://www.cradlepoint.com",10661],
    ["http://cymtec.com",10676],
    ["http://www.semafone.com",10731],
    ["http://leostream.com",10748],
    ["http://www.globalvelocity.com",10760],
    ["http://www.plumchoice.com",10765],
    ["http://www.untangle.com",10784],
    ["http://www.kalido.com",10854],
    ["http://www.engineyard.com",10893],
    ["http://gosecureauth.com",10927],
    ["http://www.netentsec.com",10964],
    ["http://xiotech.com",11046],
    ["http://www.mformation.com",11101],
    ["http://hytrust.com",11134],
    ["http://www.silvertailsystems.com",11169],
    ["http://zenprise.com",11196],
    ["http://www.b-obvious.com",11202],
    ["http://nominum.com",11254],
    ["http://www.koolspan.com",11255],
    ["http://www.bit9.com",11292],
    ["http://www.alienvault.com",11300],
    ["http://www.imperva.com",11338],
    ["http://messagesystems.com",11497],
    ["http://netsecuretechnologies.com",11533],
    ["http://www.forescout.com",11548],
    ["http://eiqnetworks.com",11568],
    ["http://threatmetrix.com",11634],
    ["http://xirrus.com",11650],
    ["http://www.opsource.net",11652],
    ["https://www.sugarsync.com",11668],
    ["http://secureinfo.com",11687],
    ["http://www.installfree.com",11769],
    ["http://www.boingo.com",11772],
    ["http://www.cenzic.com",11787],
    ["http://www.actifio.com",11815],
    ["http://airtightnetworks.com",11856],
    ["http://returnpath.com",11925],
    ["http://www.cloud.com",11949],
    ["http://gazzang.com",12020],
    ["http://storediq.com",12026],
    ["http://www.mashery.com",12030],
    ["http://proofpoint.com",12093],
    ["http://enterprisedb.com",12161],
    ["http://skyhookwireless.com",12217],
    ["http://www.certesnetworks.com",12271],
    ["http://fireeye.com",12277],
    ["http://www.n-dimension.com",12278],
    ["http://www.ievoreader.com",12337],
    ["http://www.6fusion.com",12355],
    ["http://voltdb.com",12366],
    ["https://gobuck.com",12373],
    ["http://www.quarri.com",12390],
    ["http://www.caringo.com",12407],
    ["http://www.qualys.com",12408],
    ["http://www.layar.com",12410],
    ["http://softlayer.com",12436],
    ["http://liveqos.com",12452],
    ["http://ruckuswireless.com",12522],
    ["http://www.indigoidware.com",12564],
    ["http://www.4access.com",12571],
    ["http://www.seculert.com",12588],
    ["http://acronis.com",12608],
    ["http://main.mchek.com",12658],
    ["http://www.logrhythm.com",12700],
    ["http://www.insidesecure.com",12721],
    ["http://www.vertica.com",12787],
    ["http://nicira.com",12794],
    ["http://bytemobile.com",12867],
    ["http://www.nitrosecurity.com",12893],
    ["http://sandforce.com",12953],
    ["http://www.timesightsystems.com",12992],
    ["http://gigamon.com",13008],
    ["http://www.nutanix.com",13020],
    ["http://www.cloudswitch.com",13062],
    ["http://www.xeround.com",13084],
    ["http://www.acculynk.com",13154],
    ["http://www.breakingpointsystems.com",13278],
    ["http://www.extrahop.com",13306],
    ["https://www.obopay.com",13409],
    ["http://www.symplified.com",13455],
    ["http://www.duosecurity.com",13525],
    ["http://quickheal.com",13619],
    ["http://www.quickoffice.com",13731],
    ["http://nasuni.com",13745],
    ["http://www.voltage.com",13797],
    ["http://idanalytics.com",13805],
    ["http://joyent.com",13850],
    ["http://mudynamics.com",13905],
    ["http://www.mblox.com",13907],
    ["http://www.verafin.com",14041],
    ["http://www.lumension.com",14144],
    ["http://www.locationlabs.com",14174],
    ["http://www.finsphere.com",14205],
    ["http://avast.com/index",14231],
    ["http://www.agilenceinc.com",14248],
    ["http://www.univa.com",14274],
    ["http://www.tagsysrfid.com",14275],
    ["http://www.datameer.com",14287],
    ["http://lumidigm.com",14379],
    ["https://www.explorys.com",14401],
    ["http://www.qihoo.com",14404],
    ["http://yodlee.com",14419],
    ["http://www.pingidentity.com",14476],
    ["http://comviva.com",14482],
    ["http://vkernel.com",14484],
    ["http://www.fring.com",14526],
    ["http://www.tripwire.com",14549],
    ["http://victrio.com",14551],
    ["http://www.mobileiron.com",14744],
    ["http://opendns.com",14798],
    ["http://sensage.com",14847],
    ["http://www.trustid.com",14861],
    ["http://www.virtustream.com",14891],
    ["http://www.milestonesys.com",14996],
    ["http://rightscale.com",15023],
    ["http://www.securekey.com",15062],
    ["http://tropos.com",15083],
    ["http://lavante.com",15089],
    ["http://www.zong.com",15100],
    ["http://www.redsealnetworks.com",15110],
    ["http://www.silverspringnet.com",15170],
    ["http://yottamark.com",15212],
    ["http://panzura.com",15243],
    ["http://www.aryaka.com",15262],
    ["http://securityinnovation.com",15283],
    ["http://www.moonshado.com",15297],
    ["http://perimeterusa.com",15353],
    ["http://nirvanix.com",15383],
    ["http://www.devifi.com",15433],
    ["http://www.bivio.net",15530],
    ["http://clearswift.com",15536],
    ["http://www.box.net",15550],
    ["http://www.getjar.com",15556],
    ["http://www.ironstratus.com",15623],
    ["http://quantenna.com",15644],
    ["http://www.sonavation.com",15659],
    ["http://www.packetmotion.com",15660],
    ["http://www.whitepages.com",15662],
    ["http://www.appcentral.com",15761],
    ["http://saffrontech.com",15762],
    ["http://www.soasta.com",15766],
    ["http://kxen.com",15859],
    ["http://www.bridgewave.com",15954],
    ["http://xterprise.com",16000],
    ["http://www.reflexsystems.com",16041],
    ["http://oversightsystems.com",16176],
    ["http://www.envysion.com",16177],
    ["http://www.squareup.com",16191],
    ["http://dynamicsinc.com",16247],
    ["http://eucalyptus.com",16303],
    ["http://www.xsigo.com",16399],
    ["http://www.armorize.com",16501],
    ["http://www.greensql.com",16528],
    ["http://www.infoglide.com",16745],
    ["http://www.gfi.com",16937],
    ["http://www.intalio.com",17018],
    ["http://www.datamotion.com",17032],
    ["http://www.navajosystems.com",17146],
    ["http://www.perspecsys.com",17315],
    ["http://red-m.com",17343],
    ["http://www.goahead.com",17377],
    ["http://www2.watchdox.com",17461],
    ["http://www.x6868.com",17476],
    ["http://www.sones.de",17563],
    ["http://kaspersky.com",17627],
    ["http://www.quest.com",18042],
    ["http://www.coalfire.com",18660],
    ["http://www.accuvant.com",19726],
    ["http://six3systems.com",19802],
    ["http://www.logicalis.com",20199],
    ["http://www.umonitor.com/uMonitor/index.jsp",20204],
    ["http://www.compushare.com",20522],
    ["http://www.terremark.com",20590],
    ["http://www.beyondtrust.com",20861],
    ["http://www.strands.com",20936],
    ["http://openmarket.com",21204],
    ["http://www.keynotedeviceanywhere.com",21459],
    ["http://www.digitalreasoning.com",21557],
    ["http://www.appsense.com",21661],
    ["http://www.telcred.com",21741],
    ["http://www.courion.com",21862],
    ["http://www.confidenttechnologies.com",21868],
    ["http://www.hotlinkv.com",21902],
    ["http://www.lucidport.com",21922],
    ["http://cyphort.com",22009],
    ["https://www.appdirect.com",22044],
    ["http://www.maas360.com",22160],
    ["http://www.bullguard.com",22168],
    ["http://www.aikosolutions.com",22184],
    ["http://www.bitdefender.com",22188],
    ["http://www.radioip.com",22196],
    ["http://www.appistry.com",22199],
    ["http://www.redbend.com",22201],
    ["http://www.bitzermobile.com",22205],
    ["http://www.caspertech.com",22227],
    ["http://www.compumatica.de",22228],
    ["http://www.redcannon.com",22269],
    ["http://www.authentify.com",22286],
    ["http://www.airscanner.com",22338],
    ["http://www.redcloudsecurity.com",22376],
    ["http://www.globant.com",22526],
    ["http://www.hadapt.com",22540],
    ["http://www.prolexic.com",22622],
    ["http://www.certivox.com",22625],
    ["http://www.rpost.com",22785],
    ["http://www.bigswitch.com",22786],
    ["http://www.verimatrix.com",22814],
    ["http://www.logicworks.net",22876],
    ["http://www.singledigits.com",22899],
    ["http://www.air-watch.com",23209],
    ["http://digitalpersona.com",23236],
    ["http://www.firemon.com",23258],
    ["http://www.lockpath.com",23317],
    ["http://www.21vianet.com",23325],
    ["http://www.zettaset.com",23407],
    ["http://www.appneta.com",23446],
    ["http://www.cloudpassage.com",23447],
    ["http://www.manageiq.com",23633],
    ["http://www.behaviosec.com",23819],
    ["http://www.typesafe.com",23881],
    ["http://www.shavlik.com",23973],
    ["http://www.codenomicon.com",24210],
    ["http://www.cognitivesecurity.cz",24227],
    ["http://www.pivotallabs.com",24289],
    ["http://www.bluestacks.com",24310],
    ["http://www.ioactive.com",24328],
    ["http://www.cleardata.net",24374],
    ["http://mobilisafe.com",24389],
    ["http://www.codeguard.com",24527],
    ["http://www.authentic8.com",24658],
    ["http://www.acens.com",24702],
    ["http://www.bromium.com",25098],
    ["http://www.mandiant.com",25199],
    ["http://www.stone-ware.com",25242],
    ["http://vellosystems.com",25304],
    ["http://www.enstratus.com",25377],
    ["http://www.wdi.ca",25454],
    ["http://www.emue.com",25483],
    ["http://www.voicecommercegroup.com",25495],
    ["http://www.point.se",25598],
    ["http://www.intrinsic.co.uk",25611],
    ["http://www.naturalsecurity.com",25692],
    ["http://copperegg.com",25768],
    ["http://www.azulstar.com",25812],
    ["http://www.appi.com.br",25915],
    ["http://www.tgatepayments.com",25920],
    ["http://www.tagattitude.fr",26033],
    ["http://www.mindmatics.com",26163],
    ["http://www.pittpatt.com",26297],
    ["https://www.whitehatsec.com",26329],
    ["http://www.workbooks.com",26339],
    ["http://www.morpho.com",26388],
    ["http://www.ernet.com.br",26483],
    ["http://www.cloudnumbers.com",26712],
    ["http://www.solsticemedical.com",27041],
    ["http://www.tllod.com",27223],
    ["http://www.academica.fi",27349],
    ["http://www.nexusna.com",27420],
    ["http://www.9starinc.com",27504],
    ["http://www.ciphercloud.com",27533],
    ["http://www.evigilo.net",27535],
    ["http://www.athoc.com",27537],
    ["http://www.aforesolutions.com",27574],
    ["http://www.personalcapital.com",27585],
    ["http://www.hosteurope.de",27678],
    ["http://www.centrixsoftware.com",27722],
    ["http://www.viableware.com",27766],
    ["http://www.curbsys.com",27802],
    ["http://trustpipe.com",27828],
    ["http://www.opdemand.com",28621],
    ["http://www.cipherpointsoftware.com",28636],
    ["http://www.datum.net",28767],
    ["http://www.bi2technologies.com",28876],
    ["http://www.alertenterprise.com",28903],
    ["http://www.sensysnetworks.com",29163],
    ["http://neotechnology.com",29797],
    ["http://www.vilabs.com",29822],
    ["http://www.processunity.com",29824],
    ["http://www.omni-id.com",29858],
    ["http://www.mtel.com.br",29987],
    ["http://www.watchdata.com",30058],
    ["https://www.bancvue.com",30069],
    ["http://www.nexperts.com",30083],
    ["http://www.cryptomathic.com",30084],
    ["http://www.dimoco.at",30087],
    ["http://www.digitalvirgo.com",30138],
    ["http://www.spectranetix.com",30185],
    ["http://www.fss.co.in",30212],
    ["http://www.gfg-group.com",30302],
    ["http://www.eastnets.com",30306],
    ["http://www.cloudprime.net",30320],
    ["http://www.xtium.com",30322],
    ["http://www.integratedbiometrics.com",30323],
    ["http://www.wts.com",30456],
    ["http://www.aepnetworks.com",30644],
    ["http://www.vidder.com",30672],
    ["http://www.mavenlink.com",30728],
    ["http://www.perfectaddress.com",30736],
    ["http://www.transecq.com",31321],
    ["http://www.crealogix.com",31323],
    ["http://www.n-able.com",31332],
    ["http://mobilous.com",32266],
    ["http://pindropsecurity.com",33262],
    ["http://www.checkmarx.com",34220],
    ["http://www.nginx.com",34232],
    ["http://www.isightpartners.com",34384],
    ["http://www.sharefile.com",34408],
    ["http://www.mobile2win.com",34607],
    ["http://docassist.us",34658],
    ["http://www.wolterskluwerfs.com",34736],
    ["http://yunteq.com",34968],
    ["http://tinfoilsecurity.com",35373],
    ["http://www.flexdiscovery.com",36135],
    ["http://www.memorylink.com",36151],
    ["http://www.traffixsystems.com",36196],
    ["http://www.bt-systems.com",36257],
    ["http://www.easy2comply.com",36303],
    ["http://www.medrio.com",36317],
    ["http://www.agari.com",36341],
    ["http://www.wavionnetworks.com",36626],
    ["http://boundary.com",37378],
    ["http://www.antvision.cn",37541],
    ["http://www.colasoft.com.cn",37544],
    ["http://www.anxunsoft.com",37556],
    ["http://www.chiefkey.com.cn",37564],
    ["http://www.bjrun.com",37570],
    ["http://www.realwee.com",37575],
    ["http://actioning.com.cn",37792],
    ["http://www.exactearth.com",37924],
    ["http://www.servicemesh.com",37954],
    ["http://ilangoc.com",38009],
    ["http://www.routdata.com",38059],
    ["http://www.finfosoft.com",38083],
    ["http://www.aotain.com",38112],
    ["http://www.runtrend.com.cn",38115],
    ["http://www.fibridge.com",38161],
    ["http://www.skyeyes.cc",38171],
    ["http://www.bellsent.com",38176],
    ["http://www.d-ear.com",38179],
    ["http://www.adhand.cn",38181],
    ["http://www.lyx-solutions.com",38182],
    ["http://www.zmcloud.com",38188],
    ["http://www.nsfocus.com",38192],
    ["http://www.redneurons.com",38216],
    ["http://www.prg-tech.com.cn",38243],
    ["http://www.xahhrj.com",38244],
    ["http://www.boanying.com",38253],
    ["http://www.tylsz.com",38281],
    ["http://www.s-ec.com",38285],
    ["http://www.ragile.com",38320],
    ["http://www.betasoft.com.cn",38351],
    ["http://www.seentech.com.cn",38358],
    ["http://www.victory-idea.com",38411],
    ["http://www.xplus.com",38418],
    ["http://www.maxit-tech.com.cn",38420],
    ["http://www.xm-my.com.cn",38423],
    ["http://www.ismetasoft.com",38425],
    ["http://www.jump.net.cn",38653],
    ["http://www.scalingdata.com",39538],
    ["http://www.janya.com",39547],
    ["http://www.bis2.net",39564],
    ["http://www.phocassoftware.com",39566],
    ["http://www.visualanalytics.com",39609],
    ["http://www.nextiernetworks.com",39612],
    ["http://innovativequery.com",39627],
    ["http://www.baynetsystems.com",39640],
    ["http://www.tenable.com",39645],
    ["http://www.intensityanalytics.com",39646],
    ["http://www.scalebase.com",39652],
    ["http://www.searchridge.com",39688],
    ["http://www.ai-one.com",39727],
    ["http://www.mitratech.com",39899],
    ["http://pikewerks.com",40052],
    ["http://www.192business.com",40105],
    ["http://www.oneneck.com",40451],
    ["http://bonetonecom.com",40724],
    ["http://www.lightcyber.com",41030],
    ["http://www.peersec.com",41158],
    ["http://cynapspro.com",41167],
    ["http://infowatch.com",41169],
    ["http://www.whispersystems.org",41729],
    ["http://www.argus-systems.com",41754],
    ["http://www.knownsec.com",41897],
    ["http://www.saoatech.com",41899],
    ["http://www.wiz.cn",41950],
    ["http://www.blackmagicdesign.com",42102],
    ["http://www.bluesprig.com",45573],
    ["http://www.css.co.cr",45689],
    ["http://www.tageos.com",45880],
    ["http://www.cyber-ark.com",46038],
    ["http://www.enomaly.com",46068],
    ["http://www.suntel.lk",46181],
    ["http://www.mobidia.com",46803],
    ["http://anchorfree.com",46924],
    ["http://www.getbridge.com",47070],
    ["http://www.parlms.com",47259],
    ["http://www.stopthehacker.com",47918],
    ["http://www.expand.com",48244],
    ["http://www.mykonossoftware.com",48348],
    ["http://www.identropy.com",48455],
    ["http://www.actatek.com",48491],
    ["http://www.lgscout.com",48593],
    ["http://www.terraechos.com",48669],
    ["http://www.distil.it",48677],
    ["http://www.blueridgenetworks.com",48798],
    ["http://v3sys.com",48818],
    ["http://www.blackstratus.com",48843],
    ["http://www.porticor.com",49040],
    ["http://www.crowdstrike.com",49200],
    ["http://www.vaultive.com",49229],
    ["http://itadsecurity.com",49285],
    ["http://www.loginconsultants.com",49289],
    ["http://www.globesherpa.com",49334],
    ["http://www.etronika.lt",49423],
    ["http://www.idt911.com",49431],
    ["http://www.jwaala.com",49432],
    ["http://www.sandstone.com.au",49439],
    ["http://www.appassure.com",49482],
    ["http://www.pbmit.com",49490],
    ["http://hbgary.com",49491],
    ["https://cloudant.com",49597],
    ["https://account.ecachemobile.com",49614],
    ["http://www.rsignia.com",49627],
    ["http://www.jamcracker.com",49640],
    ["http://www.cloudlock.com",49663],
    ["http://www.cohesiveft.com",49668],
    ["http://mozy.com",49693],
    ["http://openstack.org",49711],
    ["http://www.picloud.com",49723],
    ["http://www.sendthisfile.com",49724],
    ["http://gryphn.co",49850],
    ["http://www.ipghoster.com",49870],
    ["http://www.clearstorydata.com",49934],
    ["http://nextcloud.co",53564],
    ["https://adeptcloud.com",53566],
    ["http://www.nextgensupport.com",53612],
    ["http://www.veriteqcorp.com",53640],
    ["http://eyeverify.com",53646],
    ["http://www.aegisidentity.com",53671],
    ["http://www.authotecq.com",53698],
    ["http://shapesecurity.com",53725],
    ["https://rightsignature.com",53870],
    ["http://www.syncplicity.com",53873],
    ["http://www.kaavo.com",53900],
    ["http://www.asperasoft.com",53907],
    ["http://www.accelops.com",53923],
    ["http://www.mezeo.com",53926],
    ["http://www.cloudsoftcorp.com",53937],
    ["http://www.ddn.com",53938],
    ["http://www.galetechnologies.com",53941],
    ["http://www.trewidmcloud.com",53978],
    ["http://www.appriver.com",53979],
    ["http://www.anycloudplus.com",54073],
    ["http://becloud.se",54074],
    ["http://www.bitcloud.com.au",54077],
    ["http://www.cloud9technology.com",54083],
    ["http://www.cloud49.com",54091],
    ["http://microcloudsolutions.com",54098],
    ["http://www.mainstcloud.com",54099],
    ["http://www.intercloud.fr",54100],
    ["http://www.iamcloud.com",54103],
    ["http://www.eco4cloud.com",54110],
    ["http://www.cloudyn.com",54112],
    ["http://icoresoftware.com",54114],
    ["http://www.carinatek.com",54214],
    ["http://www.cloudmeter.com",54245],
    ["http://www.flintmo.com",54271],
    ["http://www.circadence.com",54297],
    ["http://www.efortresses.com",54349],
    ["http://www.oneid.com",54389],
    ["http://www.avalanwireless.com",54413],
    ["http://jelastic.com",54452],
    ["http://www.voxmobile.com",54622],
    ["http://www.intrinsic-id.com",54714],
    ["http://www.ask-rfid.com",54715],
    ["http://www.evidencepix.com",54730],
    ["http://www.appthority.com",54801],
    ["http://www.bradfordnetworks.com",54852],
    ["http://www.xintec.com",54862],
    ["http://www.cynapse.com",54935],
    ["http://www.scalify.com",54957],
    ["http://www.netclarity.net",55184],
    ["http://www.copperfasten.com/html/our_products/overview_001.htm",55822],
    ["http://www.harborcloud.com",55965],
    ["http://www.nevisnetworks.com",56025],
    ["http://www.rancardmobility.com",56057],
    ["http://www.tierpoint.com",56219],
    ["http://norse-corp.com",56234],
    ["http://www.mercurypay.com",56259],
    ["http://www.telesign.com",56282],
    ["http://www.drgsf.com",56293],
    ["http://www.anuesystems.com",56324],
    ["http://www.networkinstruments.com",56396],
    ["http://phishme.com",56522],
    ["http://www.landesk.com",56525],
    ["http://www.idesia-biometrics.com",56661],
    ["http://iconnectivity.com",56681],
    ["http://www.sanbolic.com",56854],
    ["http://www.crossmatch.com",56920],
    ["http://www.l-com.com",56939],
    ["http://www.qmarkets.net",57193],
    ["http://www.elinia.com",57280],
    ["http://www.smarsh.com",57314],
    ["http://atyati.com",57321],
    ["http://mobilespaces.com",57346],
    ["http://www.sensometrix.ch",57375],
    ["http://perceivesolutions.com",57384],
    ["http://www.neurotechnology.com",57462],
    ["http://www.sensiblevision.com",57477],
    ["http://www.cognitec-systems.de",57535],
    ["http://www.agnitio-corp.com",57559],
    ["http://www.skydox.com",57634],
    ["http://www.zscaler.com",57696],
    ["http://www.certirx.com",57944],
    ["http://www.dome9.com",57954],
    ["http://www.gravitant.com",58005],
    ["http://www.aspectlp.com",58177],
    ["http://i7networks.in",58290],
    ["http://payleap.com",58357],
    ["http://www.skytechnologies.com",58360],
    ["http://www.v-key.com",58366],
    ["http://www.vocality.com",58405],
    ["http://siliciumsecurity.com",58540],
    ["http://www.techmahindra.com",58581],
    ["https://www.phonefactor.com",58686],
    ["http://www.zimperium.com",58922],
    ["http://www.altusbilisim.com",58951],
    ["http://www.opentechsystems.com",59025],
    ["http://invested.in",59129],
    ["http://www.skycure.com",59437],
    ["http://www.bitsighttech.com",59522],
    ["http://www.criticalwatch.com",59524],
    ["http://www.ipssecurity.com.au",59532],
    ["http://www.passwordbank.com",59548],
    ["http://netauthority.com",59581],
    ["http://www.redjack.com",59585],
    ["http://www.totaldefense.com",59597],
    ["http://www.troubadourltd.com",59618],
    ["http://www.ubercrypt.com",59619],
    ["http://www.cyberoam.com",59622],
    ["http://www.vormetric.com",59633],
    ["http://www.wombatsecurity.com",59634],
    ["http://www.dosarrest.com",59635],
    ["http://www.matasano.com",59636],
    ["https://www.appsecconsulting.com",59637],
    ["http://www.leafsr.com",59638],
    ["http://www.threatgrid.com",59639],
    ["http://www.elitecore.com",59730],
    ["http://www.logictrends.com",59766],
    ["http://ipsnetworks.com",59772],
    ["http://www.lumenate.com",59777],
    ["http://www.anidirect.com",59780],
    ["http://www.isheriff.com",59788],
    ["http://www.vcider.com",59842],
    ["http://www.raizlabs.com",59864],
    ["http://www.wwpass.com",59865],
    ["http://www.dialogs.de",59968]
]
for item in seeds:
    queue( item[0] )
# ---------------------------------------------------------------
# worker thread pool
# ---------------------------------------------------------------
for i in range( 100 ):
    t = MagpieAgentThread( i )
    t.start()