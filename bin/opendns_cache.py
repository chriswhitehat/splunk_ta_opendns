#!/usr/bin/env python

import itertools, json, datetime, sys, StringIO, csv, urllib
from urllib2 import Request, urlopen, HTTPError


def getMalicious(domains, attempts=0):
    
    jsonEnc = json.JSONEncoder()
    headers = {'Authorization': 'Bearer %s'}

    try:
        request = Request('https://sgraph.api.opendns.com/domains/categorization/?showLabels', data=jsonEnc.encode(domains), headers=headers)
        
        response_body = urlopen(request).read()
        response = json.loads(response_body)
    
        return response
        
    except(HTTPError):
        if attempts > 0:
            return getMalicious(domains, attempts=attempts - 1)
        else:
            print domains
            return
        

def pullScores(domain):

    jsonEnc = JSONEncoder()
    headers = {'Authorization': 'Bearer %s'}
    
    request = Request('https://sgraph.api.opendns.com/security/name/%s.json' % domain, headers=headers)
    
    response_body = urlopen(request).read()
    
    return json.loads(response_body)


def queryOpenDNS(domains):

    queryResults = {}

    # Loop through domains 1000 at a time pulling the malicious result and categories from OpenDNS.
    for domainGroup in itertools.izip_longest(*(iter(set(domains)),) * 1000):
        malicious = getMalicious([x for x in domainGroup if x if x not in queryResults], 3)

        for domain, verdict in malicious.iteritems():
            if domain not in queryResults:
                queryResults[domain] = verdict
                queryResults[domain]['domain'] = domain
                queryResults[domain]['update_time'] = datetime.datetime.today().isoformat()

            scores = pullScores(domain)

            queryResults[domain].update(scores)

            for attribute in ['geodiversity', 'geodiversity_normalized', 'tld_geodiversity']:
                if attribute in queryResults[domain]:
                    del(queryResults[domain][attribute])

            for attribute in ['security_categories', 'content_categories']: 
                if attribute in queryResults[domain] and queryResults[domain][attribute]:
                    queryResults[domain][attribute] = ';'.join(queryResults[domain][attribute])
                else:
                    queryResults[domain][attribute] = '-'

            if 'status' in queryResults[domain]:
                statusMap = {-1: 'Malicious', 0: 'Unknown', 1: 'Benign'}
                queryResults[domain]['status'] = statusMap[queryResults[domain]['status']]

    return queryResults


# Tees output to a logfile for debugging
class Logger:
    def __init__(self, filename, buf = None):
        self.log = open(filename, 'w')
        self.buf = buf

    def flush(self):
        self.log.flush()

        if self.buf is not None:
            self.buf.flush()

    def write(self, message):
        self.log.write(message)
        self.log.flush()
        
        if self.buf is not None:
            self.buf.write(message)
            self.buf.flush()


# Tees input as it is being read, also logging it to a file
class Reader:
    def __init__(self, buf, filename = None):
        self.buf = buf
        if filename is not None:
            self.log = open(filename, 'w')
        else:
            self.log = None

    def __iter__(self):
        return self

    def next(self):
        return self.readline()

    def readline(self):
        line = self.buf.readline()

        if not line:
            raise StopIteration

        # Log to a file if one is present
        if self.log is not None:
            self.log.write(line)
            self.log.flush()

        # Return to the caller
        return line





def read_input(buf, has_header = True):
    """Read the input from the given buffer (or stdin if no buffer)
    is supplied. An optional header may be present as well"""

    # Use stdin if there is no supplied buffer
    if buf is None:
        buf = sys.stdin

    # Attempt to read a header if necessary
    header = {}
    if has_header:
        # Until we get a blank line, read "attr:val" lines, 
        # setting the values in 'header'
        last_attr = None
        while True:
            line = buf.readline()

            # remove lastcharacter (which is a newline)
            line = line[:-1] 

            # When we encounter a newline, we are done with the header
            if len(line) == 0:
                break

            colon = line.find(':')

            # If we can't find a colon, then it might be that we are
            # on a new line, and it belongs to the previous attribute
            if colon < 0:
                if last_attr:
                    header[last_attr] = header[last_attr] + '\n' + urllib.unquote(line)
                else:
                    continue

            # extract it and set value in settings
            last_attr = attr = line[:colon]
            val  = urllib.unquote(line[colon+1:])
            header[attr] = val

    return buf, header


def generateEvents(queryResults):
    headers = ['update_time',
                'domain',
                'found',
                'status',
                'content_categories',
                'security_categories',
                'attack',
                'threat_type',
                'fastflux',
                'rip_score',
                'asn_score',
                'dga_score',
                'geoscore',
                'prefix_score',
                'securerank2',
                'entropy',
                'perplexity',
                'popularity',
                'ks_test',
                'pagerank']

    writer = csv.DictWriter(sys.stdout, headers)

    writer.writeheader()
    for result in queryResults.values():
        writer.writerow(result)



def main(argv):
    stdin_wrapper = Reader(sys.stdin)
    buf, settings = read_input(stdin_wrapper, has_header = True)
    events = csv.DictReader(buf)
    
    domains = set()

    for event in events:
        # For each event, we read in the raw event data
        raw = StringIO.StringIO(event["_raw"])

        domains.add(raw)    
        
    queryResults = queryOpenDNS(domains)

    generateEvents(queryResults)



if __name__ == "__main__":
    try: 
        main(sys.argv)
    except Exception:
        import traceback
        traceback.print_exc(file=sys.stdout)

