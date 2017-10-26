#!/bin/python

import sys
import difflib
import re
import os
import csv
import netaddr
import json
import requests
from feeds import feeds
import config

re_ipcidr = (r'^(([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.)'
             '{3}([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])'
             '((/([0-9]|[1-2][0-9]|3[0-2]){0,2})?)')


def download_file(url, filename):
    """
    :param url: URL of file to download
    :param filename: Filename to write the result object to
    :return:
    """
    r = requests.get(url, stream=True, proxies=config.proxies, verify=config.verifySSL)

    with open(filename, 'wb') as fd:
        for chunk in r.iter_content(1024):
            fd.write(chunk)


class RepDB(list):
    def __init__(self):
        super(RepDB, self).__init__()
        self.entries = []

    def add(self, ip):

        if not re.match(re_ipcidr, ip):
            # How did we get here?
            raise Exception(ValueError, "IP %s is not valid" % ip)

        for i in netaddr.IPNetwork(ip):
            self.entries.append(
                {'ip': i})

    def __count__(self):
        """ Returns count of RepDB entries.

        :return:
        """
        return len(self)

    def __iter__(self):
        """ Custom iterator to use entries instead of the object itself
        :return:
        """
        for e in self.entries:
            # print("Entry: {}".format(e))
            yield e

    def __getitem__(self, item):
        """
        :param int item: Integer index of entry item
        :return: Returns selected item slice
        """
        return self.entries[item]

    def __len__(self):
        return len(self.entries)

    def search(self, ip, top=False):

        results = []
        for entry in self:
            if netaddr.IPNetwork(ip).network in netaddr.IPNetwork(entry['ip']):
                if top:
                    results.append(entry)
                    return results
                results.append(entry)
        # list of results
        return results


class BuildCompare:

    def __init__(self, old, new):
        """
        :param list old: List of 'old' lines to compare to new
        :param list new: List of 'new' lines to compare to old
        :return:
        """

        # Compares best when items are sorted
        old.sort()
        new.sort()
        self.add = []
        self.delete = []
        self.equal = []
        s = difflib.SequenceMatcher(None, old, new)
        for tag, i1, i2, j1, j2 in s.get_opcodes():

            # This helps to understand what we're adding and removing. From difflib documentation
            if config.debug:
                print("%7s a[%d:%d] (%s) b[%d:%d] (%s)" % (tag, i1, i2, old[i1:i2], j1, j2, new[j1:j2]))

            # replace takes out items from list A[i1:i2] and adds from list B[j1:j2]
            if tag == 'replace':
                for i in old[i1:i2]:
                    self.delete.append(i)
                for i in new[j1:j2]:
                    self.add.append(i)
            # delete records are not seen in list b. Remove items from list a[i1:i2]
            elif tag == 'delete':
                for i in old[i1:i2]:
                    self.delete.append(i)
            # insert records are not seen in list a. Add items from list b.
            elif tag == 'insert':
                for i in new[j1:j2]:
                    self.add.append(i)
            elif tag == 'equal':
                for i in old[i1:i2]:
                    self.equal.append(i)

    def add(self):
        """ Returns a list of items to add

        :return: Returns a list of items to ADD
        """
        return self.add

    def delete(self):
        """ Returns a list of items to delete

        :return: Returns a list of items to delete
        """
        return self.delete

    def equal(self):
        """ Returns a list of unchanged items

        :return:Returns a list of unchanged items
        """
        return self.equal


def emergingthreat(url, data):
    repdb = RepDB()
    re_section = r'^#(.*)'
    iptype = ''
    for line in data:
        typematch = re.match(re_section, line)
        ipmatch = re.match(re_ipcidr, line)
        if typematch:
            # Get rid of extra whitespace. Match group '1'.
            iptype = ' '.join(typematch.group(1).split())
        elif ipmatch:
            # Spamhaus are too big and too annoying.  They break RepDB later when we parse out CIDR
            if iptype != 'Spamhaus DROP Nets':
                ip = ipmatch.group(0)
                repdb.add(ip)
    return repdb


def ipfeed(url, description, data):
    """ Builds reputation DB based on one IP per line
    Only imports valid IPs

    Format is one IP per line with no further details. EG:

    1.2.3.4
    3.4.5.2
    9.9.9.9

    :param string url: URL for generic IP feed to include in DB entry
    :param string description: Description of DB entry
    :param list data: List of lines to parse
    :return: RepDB: A RepDB() instance containing threat information
    """
    repdb = RepDB()
    for line in data:
        ipmatch = re.match(re_ipcidr, line)
        if ipmatch:
            ip = ipmatch.group(0)
            repdb.add(ip)
    return repdb


def sslblacklist(url, data):
    """ Parse SSLBlacklist CSV entries
    Format is:
    ip,port,description


    :param string url: URL for generic IP feed to include in DB entry
    :param list data: List of lines to parse
    :return:RepDB: A RepDB() instance containing threat information
    """
    repdb = RepDB()
    reader = csv.reader(data, delimiter=',')

    for line in reader:
        ipmatch = re.match(re_ipcidr, line[0])
        if ipmatch:
            ip = ipmatch.group(0)
            repdb.add(ip)
    return repdb


def autoshun(url, data):
    """ Parse Autoshun CSV entries
    Format is:
    ip,port,description


    :param string url: URL for generic IP feed to include in DB entry
    :param list data: List of lines to parse
    :return: RepDB: A RepDB() instance containing threat information
    """
    repdb = RepDB()
    reader = csv.reader(data, delimiter=',')

    for line in reader:
        ipmatch = re.match(re_ipcidr, line[0])
        if ipmatch:
            ip = ipmatch.group(0)
            repdb.add(ip, url, line[2])
    return repdb


def alienvault(url, data):
    """ Parse alienvault reputation db entries. These are pretty complicated so a simpler parser is used.

    Format is:
    #<IP>#<PRIORITY>#<CONFIDENCE>#<Description>#<COUNTRY>#<CITY>#<LATITUDE>,<LONGITUDE>#??

    :param string url: URL for generic IP feed to include in DB entry
    :param list data: List of lines to parse
    :return: RepDB: A RepDB() instance containing threat information
    """
    repdb = RepDB()

    def check_reputation_format(ln):
        r = re.compile("^[+-]?\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}#\d\d?#\d\d?#.*#.*#.*#.*#.*$")
        if ln != "":
            if not r.match(ln):
                return False
        return True

    for d in data:
        if check_reputation_format(d) and d != "":
            if d[0] == "-":
                continue
            if d[0] == "+":
                d = d[1:]
            fs = d.split("#")
            if len(fs) == 8:
                # Check parameters
                # Some variables are unsed; Alienvault includes its own repDB entry for maxmind lookups
                # but we prefer to do it ourselves
                ip = fs[0]
                rel = int(fs[1])
                prio = int(fs[2])
                desc = fs[3]

                repdb.add(ip)
    return repdb


def build_db(dbtype, url, description, db_add, db_del, db_equal):

    old_filename = '.cache/%s.txt' % dbtype
    new_filename = '.cache/%s.txt.compare_add' % dbtype

    if not os.path.exists('.cache'):
        os.makedirs('.cache')

    try:
        download_file(url, new_filename)
    except requests.ConnectionError as e:
        print('Connection interrupted while downloading: {0} - {1}'.format(url, e))
        # If there's a problem just keep going.
        return

    except IOError:
        e = sys.exc_info()[0]
        print('Error downloading: {0} - {1}'.format(url, e))
        raise IOError('Something happened {0}'.format(e))

    if os.path.isfile(new_filename):
        with open(new_filename, 'r') as fn:
            compare_add = fn.read().splitlines()
    else:
        compare_add = []

    if os.path.isfile(old_filename):
        with open(old_filename, 'r') as fn:
            compare_delete = fn.read().splitlines()
    else:
        compare_delete = []
    print('Comparing {0} downloaded to {1} cached lines'.format(len(compare_add), len(compare_delete)))

    compare = BuildCompare(compare_delete, compare_add)
    compare_delete = compare.delete
    compare_add = compare.add
    compare_equal = compare.equal
    print("{0} new, {1} deleted, {2} unchanged lines".format(len(compare_add), len(compare_delete),
                                                             len(compare_equal)))

    if dbtype == 'alienvault':
        db_del.append(alienvault(url, compare_delete))
        db_add.append(alienvault(url, compare_add))
        db_equal.append(alienvault(url, compare_equal))
    elif dbtype == 'emerging-block':
        db_del.append(emergingthreat(url, compare_delete))
        db_add.append(emergingthreat(url, compare_add))
        db_equal.append(emergingthreat(url, compare_equal))

    elif dbtype == 'ssl-blacklist':
        db_del.append(sslblacklist(url, compare_delete))
        db_add.append(sslblacklist(url, compare_add))
        db_equal.append(sslblacklist(url, compare_equal))
    elif dbtype == 'ssl-blacklist':
        db_del.append(autoshun(url, compare_delete))
        db_add.append(autoshun(url, compare_add))
        db_equal.append(autoshun(url, compare_equal))
    else:
        db_del.append(ipfeed(url, description, compare_delete))
        db_add.append(ipfeed(url, description, compare_add))
        db_equal.append(ipfeed(url, description, compare_equal))

    if not os.path.exists('.cache'):
        os.makedirs('.cache')

    if os.path.isfile(old_filename):
        try:
            os.remove(old_filename)
        except (IOError, OSError) as e:
            raise OSError('Could not remove file: {0}- {1}'.format(old_filename, e))
    try:
        os.rename(new_filename, old_filename)
    except (IOError, OSError) as e:
        raise OSError('Could not rename {0} to {1} - {2}'.format(new_filename, old_filename, e))


# def printjson(action, entry):
#     """ Prints a JSON-formatted object for an action and entry
#
#     :param string action:  add remove or delete
#     :param entry: One RepDB entry to print JSON output for
#     :return: null
#     """
#     outjson = json.dumps({
#         action: {
#             'ip': str(entry['ip']),
#             'source': entry['source'],
#             'description': entry['description'],
#             'priority': entry['priority'],
#             'reputation': entry['reputation'],
#             'city': entry['city'],
#             'country': entry['country'],
#             'latitude': entry['latitude'],
#             'longitude': entry['longitude'],
#         }
#     })
#     print(outjson)


def buildcef(action, entry):
    return entry['ip']


def start(feedlist, db_add, db_del, db_equal):

    for i in feedlist:
        print("Processing {0} from {1}".format(i['description'], i['url']))
        build_db(i['type'], i['url'], i['description'], db_add, db_del, db_equal)


def process(db_add, db_del, db_equal):

    count_add = 0
    count_del = 0
    count_equal = 0
    fd = open(".cache/IPRepDB", "w")
    for line in db_add:
        for i in line:
            count_add += 1
            msg = buildcef('add', i)
            # print(msg)
            try:
                fd.write(str(msg) + '\n')
            except Exception, e:
                print str(e)
                pass
            # if config.debug:
            #     printjson('add', i)
            # f.write("%s %s\n" % (i['latitude'], i['longitude']))
    fd.close()



# # Only run code if invoked directly: This allows a user to import modules without having to run through everything
# # if __name__ == "__main__":
# _db_add = []
# _db_del = []
# _db_equal = []
#
# start(feeds, _db_add, _db_del, _db_equal)
# process(_db_add, _db_del, _db_equal)
