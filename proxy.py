import socket
import select
import thread
import re
import logging
import logging.config
import getopt
import sys

VERSION		  = 'Proxy/0.0'
HTTP_VERSION  = 'HTTP/1.1'
BUFF_SIZE	  = 32764
TIMEOUT		  = 50000

# Configure Logging
log = None

# configurations
conf = { 'routes'	:	[],
		 'address'	:	'localhost',
		 'port'		:	8080,
		 'app_conf'	:	'proxy.conf',
		 'log_conf'	:	'proxy.log.conf'}

class Route(object):
	def __init__(self,pattern):
		self.pattern = re.compile(pattern)
		self.txtpattern = pattern
	
	def isMatch(self,path):
		return self.pattern.match(path) != None

	def socket_read_write(self,client,target):
		socks = {client.fileno(): client,
				 target.fileno(): target}

		poller = select.poll()
		READ_ONLY = select.POLLIN | select.POLLPRI | select.POLLHUP | select.POLLERR
		poller.register(client, READ_ONLY)
		poller.register(target, READ_ONLY)
		while 1:
			events = poller.poll(TIMEOUT)
			for fd, flag in events:
				if flag & (select.POLLHUP | select.POLLERR):
					log.debug("Connection Interrupted")
					break
				else:
					sock = socks[fd]
					data = sock.recv(BUFF_SIZE)
					if len(data) == 0:
						return
					if sock is client:
						target.send(data)
					else:
						client.send(data)
			if len(events) == 0:
				log.debug("Timeout reached")
				return

class ProxyRoute(Route):
	def __init__(self,pattern,host,port,trim=False):
		super(ProxyRoute,self).__init__(pattern)
		self.port = int(port)
		self.host = host
		self.trim = trim
	
	def __str__(self):
		return 'PROXY: '+str(self.txtpattern)+' '+self.host+':'+str(self.port)

	def _connect(self):
		addresses = socket.getaddrinfo(self.host, self.port)
		target = None
		for (family, _, _, _, address) in addresses:
			log.debug("Connecting to: "+str(address))
			try:
				target = socket.socket(family)
				target.connect(address)
				break
			except:
				pass
		else:
			log.error("Failed to connect: "+self.host+":"+str(self.port))
			target = None
		return target

	def action(self,client,method,path,protocol,tail):
		target = self._connect()

		# strip the prefix from the path
		if self.trim:
			path = path[path.find('/',1):]
		
		message = '%s %s %s\r\n'%(method, path, protocol)+tail
		#print message
		target.send(message)
		self.socket_read_write(client,target)
		target.close()

class HTTPRoute(Route):
	def __init__(self,pattern,webroot):
		super(HTTPRoute,self).__init__(pattern)
		self.webroot = webroot 

	def __str__(self):
		return 'HTTP : '+self.txtpattern+' '+self.webroot

	def action(self,connection,method,path,protocol,tail):
		raise NotImplementedError("HTTPRoute.action")

class ConnectionHandler(object):
	def __init__(self, connection):
		(client,_) = connection

		try:
			method, path, protocol, tail = self.get_base_header(client)
			matches = filter(lambda x: x.isMatch(path),conf['routes'])

			if len(matches) == 0:
				log.error("No matches")
				return
		
			print matches[0]
			matches[0].action(client,method,path,protocol,tail)
		finally:
			client.close()
			log.debug("Connection Closed")

	def get_base_header(self,client):
		client_buffer = ''
		end = -1
		while end < 0:
			client_buffer += client.recv(BUFF_SIZE)
			end = client_buffer.find('\n')

		(method,path,protocol) = (client_buffer[:end+1]).split()
		return (method,path,protocol,client_buffer[end+1:])

def parse_configuration( filename ):
	import ConfigParser
	f = open(filename)
	c = ConfigParser.ConfigParser()
	c.readfp(f)
	f.close()

	routes = []
	for section in c.sections():
		keys = {}
		for (x,y) in c.items(section):
			keys[x] = y
		
		if keys['type'] == 'proxy':
			if 'trim' not in keys:
				keys['trim'] = False
			routes.append(ProxyRoute(keys['expr'],keys['host'],keys['port'],keys['trim']))
		if keys['type'] == 'host':
			routes.append(HTTPRoute(keys['expr'],keys['root']))
	return routes
	

def start_server(host='0.0.0.0', port=8080):
	socket_type = socket.AF_INET
	server		= socket.socket(socket_type)
	server.bind((host, port))
	log.info("Serving on %s:%d."%(host, port))
	server.listen(0)
	try:
		while 1:
			client = server.accept()
			thread.start_new_thread(ConnectionHandler, (client,))
	except Exception, e:
		log.info("Exception: "+str(e))
	finally:
		server.close()

def usage():
	print 'usage'

def parse_arguments((optlist,args)):
	global conf, log
	options = { '-a' : 'address'	,
				'-p' : 'port'		,
				'-c' : 'app_conf'	,
				'-l' : 'log_conf'	,
				'-d' : 'debug'		}

	for (opt,arg) in optlist:
		conf[options[opt]] = arg

	logging.config.fileConfig(conf['log_conf'])
	log = logging.getLogger('Proxy')
	log.setLevel(logging.INFO)

	# debug configuration
	if conf.has_key('debug'):
		log.setLevel(logging.DEBUG)

	# routes
	conf['routes'] = parse_configuration(conf['app_conf'])
	map( lambda x: log.debug(x), conf['routes'])

if __name__ == '__main__':
	try:
		parse_arguments(getopt.getopt(sys.argv[1:], 'a:p:c:l:d'))
	except getopt.GetoptError as err:
		print str(err)
		usage()
		sys.exit(1)
	
	start_server()
