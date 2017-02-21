#!/usr/bin/python

import pprint
import getopt
import sys
import signal
import yaml
import socket
from dnslib import *

def usage (progName):
	""" Print the program's usage and then sys.exit() """
	print ("Usage: %s -c <conf. file> -l <listening address> -p <listening port> -r <remote resolver IP> " % progName)
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
	ipMap = {}
	dnsReply = ""
	forwarder = ""
	socket = ""

	def __init__ (self, ip, confMap):
		print ("[*]\tThe DNS resolver for this session is %s" % ip)
		sys.stdout.flush ()
		self.forwarder = ip
		self.ipMap = confMap

		try:
			self.socket = socket.socket (socket.AF_INET, socket.SOCK_DGRAM)

		except socket.error:
			print ("[!]\tFailed to create forwarding socket")
			sys.stdout.flush ()
			sys.exit (1)

	def run (self, rawRequest):
		dnsRequest = DNSRecord.parse (rawRequest)
		splitRequest = dnsRequest.get_q()._qname.label
		match = 0

		# For each IP contained in the YAML conf. file
		for ip in self.ipMap.keys ():

			# For each domain
			for domain in self.ipMap[ip]:
				splitDomain = domain.split ('.')

				if len (splitRequest) < len (splitDomain):
					break

				# Compare each request FQDN element with current config. domain from end to beginning
				for i in range (-1, -(len (splitRequest)) - 1, -1):

					# If the current FQDN matches the current config. domain
					if ((splitDomain[i] == splitRequest[i]) or (not splitDomain[i] and i ** 2 == len (splitDomain) ** 2 )):
						match = 1

					else:
						match = 0
						break
						
				if match:
					break
			
			if match:
				dnsAnswer = ip
				break

		if match:
			print ("[*]\tResolving %s" % '.'.join (splitRequest))
			sys.stdout.flush ()
			self.resolve ('.'.join (splitRequest), dnsAnswer, dnsRequest)

		else:
			print ("[*]\tForwarding %s to external resolver" % '.'.join (splitRequest))
			sys.stdout.flush ()
			self.forward (rawRequest)

		return self.dnsReply

	def resolve (self, question, answer, request):
		self.dnsReply = request.reply ()
		self.dnsReply.add_answer (RR (question, rdata = A (answer)))

	def forward (self, request):

		try:
			self.socket.sendto (request, (self.forwarder, 53))
			d = self.socket.recvfrom (1024)

			data = d[0]
			addr = d[1]
	
			self.dnsReply = DNSRecord.parse (data)

		except socket.error:
			print ("[!]\tFailed to forward DNS request")
			sys.exit (1)

	def close (self):
		self.socket.close ()



class dnsListener ():
	""" DNS server definition """
	ip = "127.0.0.1"
	port = "53"
	socket = ""

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
				sys.exit (1)

			data = d[0]
			addr = d[1]

			# Continue if there's no data in the packet
			if (not data):
				continue

			# Forward the received data to the resolver
			reply = resolver.run (data)

			try:
				self.socket.sendto (reply.pack(), addr)

			except:
				print ("[!]\tFailed to reply to DNS query")
				sys.stdout.flush ()
				sys.exit (1)

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
