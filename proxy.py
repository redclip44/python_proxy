import sys, os, socket, signal, importlib
import argparse
from OpenSSL import SSL

buf_len = 8192
in_sock = None
out_sock = None
child_pid = -1

class StaticProxy(object):
	# listen_on = None
	# listen_ssl = None
	# listen_ca_cert = None
	# listen_cert = None
	# listen_key = None
	# proxy_ssl = None
	# proxy_to = None
	
	def __init__(self, *args, **kwargs):
		for k,v in kwargs.iteritems():
			exec("self.%s=%s" % (k, repr(v)))
		print vars(self)
		self.listen()

	def listen(self):
		if type(self.listen_on) == tuple:
			s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
		elif type(self.listen_on) == str:
			s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
		if self.listen_ssl:
			listen_context = SSL.Context(SSL.SSLv23_METHOD)
			if self.listen_cert:
				listen_context.use_certificate_file(os.path.abspath(self.listen_cert))
			else:
				print "No CA cert given although listening mode SSL requested"
				exit(1)
			if self.listen_key:
				listen_context.use_privatekey_file(os.path.abspath(self.listen_key))
			else:
				print "No server cert given although listening mode SSL requested"
				exit(1)
			if self.listen_ca_cert:
				listen_context.load_client_ca(os.path.abspath(self.listen_ca_cert))
			else:
				print "No server key given although listening mode SSL requested"
				exit(1)
			s = SSL.Connection(listen_context, s)
			s.set_accept_state()
		s.bind(self.listen_on)
		s.listen(10)
		print "Start listening on %s" % str(self.listen_on)
		while True:
			self.serve(s)
	
	def serve(self, s):
		clientsock, addr = self.accept(s)
		forward_sock = self.init_forwarding()
		if forward_sock and clientsock:
			child_pid1 = os.fork()
			if child_pid1 == 0:
				signal.signal(signal.SIGTERM, self.do_close)
				child_pid2 = os.fork()
				child_pid = child_pid2
				if child_pid2 == 0:
					print "second end connection successful with " + str(self.proxy_to)
					in_sock = forward_sock
					out_sock = clientsock
					self.handle_client(fr=forward_sock, to=clientsock, prnt=int(os.getenv("LOG_SCANNER_OUTPUT", 0)))
				else:
					print "first end connection successful with client " + str(addr)
					in_sock = clientsock
					out_sock = forward_sock
					self.handle_client(fr=clientsock, to=forward_sock, prnt=int(os.getenv("LOG_SCANNER_INPUT", 0)))
			else:
				os.waitpid(-1, os.WNOHANG) 
		else:
			clientsock = None
			forward_sock = None

	def accept(self, s):
		clientsock, addr = s.accept()
		if self.listen_ssl:
			try:
				clientsock.do_handshake()
			except:
				clientsock = None
		return clientsock, addr

	def init_forwarding(self):
		if type(self.proxy_to) == tuple:
			forward_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
		elif type(self.proxy_to) == str:
			forward_sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
		if self.proxy_ssl:
			proxy_context = SSL.Context(SSL.SSLv23_METHOD)
			forward_sock = SSL.Connection(proxy_context, forward_sock)
			forward_sock.connect(self.proxy_to)
			forward_sock.set_connect_state()
			forward_sock.do_handshake()
		else:
			forward_sock.connect(self.proxy_to)
		return forward_sock

	def handle_client(self, fr=None, to=None, prnt=False, child=False):
		while True:
			try:
				data=fr.recv(buf_len)
			except Exception as e:
				self.do_close()
			if prnt == 1:
				print data
			try:
				length = to.send(data)
			except Exception as e:
				self.do_close()

	def do_close(self, *args):
		def _close_sockets(socks):
			for sock in socks:
				try:
					if sock.__class__.__name__ == "_socketobject":
						sock.shutdown(socket.SHUT_RDWR)
					else:
						sock.shutdown()
					sock.close()
				except:
					pass
		_close_sockets([in_sock, out_sock])
		print "Client disconnected"
		if child_pid > 0:
			os.kill(child_pid, signal.SIGTERM)
			os.waitpid(child_pid, 0)
		elif child_pid == 0:
			os.kill(os.getppid(), signal.SIGTERM)
		sys.exit(0)

class ReverseProxy(object):
	def __init__(self, *args, **kwargs):
		for k,v in kwargs.iteritems():
			exec("self.%s=%s" % (k, repr(v)))
		if not self.proxy_module:
			print "Please use --proxy-module to give a module containing a class named ProxyHandler"
			sys.exit(1)
		try:
			path, filename = os.path.split(self.proxy_module)
			sys.path.insert(0, path)
		except:
			filename = self.proxy_module
		self.mod_proxy = __import__(filename.split(".py")[0])
		self.listen()

	def do_close(self, *args):
		def _close_sockets(socks):
			for sock in socks:
				try:
					if sock.__class__.__name__ == "_socketobject":
						sock.shutdown(socket.SHUT_RDWR)
					else:
						sock.shutdown()
					sock.close()
				except:
					pass
		_close_sockets([in_sock, out_sock])
		print "Client disconnected"
		if child_pid > 0:
			os.kill(child_pid, signal.SIGTERM)
			os.waitpid(child_pid, 0)
		elif child_pid == 0:
			os.kill(os.getppid(), signal.SIGTERM)
		sys.exit(0)


	def listen(self):
		if type(self.listen_on) == tuple:
			s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
		elif type(self.listen_on) == str:
			s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
		if self.listen_ssl:
			listen_context = SSL.Context(SSL.SSLv23_METHOD)
			if self.listen_cert:
				listen_context.use_certificate_file(os.path.abspath(self.listen_cert))
			else:
				print "No CA cert given although listening mode SSL requested"
				exit(1)
			if self.listen_key:
				listen_context.use_privatekey_file(os.path.abspath(self.listen_key))
			else:
				print "No server cert given although listening mode SSL requested"
				exit(1)
			if self.listen_ca_cert:
				listen_context.load_client_ca(os.path.abspath(self.listen_ca_cert))
			else:
				print "No server key given although listening mode SSL requested"
				exit(1)
			s = SSL.Connection(listen_context, s)
			s.set_accept_state()
		s.bind(self.listen_on)
		s.listen(10)
		print "Start listening on %s" % str(self.listen_on)
		while True:
			self.serve(s)
	
	def serve(self, s):
		clientsock, addr = self.accept(s)
		forward_sock = self.init_forwarding()
		if forward_sock and clientsock:
			child_pid1 = os.fork()
			if child_pid1 == 0:
				signal.signal(signal.SIGTERM, self.do_close)
				child_pid2 = os.fork()
				child_pid = child_pid2
				if child_pid2 == 0:
					print "second end connection successful with " + str(self.proxy_to)
					in_sock = forward_sock
					out_sock = clientsock
					self.handle_client(fr=forward_sock, to=clientsock, prnt=int(os.getenv("LOG_SCANNER_OUTPUT", 0)))
				else:
					print "first end connection successful with client " + str(addr)
					in_sock = clientsock
					out_sock = forward_sock
					self.handle_client(fr=clientsock, to=forward_sock, prnt=int(os.getenv("LOG_SCANNER_INPUT", 0)))
			else:
				os.waitpid(-1, os.WNOHANG) 
		else:
			clientsock = None
			forward_sock = None



	def handle_client(self, fr=None, to=None, prnt=False, child=False):
		while True:
			try:
				data=fr.recv(buf_len)
			except Exception as e:
				self.do_close()
			try:
				data = self.mod_proxy.ProxyHandler.modify_data(data)
			except:
				pass
			try:
				length = to.send(data)
			except Exception as e:
				self.do_close()

	def accept(self, s):
		clientsock, addr = s.accept()
		if self.listen_ssl:
			try:
				clientsock.do_handshake()
			except:
				clientsock = None
		try:
			del self.proxy_handler
		except:
			pass
		self.proxy_handler = self.mod_proxy.ProxyHandler()
		self.proxy_handler.initial_handshake(clientsock)
		return clientsock, addr

	def init_forwarding(self):
		# Select right reverse host and connect, custom class callbacks: handshake, get ip and port, maybe injection method
		try:
			self.proxy_to, ssl_socket = self.proxy_handler.get_reverse_proxy()
			if not self.proxy_to:
				raise
		except:
			return None
		if type(self.proxy_to) == tuple:
			forward_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
		elif type(self.proxy_to) == str:
			forward_sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
		if ssl_socket:
			proxy_context = SSL.Context(SSL.SSLv23_METHOD)
			forward_sock = SSL.Connection(proxy_context, forward_sock)
			forward_sock.connect(self.proxy_to)
			forward_sock.set_connect_state()
			forward_sock.do_handshake()
		else:
			forward_sock.connect(self.proxy_to)
		if self.proxy_handler.init_reverse_proxy(forward_sock) == False:
			return forward_sock
		return forward_sock



parser = argparse.ArgumentParser(prog='./proxy.py')
subparsers = parser.add_subparsers(title="subcommands", description="valid subcommands", dest="subparser", help='sub-command help')
staticproxy = subparsers.add_parser('staticproxy', help='Proxy static end to end connection')
staticproxy.add_argument('--listen-port', type=int, help='Listen port for proxy only with --listen-host')
staticproxy.add_argument('--listen-host', type=str, help='Listen host for proxy only with --listen-port')
staticproxy.add_argument('--listen-unix', type=str, help='Listen unix socket for proxy')
staticproxy.add_argument('--listen-ssl', type=bool, help='Listen with SSL')
staticproxy.add_argument('--listen-ca-cert', type=str, help='PEM-CA-Cert for listening')
staticproxy.add_argument('--listen-cert', type=str, help='PEM-Cert for listening')
staticproxy.add_argument('--listen-key', type=str, help='PEM-Key for listening')

staticproxy.add_argument('--proxy-port', type=int, help='Port of the TCP proxy endpoint, only with --proxy-host')
staticproxy.add_argument('--proxy-host', type=str, help='Host of the proxy endpoint, only with --proxy-port')
staticproxy.add_argument('--proxy-unix', type=str, help='Unix socket of the proxy endpoint')
staticproxy.add_argument('--proxy-ssl', type=bool, help='Proxy endpoint uses SSL?')

reverseproxy = subparsers.add_parser('reverseproxy', help='Proxy depending on circumstances')
reverseproxy.add_argument('--listen-port', type=int, help='Listen port for proxy only with --listen-host')
reverseproxy.add_argument('--listen-host', type=str, help='Listen host for proxy only with --listen-port')
reverseproxy.add_argument('--listen-unix', type=str, help='Listen unix socket for proxy')
reverseproxy.add_argument('--listen-ssl', type=bool, help='Listen with SSL')
reverseproxy.add_argument('--proxy-ssl', type=bool, help='Reverse proxy endpoints use SSL?')
reverseproxy.add_argument('--proxy-module', type=str, help='Import .py file as a module containing a class named ProxyHandler to handle reverse proxy functionality')

ns = parser.parse_args()

if ns.subparser == "staticproxy":
	del ns.subparser
	if ns.listen_port and ns.listen_host:
		ns.listen_on = (socket.gethostbyname(ns.listen_host), ns.listen_port)
	elif ns.listen_unix:
		ns.listen_on = ns.listen_unix
	else:
		print "No valid listen address given"
		exit(1)
	if ns.proxy_port and ns.proxy_host:
		ns.proxy_to = (socket.gethostbyname(ns.proxy_host), ns.proxy_port)
	elif ns.proxy_unix:
		ns.proxy_to = ns.proxy_unix
	else:
		print "No valid proxy address given"
		exit(1)
	del ns.listen_port
	del ns.listen_host
	del ns.listen_unix
	del ns.proxy_port
	del ns.proxy_host
	del ns.proxy_unix
	proxy = StaticProxy(**vars(ns))

elif ns.subparser == "reverseproxy":
	del ns.subparser
	if ns.listen_port and ns.listen_host:
		ns.listen_on = (socket.gethostbyname(ns.listen_host), ns.listen_port)
	elif ns.listen_unix:
		ns.listen_on = ns.listen_unix
	else:
		print "No valid listen address given"
		exit(1)
	del ns.listen_port
	del ns.listen_host
	del ns.listen_unix
	proxy = ReverseProxy(**vars(ns))
