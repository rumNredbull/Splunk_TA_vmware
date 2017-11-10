# Copyright (C) 2005-2017 Splunk Inc. All Rights Reserved.
#Core Python imports
import cookielib

#TA-vmware imports
import vim25.soap_wrapper
from vim25 import logger
#from vim25.mo import ServiceInstance
#from vim25 import vimobjs



class Connection(object):
	"""
	Represents a connection that all collectors/classes can inherit from and thus
	have access to a service instance and other valuable things. 
	
	This connection must be instantiated/updated with the class method update_connection.
	"""
	#Cached connections store all of the wsdl's and such of past targets
	cached_connections = {}
	vim25client = None
	svcInstance = None
	propColl = None
	rootFolder = None
	viewMgrRef = None
	tSpec = None
	cookie = None
	session_key = None
	eventManager = None
	taskManager = None
	perfManager = None
	domain = None
	vc_name = None
	vc_uuid = None
	vc_version = None
	target_type = None # HostAgent or VirtualCenter
	
	_domain_key = None
	
	@staticmethod
	def create_session_cookie(domain, value, version=0, name='vmware_soap_session', 
			port=None, port_specified=False, domain_specified=False, domain_initial_dot=False, 
			path='/', path_specified=True, secure=False, expires=None, discard=True, comment=None, 
			comment_url=None, rest={'HttpOnly': None}, rfc2109=False):
		"""
		Create a session cookie in order to enable the making of the service instance with the session key.
		args:
			domain - the domain for the vsphere
			value - the session key as a string
			hella stuff - ignore it except for domain and value
		
		Note: sessionStr format is: "vmware_soap_session=\"B3240D15-34DF-4BB8-B902-A844FDF42E85\"" (i.e.,
		correct way to quote the value is like this: create_session_cookie('foo.sv.splunk.com', '"2527788C-562B-4C44-A57E-96A61EE6DC4B"'))
		"""
		return cookielib.Cookie(version, name, value, port, port_specified, domain, domain_specified, 
			domain_initial_dot, path, path_specified, secure, expires, discard, comment, 
			comment_url, rest, rfc2109)
	
	@classmethod
	def is_service_instance_valid(cls):
		"""
		Check if the current service instance bound to the static class is valid
		"""
		try:
			logger.debug("[Connection] Checking for current time on the service instance.")
			cls.svcInstance.currentTime()
			logger.debug("[Connection] Time returned properly.")
			return True
		except Exception as e:
			logger.error("[Connection] I can't check the time for domain %s.  Exception below.  Returning False on valid session. Killing all the rebel scum!" % (cls.domain))
			logger.exception(e)
			logger.info("[Connection] Destroying bad session for domain %s" %(cls.domain))
			cls._destroy_vim_service()
			return False
	
	@classmethod
	def _populate_connection_properties(cls):
		"""
		Once the service instance has been refreshed this method should be called
		to re-populate the convenience properties.
		"""
		cls.cookie = cls.svcInstance.getServerConnection().getSessionCookie()
		cls.session_key = cls.cookie.value
		cls.domain = cls.svcInstance.getServerConnection().getUrl()
		cls.propColl = cls.svcInstance.getPropertyCollector()
		cls.rootFolder = cls.svcInstance.getRootFolder()
		cls.viewMgrRef = cls.svcInstance.getViewManager()
		cls.eventManager = cls.svcInstance.getEventManager()
		cls.taskManager = cls.svcInstance.getTaskManager()
		cls.perfManager = cls.svcInstance.getPerformanceManager()
		cls.tSpec = cls.vim25client.new('TraversalSpec', name="traverseEntities", path="view", skip=False, type="ContainerView")
		# Note for the future: if we want the vc url we should grab it from the update_connection parameters
		if hasattr(cls.svcInstance.getAboutInfo(), 'instanceUuid'):
			cls.vc_uuid = cls.svcInstance.getAboutInfo().instanceUuid
		else:
			cls.vc_uuid = cls.domain
		cls.vc_name = cls.svcInstance.getAboutInfo().name.replace(' ', '_')
		cls.vc_version = cls.svcInstance.getAboutInfo().version
		cls.target_type = cls.svcInstance.getAboutInfo().apiType
	
	@classmethod
	def _cache_and_populate_connection_properties(cls, new_domain):
		"""
		Check for a cached set of connection properties and cache the current ones.
		If cache is found use it to re-populate the convenience properties.
		
		RETURNS True if populated connection from cache
		"""
		#First cache what we have
		new_cache = {}
		new_cache["svcInstance"] = cls.svcInstance
		new_cache["vim25client"] = cls.vim25client
		new_cache["cookie"] = cls.cookie
		new_cache["session_key"] = cls.session_key
		new_cache["domain"] = cls.domain
		new_cache["propColl"] = cls.propColl
		new_cache["rootFolder"] = cls.rootFolder
		new_cache["viewMgrRef"] = cls.viewMgrRef
		new_cache["eventManager"] = cls.eventManager
		new_cache["taskManager"] = cls.taskManager
		new_cache["perfManager"] = cls.perfManager
		new_cache["tSpec"] = cls.tSpec
		new_cache["vc_uuid"] = cls.vc_uuid
		new_cache["vc_name"] = cls.vc_name
		new_cache["vc_version"] = cls.vc_version
		new_cache["target_type"] = cls.target_type
		if cls._domain_key is not None:
			cls.cached_connections[cls._domain_key] = new_cache
		else:
			logger.warning("[Connection] could not cache connection due to lack of set _domain_key")
		
		#Check if we have a cache, if so populate from it
		cached_connection = cls.cached_connections.get(new_domain, None)
		if cached_connection is not None:
			logger.info("[Connection] resetting connection from cache for domain=%s", new_domain)
			try:
				cls.svcInstance = cached_connection["svcInstance"]
				cls.vim25client = cached_connection["vim25client"]
				cls.cookie = cached_connection["cookie"]
				cls.session_key = cached_connection["session_key"]
				cls.domain = cached_connection["domain"]
				cls.propColl = cached_connection["propColl"]
				cls.rootFolder = cached_connection["rootFolder"]
				cls.viewMgrRef = cached_connection["viewMgrRef"]
				cls.eventManager = cached_connection["eventManager"]
				cls.taskManager = cached_connection["taskManager"]
				cls.perfManager = cached_connection["perfManager"]
				cls.tSpec = cached_connection["tSpec"]
				cls.vc_uuid = cached_connection["vc_uuid"]
				cls.vc_name = cached_connection["vc_name"]
				cls.vc_version = cached_connection["vc_version"]
				cls.target_type = cached_connection["target_type"]
				cls._domain_key = new_domain
				cls.svcInstance.getServerConnection().setSessionCookie(cls.cookie)
				cls.vim25client.setServerConnection(cls.svcInstance.getServerConnection())
				return cls.is_service_instance_valid()
			except KeyError as e:
				logger.error("[Connection] cache for domain=%s was missing a required property: %s", new_domain, e)
				cls._destroy_vim_service()
				return False
		else:
			logger.info("[Connection] could not reset connection from cache for domain=%s because cache does not exist yet", new_domain)
			cls._destroy_vim_service()
			return False
		
		
	@classmethod
	def _create_vim_service_from_cookie(cls, domain, cookie, raise_exceptions=False):
		"""
		Given a domain and a session key try to create a vim service from them
		"""
		try:
			cls.vim25client.createServiceInstance(server_url=domain, sessioncookie=cookie)
			cls.svcInstance = cls.vim25client.serviceInstance
			cls._populate_connection_properties()
		except Exception as e:
			#this means that the cookie was invalid
			msg = "[Connection] something went wrong when trying to create a new connection for domain "
			logger.exception("%s %s: %s", msg, domain, e)
			if raise_exceptions: raise e
			
		
	@classmethod
	def _create_vim_service_from_username_password(cls, domain, username, password, raise_exceptions=False):
		"""
		Given a domain, username and password create a vim service from them.
		"""
		# Create an empty serviceInstance first, this is to properly populate with an empty serverConnection
		try:
			cls.vim25client.createServiceInstance(server_url=domain, username=username, password=password)
			cls.svcInstance = cls.vim25client.serviceInstance
			cls._populate_connection_properties()
		except Exception as e:
			msg = "[Connection] something went wrong when trying to create a new connection for domain "
			logger.exception("%s %s: %s", msg, domain, e)
			if raise_exceptions: raise e
		
	@classmethod
	def _create_vim25client(cls, domain, use_cache=False):
		"""
		Given a domain, download and populate the wsdl in a Vim25Client
		"""
		logger.info("[Connection] creating a new vim25client object")
		cls.vim25client = vim25.soap_wrapper.Vim25Client(domain, plugins=[vim25.soap_wrapper.SoapFixer()])
		
	@classmethod
	def _create_vim_service(cls, domain, username=None, password=None, cookie=None, raise_exceptions=False, use_cache=False):
		#First check if there even is a service instance
		if use_cache:
			if cls._cache_and_populate_connection_properties(domain):
				return True
			else:
				logger.info("[Connection] could not load connection from cache for domain=%s, rebuilding from scratch", domain)
		if cls.svcInstance is None:
			logger.info("[Connection] svcInstance was destroyed correctly, proceeding with creation")
			#Here we set the domain key which is used for caching purposes
			cls._domain_key = domain
			#if no service instance make a new one
			#First check if the wsdl's been loaded, if not, load it.
			if cls.vim25client == None:
				logger.info("[Connection] WSDL not yet loaded, loading...")
				cls._create_vim25client(domain)
			#now try to build the serviceInstance
			#first try from session_key
			if cookie is not None:
				logger.info("[Connection] Trying to build creation from session key")
				try:
					cls._create_vim_service_from_cookie(domain, cookie, raise_exceptions=raise_exceptions)
					return cls.is_service_instance_valid()
				except Exception as e:
					#this means that the cookie was invalid
					msg = "[Connection] Cookie invalid. Failing for domain"
					logger.exception("%s %s: %s", msg, domain, e)
					if raise_exceptions: raise e
			#if session key failed try the username and password
			if username is not None and password is not None:
				logger.info("[Connection] Trying to build creation from User/Password")
				try:
					cls._create_vim_service_from_username_password(domain, username, password, raise_exceptions=raise_exceptions)
					return cls.is_service_instance_valid()
				except Exception as e:
					msg = "[Connection] something went wrong when trying to create a new vim service for domain "
					logger.exception("%s %s: %s", msg, domain, e)
					if raise_exceptions: raise e
					#username and password were bad, so we return False
					return False
			
	@classmethod
	def _destroy_vim_service(cls):
		logger.info("[Connection] Clearing Cookies")
		cls.vim25client.soapClient.options.transport.cookiejar.clear()
		logger.info("[Connection] Removing Service Instance")
		cls.vim25client.serviceInstance = None
		logger.info("[Connection] Removing class reference to Service Instance")
		cls.svcInstance = None
		logger.info("[Connection] Removing serverConnection")
		cls.vim25client.sc = None
		logger.info("[Connection] deleting vim25client object")
		cls.vim25client = None
		logger.info("[Connection] Setting class vars back to None")
		cls.cookie = None
		cls.session_key = None
		cls.domain = None
		cls.propColl = None
		cls.rootFolder = None
		cls.viewMgrRef = None
		cls.eventManager = None
		cls.taskManager = None
		cls.perfManager = None
		cls.tSpec = None
		cls.vc_uuid = None
		cls.vc_name = None
		cls.vc_version = None
		cls.target_type = None
		
	@classmethod
	def update_connection(cls, url, username=None, password=None, session_key=None, cookie=None, raise_exceptions=False):
		"""
		Create/update the static class Connection with the provided credentials and url.
		
		RETURNS True if successful, False if not
		"""
		if (username is None or password is None) and cookie is None:
			raise Exception("Must provide either a username-password and/or a cookie for domain : %s" %url)
		if url.startswith("https://") or url.startswith("http://"):
			domain = url.lstrip("htps:").lstrip("/")
		else:
			domain = url
			
		logger.debug("[Connection] Update called with url=%s username=%s password=[REDACTED] session_key=%s cookie=%s", url, username, session_key, cookie)
		
		#Create a cookie, mainly so I don't have to change unit tests
		if cookie is None and session_key is not None:
			logger.warning("[Connection] null cookie passed into update connection, creating an artificial cookie based on session_key, this will break for short named urls")
			cookie=cls.create_session_cookie(domain, session_key)
		
		#First check if there even is a service instance
		if cls.svcInstance is None:
			logger.debug("[Connection] Update called with no active svcInstance, building new service instance for domain=%s", domain)
			return cls._create_vim_service(domain, username, password, cookie, raise_exceptions)
		else:
			logger.info("[Connection] Connection has a vimservice, testing it")
			try:
				#Check if URL has changed from the currently loaded wsdl, if so reload it
				if Connection.svcInstance.serverConnection.getUrl() != domain:
					logger.info("[Connection] swapping connection from old_domain=%s to new_domain=%s", Connection.svcInstance.serverConnection.getUrl(), domain)
					return cls._create_vim_service(domain=domain, username=username, password=password, cookie=cookie, use_cache=True, raise_exceptions=raise_exceptions)
				elif Connection.svcInstance.serverConnection.getUrl() == domain:
					logger.info("[Connection] Update was called with a connection that is already in place with the same url. Validating that the current session is still valid")
					old_session_key = cls.session_key
					session_valid = cls.is_service_instance_valid()
					if session_valid and cookie is None and password is None:
						logger.info("[Connection] current_session_key=%s was valid and happy happy happy", cls.session_key)
						return True
					elif password is not None:
						logger.info("[Connection] Connection update called with password on an already created object. Updating with password.")
						cls._destroy_vim_service()
						return cls._create_vim_service(domain=domain, username=username, password=password, raise_exceptions=raise_exceptions)
					elif cookie is not None:
						logger.info("[Connection] was passed a session key/cookie, checking if it's what I'm already using")
						if cookie.value != old_session_key:
							#Got a new session key, remake the connection:
							logger.info("[Connection] was passed a different session key, making a new connection with session_key=%s", cookie.value)
							cls._destroy_vim_service()
							return cls._create_vim_service(domain=domain, cookie=cookie, raise_exceptions=raise_exceptions)
						else:
							logger.info("[Connection] urls are the same, and the session key is the same. returning current session status=%s", session_valid)
							return session_valid
			except Exception as e:
				logger.exception("[Connection] Could not update connection for domain: %s %s", url, e)
				if raise_exceptions:
					raise e
				return False
		
