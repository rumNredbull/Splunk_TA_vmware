# Copyright (C) 2005-2016 Splunk Inc. All Rights Reserved.
#Core Python Imports
import sys
import logging, logging.handlers
import re
from httplib2 import ServerNotFoundError
import socket, time

#CherryPy Web Controller Imports 
import cherrypy
import splunk.appserver.mrsparkle.controllers as controllers
from splunk.appserver.mrsparkle.lib.decorators import expose_page
from splunk.appserver.mrsparkle.lib.routes import route
from splunk.appserver.mrsparkle.lib.util import make_splunkhome_path
import splunk.entity as en

#Splunkd imports
import splunk
import splunk.rest as rest
import splunk.util as util
import lxml.etree as et
from splunk.models.app import App

#TA and SA Imports
sys.path.append(make_splunkhome_path(['etc', 'apps', 'SA-Hydra', 'bin']))
sys.path.append(make_splunkhome_path(['etc', 'apps', 'Splunk_TA_vmware', 'bin']))
from hydra.models import HydraNodeStanza, SplunkStoredCredential
from ta_vmware.models import TAVMwareCollectionStanza, TAVMwareVCenterForwarderStanza, TAVMwareSyslogForwarderStanza
import ta_vmware.simple_vsphere_utils as vsu

#CONSTANTS
REST_ROOT_PATH = '/services'


def setupLogger(logger=None, log_format='%(asctime)s %(levelname)s [SplunkForVMwareSetupController] %(message)s', level=logging.INFO, log_name="splunk_for_vmware_setup.log", logger_name="splunk_for_vmware_setup"):
	"""
	Setup a logger suitable for splunkd consumption
	"""
	if logger is None:
		logger = logging.getLogger(logger_name)
	
	logger.propagate = False # Prevent the log messages from being duplicated in the python.log file
	logger.setLevel(level)
	
	file_handler = logging.handlers.RotatingFileHandler(make_splunkhome_path(['var', 'log', 'splunk', log_name]), maxBytes=2500000, backupCount=5)
	formatter = logging.Formatter(log_format)
	file_handler.setFormatter(formatter)
	
	logger.handlers = []
	logger.addHandler(file_handler)
	
	logger.debug("Init splunk for vmware setup logger")
	
	return logger

def isValidAdmin(user=None, session_key=None):
	roles = []
	## Get user info			  
	try:
		if user is not None:
			logger.info('Retrieving role(s) for current user: %s' % (user))
			userDict = en.getEntities('authentication/users/%s' % (user), count=-1, sessionKey=session_key)
	
			for stanza, settings in userDict.items():
				if stanza == user:
					for key, val in settings.items():
						if key == 'roles':
							logger.info('Successfully retrieved role(s) for user: %s' % (user))
							roles = val
		logger.info('Current user roles: %s' % roles)
	
		if 'splunk_vmware_admin' in roles:
			logger.info('Current user is a valid admin, returning True')
			return True
		else:
			logger.info('Current user is NOT a valid admin, returning False')
			return False
	except Exception as e:
		logger.error("Failed to get role information, Exception: %s " % e)
		return False

def splunk_rest_request(path, sessionKey=None, getargs=None, postargs=None, method='GET', raiseAllErrors=False, proxyMode=False, rawResult=False, timeout=30, jsonargs=None):
	"""
	This is mostly a shameful copy of splunk.rest.simpleRequest.
	The difference lies in the automagic header/cert attachment that
	happens in splunkweb and messes with the splunkweb cherrypy.session.
	Also we don't auto magic any session keys
	
	Makes an HTTP call to the main splunk REST endpoint
	
	path: the URI to fetch
		If given a relative URI, then the method will normalize to the splunkd
		default of "/services/...".
		If given an absolute HTTP(S) URI, then the method will use as-is.
		If given a 'file://' URI, then the method will attempt to read the file
		from the local filesystem.  Only files under $SPLUNK_HOME are supported,
		so paths are 'chrooted' from $SPLUNK_HOME.
		
	getargs: dict of k/v pairs that are always appended to the URL
	
	postargs: dict of k/v pairs that get placed into the body of the 
		request. If postargs is provided, then the HTTP method is auto
		assigned to POST.
		
	method: the HTTP verb - [GET | POST | DELETE | PUT]
	
	raiseAllErrors: indicates if the method should raise an exception
		if the server HTTP response code is >= 400

	rawResult: don't raise an exception if a non 200 response is received;
		return the actual response
	
	Return:
	
		This method will return a tuple of (serverResponse, serverContent)
		
		serverResponse: a dict of HTTP status information
		serverContent: the body content
	"""
	# strip spaces
	path = path.strip(' ')
	# if absolute URI, pass along as-is
	if path.startswith('http'):
		uri = path
		
	# if file:// protocol, try to read file and return
	# the serverStatus is just an empty dict; file contents are in serverResponse
	elif path.startswith('file://'):
		raise Exception("Not supported for this method, use splunk.rest.simpleRequest instead")
			
	else:
		# prepend convenience root path
		if not path.startswith(REST_ROOT_PATH): path = REST_ROOT_PATH + '/' + path.strip('/')
		
		# setup args
		host = splunk.getDefault('host')
		if ':' in host:
			host = '[%s]' % host
			
		uri = '%s://%s:%s/%s' % \
			(splunk.getDefault('protocol'), host, splunk.getDefault('port'), path.strip('/'))

	if getargs:
		getargs = dict([(k,v) for (k,v) in getargs.items() if v != None])
		uri += '?' + util.urlencodeDict(getargs)
	
	# proxy mode bypasses all header passing
	headers = {}
	sessionSource = 'direct'
	
	if sessionKey:
		headers['Authorization'] = 'Splunk %s' % sessionKey
	
	payload = ''
	if postargs or jsonargs and method in ('GET', 'POST', 'PUT'):
		if method == 'GET':
			method = 'POST'
		if jsonargs:
			# if a JSON body was given, use it for the payload and ignore the postargs
			payload = jsonargs
		else:
			payload = util.urlencodeDict(postargs)
	#
	# make request
	#
	if logger.level <= logging.DEBUG:
		if uri.lower().find('login') > -1:
			logpayload = '[REDACTED]'
		else:
			logpayload = payload
		logger.debug('splunk_rest_request >>>\n\tmethod=%s\n\turi=%s\n\tbody=%s', method, uri, logpayload)
		logger.debug('splunk_rest_request > %s %s [%s] sessionSource=%s' % (method, uri, logpayload, sessionSource))
		t1 = time.time()

	# Add wait and tries to check if the HTTP server is up and running
	tries = 4
	wait = 10
	try:
		import httplib2
		for aTry in range(tries):
			h = httplib2.Http(timeout=timeout, disable_ssl_certificate_validation=True)
			serverResponse, serverContent = h.request(uri, method, headers=headers, body=payload)
			if serverResponse == None:
				if aTry < tries:
					time.sleep(wait)
			else:
				break
	except socket.error, e:
		raise splunk.SplunkdConnectionException, str(e)
	except socket.timeout, e:
		raise splunk.SplunkdConnectionException, 'Timed out while waiting for splunkd daemon to respond. Splunkd may be hung. (timeout=30)'
	except AttributeError, e:
		raise splunk.SplunkdConnectionException, 'Unable to establish connection with splunkd deamon. (%s)' % e

	serverResponse.messages = []
	
	if logger.level <= logging.DEBUG:
		logger.debug('simpleRequest < server responded status=%s responseTime=%.4fs', serverResponse.status, time.time() - t1)
		
	# Don't raise exceptions for different status codes or try and parse the response
	if rawResult:
		return serverResponse, serverContent

	#
	# we only throw exceptions in limited cases; for most HTTP errors, splunkd
	# will return messages in the body, which we parse, so we don't want to
	# halt everything and raise exceptions; it is up to the client to figure 
	# out the best course of action
	#
	if serverResponse.status == 401:
		#SPL-20915
		logger.debug('splunk_rest_request - Authentication failed; sessionKey=%s', sessionKey)
		raise splunk.AuthenticationFailed
	
	elif serverResponse.status == 402:
		raise splunk.LicenseRestriction
	
	elif serverResponse.status == 403:
		raise splunk.AuthorizationFailed(extendedMessages=uri)
		
	elif serverResponse.status == 404:
		
		# Some 404 responses, such as those for expired jobs which were originally
		# run by the scheduler return extra data about the original resource.
		# In this case we add that additional info into the exception object
		# as the resourceInfo parameter so others might use it.
		try:
			body = et.fromstring(serverContent)
			resourceInfo = body.find('dict')
			if resourceInfo is not None:
				raise splunk.ResourceNotFound(uri, format.nodeToPrimitive(resourceInfo))
			else:
				raise splunk.ResourceNotFound(uri, extendedMessages=rest.extractMessages(body))
		except et.XMLSyntaxError:
			pass
		
		raise splunk.ResourceNotFound, uri
	
	elif serverResponse.status == 201:
		try:
			body = et.fromstring(serverContent)
			serverResponse.messages = rest.extractMessages(body)
		except et.XMLSyntaxError, e:
			# do nothing, just continue, no messages to extract if there is no xml
			pass
		except e:
			# warn if some other type of error occurred.
			logger.warn("exception trying to parse serverContent returned from a 201 response.")
			pass
		
	elif serverResponse.status < 200 or serverResponse.status > 299:
		
		# service may return messages in the body; try to parse them
		try:
			body = et.fromstring(serverContent)
			serverResponse.messages = rest.extractMessages(body)
		except:
			pass
			
		if raiseAllErrors and serverResponse.status > 399:
			
			if serverResponse.status == 500:
				raise splunk.InternalServerError, (None, serverResponse.messages)
			elif serverResponse.status == 400:
				raise splunk.BadRequest, (None, serverResponse.messages)
			else:
				raise splunk.RESTException, (serverResponse.status, serverResponse.messages)
			

	# return the headers and body content
	return serverResponse, serverContent

def getRemoteSessionKey(username, password, hostPath):
	'''
	Get a remote session key from the auth system
	If fails return None
	'''
	
	uri = splunk.mergeHostPath(hostPath) + '/services/auth/login'
	args = {'username': username, 'password': password }
	
	try:
		serverResponse, serverContent = splunk_rest_request(uri, postargs=args)
	except splunk.AuthenticationFailed:
		return None
	
	if serverResponse.status != 200:
		logger.error('getRemoteSessionKey - unable to login; check credentials')
		rest.extractMessages(et.fromstring(serverContent))
		return None

	root = et.fromstring(serverContent)
	sessionKey = root.findtext('sessionKey')
	
	
	return sessionKey


logger = setupLogger()
splunk.setDefault()
local_host_path = splunk.mergeHostPath()

class VMwareSetupError(cherrypy.HTTPError):
	"""
	Use this to set the status and msg on the response.
	Call this like:
		raise VMwareSetupError(status=500, message="well we snafu'd a bit there")
	"""
	def get_error_page(self, *args, **kwargs):
		kwargs['noexname'] = 'true'
		return super(VMwareSetupError, self).get_error_page(*args, **kwargs)

class splunk_for_vmware_setup(controllers.BaseController):
	'''Splunk for VMware Setup Controller'''

	@route('/:app/:action=show_collection_setup')
	@expose_page(must_login=True, methods=['GET'])
	def show_collection_setup(self, **kwargs):
		"""
		Get the html content of the collection configuration page.
		"""
		
		conf_data = self._get_full_conf_data()
		return self.render_template('/Splunk_TA_vmware:/templates/collection_setup.html', dict(conf_data=conf_data))
	
	@route('/:app/:action=conf_data')
	@expose_page(must_login=True, methods=['GET'])
	def conf_data(self, **kwargs):
		"""
		Get the conf data as JSON
		"""
		conf_data = self._get_full_conf_data()
		return self.render_json(conf_data)

	@route('/:app/:action=validate_collection_node')
	@expose_page(must_login=True, methods=['GET'])
	def validate_collection_node(self, app, action, **kwargs):
		"""
		Given the node, determine several things. First, is it routeable? Next,
		is the provided username/password able to log in? Finally does it have 
		the required add-ons?
		To interact with this endpoint the node must already be stored in 
		hydra_node.conf. 
		REQUEST PARAMS:
			REQUIRED:
			node - the host path (management uri) of the node to be tested
			OPTIONAL (only used if both are passed):
				username - the username to validate
				password - the password to validate
		RESPONSE:
			All responses, unless uncaught error occurs are json with 
			a status and message field
			status - msg
			valid - Everything is valid
			unreachable - Could not reach the node to test creds
			invalid - Could reach host, but login failed
			badapps - Username/password are good but apps are not there
		"""
		node_path = kwargs.get("node", False)
		if node_path:
			validated_node_path = re.search("^\s*https?:\/\/[A-Za-z0-9\.\-_]+:\d+\/?\s*$", node_path)
			if validated_node_path is None:
				logger.error("Node name passed to validate_collection_node is not valid.")
				raise VMwareSetupError(status="500", message="Node name passed to validate_collection_node is not valid.")
		else:
			logger.error("No node name passed to validate_collection_node, cannot validate nothing!")
			raise VMwareSetupError(status="500", message="No node name passed to validate_collection_node, cannot validate nothing!")
		node_username = kwargs.get("username", False)
		node_password = kwargs.get("password", False)
		local_session_key = cherrypy.session["sessionKey"]
		response = {}
		node_stanza = HydraNodeStanza.from_name(node_path, "Splunk_TA_vmware", "nobody", session_key=local_session_key, host_path=local_host_path)
		if not node_username or not node_password:
			#No username/password provided so it must exist in the conf
			if not node_stanza:
				logger.error("Node={0} passed to validate_collection_node does not exist and username/password unspecified, cannot validate nothing!".format(node_path))
				raise VMwareSetupError(status="500", message="Node passed to validate_collection_node does not exist and username/password unspecified, cannot validate nothing!")
			else:
				node_username = node_stanza.user
				node_password = SplunkStoredCredential.get_password(node_path, node_username, "Splunk_TA_vmware", session_key=local_session_key, host_path=local_host_path)
				if node_password is None:
					node_stanza.credential_validation = False
					if not node_stanza.passive_save():
						logger.error("Error saving validation information for node={0}".format(node_path))
					return self.render_json({"status":"invalid", "msg":"No password found for this node please save a password"})
		if not node_stanza:
			node_stanza = HydraNodeStanza("Splunk_TA_vmware", "nobody", node_path, sessionKey=local_session_key, host_path=local_host_path)
			node_stanza.host = node_path
		#Time to actually validate the credentials!
		try:
			remote_session_key = getRemoteSessionKey(node_username, node_password, hostPath=node_path)
			if remote_session_key is None:
				#This is a big old fail
				response = {"status" : "invalid", "msg":"Could reach host, but login failed"}
				node_stanza.credential_validation = False
				node_stanza.addon_validation = False
				if not node_stanza.passive_save():
						logger.error("Error saving validation information for node={0}".format(node_path))
			else:
				#Okay credentials are good, now we can check that the apps are there
				serverResponse, serverContent = splunk_rest_request(path=node_path+'/services/apps/local', sessionKey=remote_session_key, getargs={'count':'0'})
				apps = rest.format.parseFeedDocument(serverContent)
				required_apps = ["SA-VMNetAppUtils", "SA-Hydra", "Splunk_TA_vmware"]
				installed_count = 0
				installed_apps = []
				for app in apps:
					contents = app.toPrimitive()
					if contents.has_key('label'):
						installed_apps.append(contents['label'])
					if app.title in required_apps:
						installed_count += 1
				if installed_count == len(required_apps):
					response = {"status" : "valid", "msg":"Everything is valid"}
					node_stanza.credential_validation = True
					node_stanza.addon_validation = True
					if not node_stanza.passive_save():
						logger.error("Error saving validation information for node={0}".format(node_path))
				else:
					logger.warning("node did not have the required apps, it had installed_apps='{0}'".format(str(installed_apps)))
					response = {"status" : "badapps", "msg":"Username/password are good but apps are not there"}
					node_stanza.credential_validation = True
					node_stanza.addon_validation = False
					if not node_stanza.passive_save():
						logger.error("Error saving validation information for node={0}".format(node_path))
		except ServerNotFoundError:
			response = {"status" : "unreachable", "msg":"Could not reach host"}
		except splunk.SplunkdConnectionException:
			logger.error("Could not find splunkd on node=%s", node_path)
			response = {"status" : "unreachable", "msg":"Could not reach host"}
		except splunk.AuthenticationFailed:
			logger.error("Could not log into splunkd on node=%s, credentials are definitely bad", node_path)
			response = {"status" : "invalid", "msg":"Could not authenticate with remote splunkd"}
		except Exception:
			response = {"status" : "unreachable", "msg":"Could not reach host"}
		return self.render_json(response)
	
	@route('/:app/:action=validate_vcenter')
	@expose_page(must_login=True, methods=['GET'])
	def validate_vcenter(self, app, action, **kwargs):
		"""
		Given the vcenter, determine several things. First, is it routeable? Next,
		is the provided username/password able to log in? 
		To interact with this endpoint without passing username password, the credentials 
		must already be stored in splunk. 
		REQUEST PARAMS:
			REQUIRED:
			vc - the vcenter's domain
			CHOICE (Must supply one of):
				name - the stanza name
					OR 
				username - the username to validate
				password - the password to validate
		RESPONSE:
			All responses, unless uncaught error occurs are json with 
			a status and message field
			status - msg
			valid - Everything is valid
			unreachable - Could not reach the vc to test creds
			invalid - Could reach vc, but login failed
		"""
		vc = kwargs.get("vc", False)
		if vc:
			validated_vc_domain = re.search("^[A-Za-z0-9\.\-_]+$", vc)
			if validated_vc_domain is None:
				logger.error("VC domain  passed to validate_vcenter is not valid.")
				raise VMwareSetupError(status="500", message="VC domain  passed to validate_vcenter is not valid.")
		else:
			logger.error("No vc domain passed to validate_vcenter, cannot validate nothing!")
			raise VMwareSetupError(status="500", message="No vc domain passed to validate_vcenter, cannot validate nothing!")
		name = kwargs.get("name", vc)
		if name:
			validated_vc_name = re.search("^[A-Za-z0-9\.\-_]+$", name)
			if validated_vc_name is None:
				logger.error("VC stanza name passed to validate_vcenter is not valid.")
				raise VMwareSetupError(status="500", message="VC stanza name passed to validate_vcenter is not valid.")
		else:
			logger.error("No vc stanza name passed to validate_vcenter, cannot validate nothing!")
			raise VMwareSetupError(status="500", message="No vc stanza name passed to validate_vcenter, cannot validate nothing!")

		vc_username = kwargs.get("username", False)
		vc_password = kwargs.get("password", False)
		if vc_username:
			validated_vc_username = re.search("[\r\n\t]", vc_username)
			if validated_vc_username is not None:
				logger.error("VC username passed to validate_vcenter is not valid.")
				raise VMwareSetupError(status="500", message="VC username passed to validate_vcenter is not valid.")
		vc_collect_logs = kwargs.get("vc_collect_logs", False)
		local_session_key = cherrypy.session["sessionKey"]
		response = {}
		vc_stanza = TAVMwareCollectionStanza.from_name(name, "Splunk_TA_vmware", "nobody", session_key=local_session_key, host_path=local_host_path)
		if not vc_username or not vc_password:
			#No username/password provided so it must exist in the conf
			if not vc_stanza:
				logger.error("vc={0} with stanza={1} passed to validate_vcenter does not exist and username/password unspecified, cannot validate nothing!".format(vc, name))
				raise VMwareSetupError(status="500", message="vc passed to validate_vcenter does not exist and username/password unspecified, cannot validate nothing!")
			else:
				vc_username = vc_stanza.username
				#get password from local storage
				vc_password = SplunkStoredCredential.get_password(vc, vc_username, "Splunk_TA_vmware", session_key=local_session_key, host_path=local_host_path)
				if vc_password is None:
					return self.render_json({"status":"invalid", "msg":"No password found for this vc please save a password"})
		#Time to actually validate the credentials!
		logger.info("Checking vc=%s with username=%s", vc, vc_username)
		try:
			vs = vsu.vSphereService(vc, vc_username, vc_password)
			response["status"] = "valid"
			response["msg"] = "Everything is valid"
			if vc_stanza:
				vc_stanza.credential_validation = True
				if not vc_stanza.passive_save():
					logger.error("problem saving credentials as validated for vc={0}".format(vc))
			if(vs.logout()) :
				logger.debug("User={0} successfully logout from {1}.".format(vc_username, vc))
			else :
				logger.warn("User={0} failed to logout from {1}.".format(vc_username, vc))
		except vsu.ConnectionFailure:
			response["status"] = "unreachable"
			response["msg"] = "Could not reach the vc to test creds"
		except vsu.LoginFailure:
			response["status"] = "invalid"
			response["msg"] = "Could reach vc, but login failed"
			if vc_stanza:
				vc_stanza.credential_validation = False
				if not vc_stanza.passive_save():
					logger.error("problem saving credentials as in-validated for vc={0}".format(vc))
		return self.render_json(response)
	
	@route('/:app/:action=update_collection')
	@expose_page(must_login=True, methods=['GET'])
	def update_collection(self, app, action, **kwargs):
		"""
		Enable/Disable Data Collection

		"""		
		local_session_key = cherrypy.session["sessionKey"]
		try:
			logger.info("updating collection")
			configured_heads = en.getEntities("/data/inputs/ta_vmware_collection_scheduler/puff", "Splunk_TA_vmware", "nobody", sessionKey=local_session_key, hostPath=local_host_path)
			for head_name, config in configured_heads.iteritems():
				isSchedulerDisabled = util.normalizeBoolean(config.get("disabled"))
				if(isSchedulerDisabled):
					on_off = "enable"
				else:
					on_off = "disable"
			path = local_host_path.rstrip("/") + "/servicesNS/nobody/Splunk_TA_vmware/data/inputs/ta_vmware_collection_scheduler/puff/" +on_off
			rsp, content = rest.simpleRequest(path, method='POST', sessionKey=local_session_key)
			logger.info(rsp)
			if rsp.status == 200:
				logger.info(" Successfully toggled the Scheduler status")
			else:
				logger.error(" some weird bad stuff happened trying to toggle a hydra scheduler on node=%s see content=%s",local_host_path, str(content))
		except ValueError as e:
			raise e
		except Exception:
			logger.exception(" Problem enabling/disabling remote hydra scheduler on node=%s", local_host_path)
	
	@route('/:app/:action=save_syslog_status')
	@expose_page(must_login=True, methods=['GET'])
	def save_syslog_status(self, app, action, **kwargs):
		"""
		Updates values in the syslog conf file
		"""
		local_session_key = cherrypy.session["sessionKey"]
		vc = kwargs.get("vc", None)
		syslog_uri = kwargs.get("syslog_uri", None)
		syslog_collect_logs = kwargs.get("collect_syslog", None)
		syslog_validation_status = kwargs.get("syslog_validation_status", None)
		syslog_config_status_msg = kwargs.get("syslog_config_status_msg",None)
		logger.debug("saving syslog info in save_syslog_status route")
		self._save_syslog_info(local_session_key, vc, syslog_uri, syslog_collect_logs, syslog_validation_status, syslog_config_status_msg)		 

	def _save_syslog_info(self, local_session_key, vc, syslog_uri=None, syslog_collect_logs=None, syslog_validation_status=None, syslog_config_status_msg=None):
		"""
		Handles saving the syslog stanza 
		Required parameters:
		  vc - vcenter's domain
		Optional parameters:
		  syslog_uri
		  syslog_collect_logs
		  syslog_validation_status
		"""
		def update_stanza_values(syslog_stanza):
			if syslog_collect_logs is not None:
				syslog_stanza.status = util.normalizeBoolean(syslog_collect_logs)
			if syslog_validation_status is not None:	
				syslog_stanza.validation_status = util.normalizeBoolean(syslog_validation_status)
			if syslog_uri is not None:
				syslog_stanza.uri = [syslog_uri]
			if syslog_config_status_msg is not None:
				syslog_stanza.config_status_msg = syslog_config_status_msg	
			# end helper functions
		if not vc: 
			raise VMwareSetupError(status="500", message="No vc domain passed to save_syslog_info")
		syslog_stanza = TAVMwareSyslogForwarderStanza.from_name(vc, "Splunk_TA_vmware", host_path=local_host_path, session_key=local_session_key)
		if syslog_stanza:
			logger.info("Updating the syslog info: vc=%s, uri=%s, status=%s, validation=%s", 
						vc, syslog_uri, syslog_collect_logs, syslog_validation_status)
			update_stanza_values(syslog_stanza)

			if not syslog_stanza.passive_save():
				logger.error("problem updating the syslog forwarder stanza for vc=%s and syslog_uri=%s , stanza will have to be regenerated", vc, syslog_uri)		
			else:
				logger.debug("successfully saved stanza: uri=%s, status=%s, validation=%s", 
							 str(syslog_stanza.uri), str(syslog_stanza.status), str(syslog_stanza.validation_status))

		else:
			# create a new stanza
			logger.info("No stored syslog infomation for vc=%s, creating new syslog stanza.", vc)
			new_syslog_stanza = TAVMwareSyslogForwarderStanza("Splunk_TA_vmware", "nobody", vc, sessionKey=local_session_key, host_path=local_host_path)
			logger.info("Created new stanza")
			update_stanza_values(new_syslog_stanza)
			try:
				new_syslog_stanza.save()
			except Exception, e:
				logger.error("problem saving syslog stanza for vc=%s, stanza will have to be regenerated",e)
				pass

	
			
	@route('/:app/:action=validate_vcenter_forwarder')
	@expose_page(must_login=True, methods=['GET'])
	def validate_vcenter_forwarder(self, app, action, **kwargs):
		"""
		Given the vcenter forwarder, determine several things. First, is it routeable? Next,
		is the provided username/password able to log in? 
		To interact with this endpoint without passing username password, the credentials 
		must already be stored in splunk. Also check if the TA-vcenter is installed on the forwarder.
		REQUEST PARAMS:
			REQUIRED:
			vc - the vcenter's domain
			CHOICE (Must supply one of):
				name - the stanza name
					OR 
				username - the username to validate
				password - the password to validate
		RESPONSE:
			All responses, unless uncaught error occurs are json with 
			a status and message field
			status - msg
			valid - Everything is valid
			unreachable - Could not reach the vc to test creds
			invalid - Could reach vc, but login failed
		"""
		vc = kwargs.get("vc", False)
		vc_host_path = kwargs.get("host_path", False)
		if vc:
			validated_vc_domain = re.search("^[A-Za-z0-9\.\-_]+$", vc)
			if  validated_vc_domain is None:
				logger.error("VC domain passed to validate_vcenter_forwarder is not valid.")
				raise VMwareSetupError(status="500", message="VC domain passed to validate_vcenter_forwarder is not valid.")
		else:
			logger.error("No vc domain passed to validate_vcenter_forwarder, cannot validate nothing!")
			raise VMwareSetupError(status="500", message="No vc domain passed to validate_vcenter_forwarder, cannot validate nothing!")
		if vc_host_path:
			validated_vc_host_path = re.search("^\s*https?:\/\/[A-Za-z0-9\.\-_]+:\d+\/?\s*$", vc_host_path)
			if validated_vc_host_path is None:
				logger.error("VC host path passed to validate_vcenter_forwarder is not valid.")
				raise VMwareSetupError(status="500", message="VC host path passed to validate_vcenter_forwarder is not valid.")
		name = kwargs.get("name", vc)
		vc_username = kwargs.get("username", False)
		vc_password = kwargs.get("password", False)
		if vc_username:
			validated_vc_username = re.search("[\r\n\t]", vc_username)
			if validated_vc_username is not None:
				logger.error("VC username passed to validate_vcenter_forwarder is not valid.")
				raise VMwareSetupError(status="500", message="VC username passed to validate_vcenter_forwarder is not valid.")
		local_session_key = cherrypy.session["sessionKey"]
		response = {}
		vc_stanza = TAVMwareVCenterForwarderStanza.from_name(name, "Splunk_TA_vmware", "nobody", session_key=local_session_key, host_path=local_host_path)
		if not vc_username or not vc_password or not vc_host_path:
			#No username/password provided so it must exist in the conf
			if not vc_stanza:
				logger.error("vc={0} with stanza={1} passed to validate_vcenter_forwarder does not exist and username/password unspecified, cannot validate nothing!".format(vc, name))
				raise VMwareSetupError(status="500", message="vc passed to validate_vcenter_forwarder does not exist and username/password unspecified, cannot validate nothing!")
			else:
				vc_username = vc_stanza.user
				vc_host_path = vc_stanza.host
				#get password from local storage
				vc_password = SplunkStoredCredential.get_password(vc_host_path, vc_username, "Splunk_TA_vmware", session_key=local_session_key, host_path=local_host_path)
				if vc_password is None:
					vc_stanza.credential_validation = False
					vc_stanza.addon_validation = False
					if not vc_stanza.passive_save():
						logger.error("Error saving validation information for vc stanza={0}".format(vc_host_path))
					return self.render_json({"status":"invalid", "msg":"Problem reaching host. Password for the specified host cannot be found"})
		#Time to actually validate the credentials!
		logger.info("Checking vc=%s  forwarder with username=%s", vc_host_path, vc_username)

		#Time to actually validate the credentials!
		try:
			remote_session_key = getRemoteSessionKey(vc_username, vc_password, hostPath=vc_host_path)
			if remote_session_key is None:
				#This is a big old fail
				response = {"status" : "invalid", "msg":"Could reach host, but login failed"}
				vc_stanza.credential_validation = False
				vc_stanza.addon_validation = False
				if not vc_stanza.passive_save():
						logger.error("Error saving validation information for vc stanza={0}".format(vc_host_path))
			else:
				#Okay credentials are good, now we can check that the apps are there
				serverResponse, serverContent = splunk_rest_request(path=vc_host_path+'/services/apps/local', sessionKey=remote_session_key, getargs={'count':'0'})
				apps = rest.format.parseFeedDocument(serverContent)
				logger.info("Accessing apps")
				required_apps = ["Splunk_TA_vcenter"]
				installed_count = 0
				installed_apps = []
				for app in apps:
					contents = app.toPrimitive()
					if contents.has_key('label'):
						installed_apps.append(contents['label'])
					if app.title in required_apps:
						installed_count += 1
				if installed_count == len(required_apps):
					response = {"status" : "valid", "msg":"Everything is valid"}
					vc_stanza.credential_validation = True
					vc_stanza.addon_validation = True
				else:
					logger.warning("vc forwarder did not have the required app- Splunk_TA_vcenter.")
					response = {"status" : "badapps", "msg":"Username/password are good but app is not there"}
					vc_stanza.credential_validation = True
					vc_stanza.addon_validation = False
				if not vc_stanza.passive_save():
					logger.error("Error saving validation information for host={0}".format(vc_host_path))
		except ServerNotFoundError:
			response = {"status" : "unreachable", "msg":"Could not reach host"}
		except splunk.SplunkdConnectionException:
			logger.error("Could not find splunkd on host=%s", vc_host_path)
			response = {"status" : "unreachable", "msg":"Could not reach host"}
		except splunk.AuthenticationFailed:
			logger.error("Could not log into splunkd on host=%s, credentials are definitely bad", vc_host_path)
			response = {"status" : "invalid", "msg":"Could not authenticate with remote splunkd"}
		except Exception:
			logger.error("Could not log into splunkd on host=%s, due to an exception", vc_host_path )
			response = {"status" : "unreachable", "msg":"Could not reach host"}		
			
		return self.render_json(response)	
		
	@route('/:app/:action=validate_unmanaged_host')
	@expose_page(must_login=True, methods=['GET'])
	def validate_unmanaged_host(self, app, action, **kwargs):
		"""
		Given the host, determine several things. First, is it routeable? Next,
		is the provided username/password able to log in? 
		To interact with this endpoint without passing username password, the credentials 
		must already be stored in splunk. 
		REQUEST PARAMS:
			REQUIRED:
			host - the host's domain
			OPTIONAL (only used if both are passed):
				name - the stanza name if different from host, else host will be used
				username - the username to validate
				password - the password to validate
		RESPONSE:
			All responses, unless uncaught error occurs are json with 
			a status and message field
			status - msg
			valid - Everything is valid
			unreachable - Could not reach the node to test creds
			invalid - Could reach host, but login failed
		"""
		host = kwargs.get("host", False)
		if host:
			validated_hostwhitelist = re.search("[A-Za-z0-9\.\-_]", host)
			validated_hostblacklist = re.search("[\r\n\t]", host)
			if validated_hostwhitelist is None or validated_hostblacklist is not None:
				logger.error("Host domain passed to validate_host is not valid.")
				raise VMwareSetupError(status="500", message="Host domain passed to validate_host is not valid.")
		else:
			logger.error("No host domain passed to validate_host, cannot validate nothing!")
			raise VMwareSetupError(status="500", message="No host domain passed to validate_host, cannot validate nothing!")
		name = kwargs.get("name", host)
		if name:
			validated_namewhitelist = re.search("[A-Za-z0-9\.\-_]", name)
			validated_nameblacklist = re.search("[\r\n\t]", name)
			if validated_namewhitelist is None or validated_nameblacklist is not None:
				logger.error("Host stanza name passed to validate_host is not valid.")
				raise VMwareSetupError(status="500", message="Host stanza name passed to validate_host is not valid.")

		host_username = kwargs.get("username", False)
		host_password = kwargs.get("password", False)
		if host_username:
			validated_host_username = re.search("[\r\n\t]", host_username)
			if validated_host_username is not None:
				logger.error("Host username passed to validate_unmanaged_host is not valid.")
				raise VMwareSetupError(status="500", message="Host username passed to validate_unmanaged_host is not valid.")
		local_session_key = cherrypy.session["sessionKey"]
		response = {}
		host_stanza = TAVMwareCollectionStanza.from_name(name, "Splunk_TA_vmware", "nobody", session_key=local_session_key, host_path=local_host_path)
		if not host_username or not host_password:
			#No username/password provided so it must exist in the conf
			if not host_stanza:
				logger.error("host={0} with stanza={1} passed to validate_unmanaged_host does not exist and username/password unspecified, cannot validate nothing!".format(host, name))
				raise VMwareSetupError(status="500", message="host passed to validate_vcenter does not exist and username/password unspecified, cannot validate nothing!")
			else:
				host_username = host_stanza.username
				#get password from local storage
				host_password = SplunkStoredCredential.get_password(host, host_username, "Splunk_TA_vmware", session_key=local_session_key, host_path=local_host_path)
				if host_password is None:
					return self.render_json({"status":"invalid", "msg":"No password found for this vc please save a password"})
		#Time to actually validate the credentials!
		logger.info("Checking host=%s with username=%s", host, host_username)
		try:
			vs = vsu.vSphereService(host, host_username, host_password)
			response["status"] = "valid"
			response["msg"] = "Everything is valid"
			if host_stanza:
				host_stanza.credential_validation = True
				if not host_stanza.passive_save():
					logger.error("problem saving credentials as validated for host={0}".format(host))
			if(vs.logout()) :
				logger.debug("User={0} successfully logout from {1}.".format(host_username, host))
			else :
				logger.warn("User={0} failed to logout from {1}.".format(host_username, host))
		except vsu.ConnectionFailure:
			response["status"] = "unreachable"
			response["msg"] = "Could not reach the unamanaged host to test creds"
		except vsu.LoginFailure:
			response["status"] = "invalid"
			response["msg"] = "Could reach unmanaged host, but login failed"
			if host_stanza:
				host_stanza.credential_validation = False
				if not host_stanza.passive_save():
					logger.error("problem saving credentials as in-validated for host={0}".format(host))
		
		return self.render_json(response)

	def _connect_to_vc(self, vc_username, vc_password, vc_stanza):
		vc = vc_stanza.target[0]
		try:
			connection = vsu.vSphereService(vc, vc_username, vc_password)
		except vsu.ConnectionFailure:
			raise VMwareSetupError(status="500", message="Could not retrieve service instance for vcenter {0}, vcenter is unreachable".format(vc_stanza.target[0]))
		except vsu.LoginFailure:
			if vc_stanza:
				vc_stanza.credential_validation = False
				if not vc_stanza.passive_save():
					logger.error("problem saving credentials as in-validated for vc={0}".format(vc))
			raise VMwareSetupError(status="500", message="Could not log in to vcenter {0} with stored creds, cannot get host list if cannot login".format(vc))
		return connection

	def _disconnect_from_vc(self, connection, vc_stanza):
		# logout the session
		if (connection.logout()):
			logger.debug("User={0} successfully logout from {1}.".format(vc_stanza.username,vc_stanza.target[0]))
		else:
			logger.warn("User={0} failed to logout from {1}.".format(vc_stanza.username,vc_stanza.target[0]))
			

	def _get_filtered_host_info(self, connection, vc_stanza):
		"""
		Uses the vSphereService to get the list of managed hosts for the given VC and separates it
		into included and excluded lists as per the white/blacklists in the ta_vmware_collection.conf stanza
		Args:
		  vc_username, password, ta_vmware_collection_stanza
		Returns:
		  tuple of (included_hosts, excluded_hosts). included/excluded_host is a list of  dictionaries, 
          with each dictionary containing the following keys: 
		  (name, moid, config.product.version, config.product.name)
		"""
		included_hosts = []
		excluded_hosts = []
		host_list = connection.get_host_list()
		#deal with the host list and such
		if (vc_stanza.managed_host_blacklist is not None) and (vc_stanza.managed_host_blacklist != "None"):
			black_re_search = re.compile(vc_stanza.managed_host_blacklist, flags=re.S).search
		else:
			#fake re search method, always doesn't match
			black_re_search = lambda s: None
		if (vc_stanza.managed_host_whitelist is not None) and (vc_stanza.managed_host_whitelist != "None"):
			white_re_search = re.compile(vc_stanza.managed_host_whitelist, flags=re.S).search
		else:
			#fake re search method, always matches (sorta, really jsut always returns true instead ofnon None match object but whatevs)
			white_re_search = lambda s: True
		for host in host_list:
			#Peform PCRE matching, i.e. python re search
			if black_re_search(host['name']) or (white_re_search(host['name']) is None):
				excluded_hosts.append(host)
			else:
				included_hosts.append(host)
		return (included_hosts, excluded_hosts)
		
	def _get_vc_stanza(self, vc):
		local_session_key = cherrypy.session["sessionKey"]
		vc_stanza = TAVMwareCollectionStanza.from_name(vc, app="Splunk_TA_vmware", host_path=local_host_path, session_key=local_session_key)
		if vc_stanza.target_type != "vc":
			raise VMwareSetupError(status="500", message="Incorrect target_type for stanza {0}, cannot get host list if not a vc. actual target_type was {1}".format(vc, str(vc_stanza.target_type)))
		return vc_stanza
		
	def _get_vc_credentials(self, vc_stanza):
		local_session_key = cherrypy.session["sessionKey"]
		vc_username = vc_stanza.username
		#get password from local storage
		vc_password = SplunkStoredCredential.get_password(vc_stanza.target[0], vc_username, "Splunk_TA_vmware", session_key=local_session_key, host_path=local_host_path)
		if vc_password is None:
			raise VMwareSetupError(status="500", message="Could not retrieve password for vcenter {0}, cannot get host list if cannot login".format(vc_stanza.target[0]))
		return vc_username, vc_password

	
		
	@route('/:app/:action=test_syslog')
	@expose_page(must_login=True, methods=['GET'])
	def test_syslog(self, app, action, **kwargs):
		import splunk.search
		local_session_key = cherrypy.session["sessionKey"]
		pause_default = '20'
		pause = int(kwargs.get('pause', pause_default))
		cmd = '|genhost vcenter="pause%d"' % pause
		job = splunk.search.dispatch(cmd, sessionkey=local_session_key)
		sid = job.sid
		logger.debug("debug pause job with sid %s", sid)
		return sid


	@route('/:app/:action=get_managed_hosts')
	@expose_page(must_login=True, methods=['GET'])
	def get_managed_hosts(self, app, action, **kwargs):
		"""
		Given the vcenter, get the list of managed hosts.
		This vcenter must already be stored in the collection conf
		in a singleton stanza.
		REQUEST PARAMS:
			REQUIRED:
			vc - the vcenter's stanza name
		RESPONSE:
			All responses, unless uncaught error occurs are json with 
			an included_hosts field that is an array of managed host names
			and excluded_hosts field that is an array of managed host names.
		"""
		vc = kwargs.get("vc", False)
		if not vc:
			logger.error("No vc stanza name passed to get_managed_hosts, cannot validate nothing!")
			raise VMwareSetupError(status="500", message="No vc stanza name passed to get_managed_hosts, cannot validate nothing!")
		vc_stanza = self._get_vc_stanza(vc)
		vc_username, vc_password = self._get_vc_credentials(vc_stanza)
		connection = self._connect_to_vc(vc_username, vc_password, vc_stanza)
		included_hosts_d, excluded_hosts_d = self._get_filtered_host_info(connection, vc_stanza)
		self._disconnect_from_vc(connection, vc_stanza)
		response = {"included_hosts": [x['name'] for x in included_hosts_d], 
					"excluded_hosts": [x['name'] for x in excluded_hosts_d]}
		return self.render_json(response)

	
	@route('/:app/:action=save_collection_node')
	@expose_page(must_login=True, methods=['POST'])
	def save_collection_node(self, app, action, **kwargs):
		"""
		Given the node info, save the worker node to hydra_node.conf
		REQUEST PARAMS:
			REQUIRED:
			node_name - the name of the node stanza being edited, if empty string means create new
			node - the management uri
			username - user to use with node
			password - password to use with node
			heads - number of input processes to enable
		RESPONSE:
			200 (update), 201 (created) or 500 (error)
		"""
		node_path = kwargs.get("node", False)
		if node_path:
			validated_node_path = re.search("^\s*https?:\/\/[A-Za-z0-9\.\-_]+:\d+\/?\s*$", node_path)
			if validated_node_path is None:
				logger.error("Node name passed to save_worker_node is not valid.")
				raise VMwareSetupError(status="500", message="Node name passed to save_worker_node is not valid.")
		else:
			logger.error("No node name passed to save_worker_node, cannot save nothing!")
			raise VMwareSetupError(status="500", message="No node name passed to save_worker_node, cannot save nothing!")
		node_name = kwargs.get("node_name", node_path)
		username = kwargs.get("username", False)
		if username:
			validated_node_username = re.search("[\r\n\t]", username)
			if validated_node_username is not None:
				logger.error("Node username passed to save_worker_node is not valid.")
				raise VMwareSetupError(status="500", message="Node username passed to save_worker_node is not valid.")
		else:
			logger.error("No username passed to save_worker_node, cannot save nothing!")
			raise VMwareSetupError(status="500", message="No username passed to save_worker_node, cannot save nothing!")
		heads = kwargs.get("heads", False)
		if heads:
			validated_heads = re.search("^(([1-2][0-9])|[1-9]|30)$", heads)
			if validated_heads is None:
				logger.error("Heads passed to save_worker_node is not valid.")
				raise VMwareSetupError(status="500", message="Heads passed to save_worker_node is not valid.")
		else:
			logger.error("No heads passed to save_worker_node, cannot save nothing!")
			raise VMwareSetupError(status="500", message="No heads passed to save_worker_node, cannot save nothing!")
		password = kwargs.get("password", False)
		if not password:
			logger.info("No password passed to save_worker_node, will not edit password")
		#First try to pull up an existing conf stanza
		local_session_key = cherrypy.session["sessionKey"]
		status = 200
		#First we check if we have to delete an old node due to changing the path
		if node_name and (node_name != node_path):
			node_stanza = HydraNodeStanza.from_name(node_name, "Splunk_TA_vmware", host_path=local_host_path, session_key=local_session_key)
			logger.info("collection node's old_host_path=%s edited will delete existing stanza and create new one with new_host_path=%s. also deleting associated credential", node_name, node_path)
			if not node_stanza.passive_delete():
				logger.error("Could not delete hydra node stanza with host_path={0}".format(node_name))
			node_stanza = False
		else:
			node_stanza = HydraNodeStanza.from_name(node_path, "Splunk_TA_vmware", host_path=local_host_path, session_key=local_session_key)
		if not node_stanza:
			logger.info("creating new hydra node stanza for host_path={0}".format(node_path))
			node_stanza = HydraNodeStanza("Splunk_TA_vmware", "nobody", node_path, sessionKey=local_session_key, host_path=local_host_path)
			status = 201
			cherrypy.response.headers["Location"] = node_stanza.get_id()
		if node_stanza.user != username:
			#Need to redo the password for new username
			stored_cred = SplunkStoredCredential.from_name(SplunkStoredCredential.build_name(node_name, str(node_stanza.user)), app="Splunk_TA_vmware", owner="nobody", host_path=local_host_path, session_key=local_session_key)
			if stored_cred:
				if not password:
					password = stored_cred.clear_password
					logger.info("Recreating secure storage of password for collection_node={0}".format(node_path))
				logger.info("Deleting outmoded credential")
				if not stored_cred.passive_delete():
					logger.error("Could not delete outmoded credential it may linger")
		if password:
			new_cred = SplunkStoredCredential("Splunk_TA_vmware", "nobody", username, sessionKey=local_session_key, host_path=local_host_path)
			new_cred.realm = node_path
			new_cred.password = password
			new_cred.username = username
			if not new_cred.passive_save():
				logger.error("Failed to save credential: realm={0} username={1}".format(node_path, username))
		else:
			password = SplunkStoredCredential.get_password(node_path, username, "Splunk_TA_vmware", session_key=local_session_key, host_path=local_host_path)
		node_stanza.host = node_path
		node_stanza.user = username
		node_stanza.heads = heads
		
		#Manipulate the inputs on the remote node to match heads if able, otherwise log error but otherwise do nothing
		input_names = ["alpha", "beta", "gamma", "delta", "epsilon", "zeta", "eta", "theta"]
		try:
			remote_session_key = getRemoteSessionKey(username, password, node_path)
		except ServerNotFoundError:
			logger.error("Could not find node=%s", node_path)
			remote_session_key = None
		except splunk.SplunkdConnectionException:
			logger.error("Could not find splunkd on node=%s", node_path)
			remote_session_key = None
		except splunk.AuthenticationFailed:
			logger.error("Could not log into splunkd on node=%s, credentials are definitely bad", node_path)
			remote_session_key = None
		except Exception:
			remote_session_key = None
		if remote_session_key is None:
			logger.error("Could not log into node=%s with the credentials provided, cannot manage the heads on that node", node_path)
			node_stanza.credential_validation = False
		else:
			for counter in range(len(input_names)):
				input_name = input_names[counter]
				if counter < int(heads):
					action = "enable"
				else:
					action = "disable"
				path = node_path.rstrip("/") + "/servicesNS/nobody/Splunk_TA_vmware/data/inputs/ta_vmware_collection_worker/" + input_name + "/" + action
				try:
					logger.info("Adjusting input with rest request on path=%s with session_key=%s", path, remote_session_key)
					splunk_rest_request(path, sessionKey=remote_session_key, method="POST", raiseAllErrors=True)
				except ServerNotFoundError:
					logger.exception("Could not reach node={0}", node_path)
				except Exception as e:
					message = "Problem editing the number of worker inputs on the remote node={0}: ".format(node_path) + e.message
					logger.exception(message)
					node_stanza.addon_validation = False
		
		if node_stanza.passive_save():
			cherrypy.response.status = status
		else:
			raise VMwareSetupError(status=500, message="Could not save node={0}".format(node_path))
	
	@route('/:app/:action=delete_collection_node/:node_path')
	@expose_page(must_login=True, methods=['DELETE'])
	def delete_collection_node(self, app, action, node_path, **kwargs):
		"""
		Given the node info, delete the worker node from hydra_node.conf
		REQUEST PARAMS:
			REQUIRED:
			node - the management uri
		RESPONSE:
			200 (deleted) or 500 (error)
		"""
		if node_path:
			validated_node_path = re.search("^\s*https?:\/\/[A-Za-z0-9\.\-_]+:\d+\/?\s*$", node_path)
			if validated_node_path is None:
				logger.error("Node name passed to delete_worker_node is not valid.")
				raise VMwareSetupError(status="500", message="Node name passed to delete_worker_node is not valid.")
		else:
			logger.error("No node name passed to delete_worker_node, cannot delete nothing!")
			raise VMwareSetupError(status="500", message="No node name passed to delete_worker_node, cannot delete nothing!")
		local_session_key = cherrypy.session["sessionKey"]
		node_stanza = HydraNodeStanza.from_name(node_path, "Splunk_TA_vmware", host_path=local_host_path, session_key=local_session_key)
		if node_stanza:
			node_username = node_stanza.user
			stored_cred = SplunkStoredCredential.from_name(SplunkStoredCredential.build_name(node_stanza.host, node_stanza.user), app="Splunk_TA_vmware", owner="nobody", host_path=local_host_path, session_key=local_session_key)
			if stored_cred:
				node_password = stored_cred.clear_password
				logger.info("Deleting obsolete credential")
				if not stored_cred.passive_delete():
					logger.error("Could not delete obsolete credential it may linger")
			else:
				node_password = None
			if not node_stanza.passive_delete():
				raise VMwareSetupError(status="500", message="Failed to delete node {0}".format(node_path))
		else:
			raise VMwareSetupError(status="500", message="Failed to find node {0}, cannot delete it".format(node_path))
		
		try:
			remote_session_key = getRemoteSessionKey(node_username, node_password, node_path)
		except ServerNotFoundError:
			logger.error("Could not find node=%s", node_path)
			remote_session_key = None
		except splunk.SplunkdConnectionException:
			logger.error("Could not find splunkd on node=%s", node_path)
			remote_session_key = None
		except splunk.AuthenticationFailed:
			logger.error("Could not log into splunkd on node=%s, credentials are definitely bad", node_path)
			remote_session_key = None
		except Exception:
			remote_session_key = None
		if remote_session_key is None:
			logger.error("Could not log into node=%s with the credentials provided, cannot manage the heads on that node", node_path)
		else:
			#Manipulate the inputs on the remote node, i.e. disable them all
			input_names = ["alpha", "beta", "gamma", "delta", "epsilon", "zeta", "eta", "theta"]
			for input_name in input_names:
				action = "disable"
				path = node_path.rstrip("/") + "/servicesNS/nobody/Splunk_TA_vmware/data/inputs/ta_vmware_collection_worker/" + input_name + "/" + action
				try:
					logger.info("Adjusting input with rest request on path=%s", path)
					splunk_rest_request(path, sessionKey=remote_session_key, method="POST", raiseAllErrors=True)
				except ServerNotFoundError:
					logger.exception("Could not reach node={0} to edit hydra worker inputs", node_path)
				except Exception as e:
					message = "Problem editing the number of worker inputs on the remote node={0}: ".format(node_path) + e.message
					logger.exception(message)
			#Destroy stored credentials
			try:
				creds = SplunkStoredCredential.all(host_path=node_path, sessionKey=remote_session_key)
				creds._owner = "nobody"
				creds.filter_by_app("Splunk_TA_vmware")
				for cred in creds:
					if not cred.passive_delete():
						logger.error("Problem deleteing credential on node={0} ".format(node_path))
			except ServerNotFoundError:
				logger.exception("Could not reach node={0} to delete all credentials under Splunk_TA_vmware", node_path)
			except Exception as e:
				message = "Problem deleting the stored credentials on the remote node={0}: ".format(node_path) + e.message
				logger.exception(message)
	
	@route('/:app/:action=save_vcenter')
	@expose_page(must_login=True, methods=['POST'])
	def save_vcenter(self, app, action, **kwargs):
		"""
		Given the vc info, modify ta_vmware_collection.conf
		REQUEST PARAMS:
			REQUIRED:
			name - the stanza name
			vc - the vcenter's domain
			username - the username to use
			OPTIONAL:
				password - the password to use, if null no change made
				host_whitelist - the host whitelist to use, if null no whitelist will be used
				host_blacklist - the host blacklist to use, if null no blacklist will be used
				vc_splunk_uri - the uri to use when talking to that splunk forwarder
				vc_splunk_username - the username to use when talking to that splunk forwarder
				vc_splunk_password - the password to use when talking to that splunk forwarder
		        syslog_uri - syslog collection target hosts
		        collect_syslog - boolean switch to control syslog collection
		        syslog_validation_status - boolean to indicate syslog collection passing validation checks
		RESPONSE:
			200 (update), 201 (created) or 500 (error)
		"""
		vc = kwargs.get("vc", False)
		if vc:
			validated_vc_domain = re.search("^[A-Za-z0-9\.\-_]+$", vc)
			if  validated_vc_domain is None:
				logger.error("VC domain passed to save_vcenter is not valid.")
				raise VMwareSetupError(status="500", message="VC domain passed to save_vcenter is not valid.")
		else:
			logger.error("No vc passed to save_vcenter, cannot save nothing!")
			raise VMwareSetupError(status="500", message="No vc name passed to save_vcenter, cannot save nothing!")

		name = kwargs.get("name", False)
		if name:
			validated_stanza_name = re.search("^[A-Za-z0-9\.\-_]+$", name)
			if validated_stanza_name is None:
				logger.error("VC stanza name passed to save_vcenter is not valid.")
				raise VMwareSetupError(status="500", message="VC stanza name passed to save_vcenter is not valid.")

		else:
			logger.info("No name passed to save_vcenter, will use vc instead")
			name = vc
		username = kwargs.get("username", False)
		if username:
			validated_vc_username = re.search("[\r\n\t]", username)
			if validated_vc_username is not None:
				logger.error("VC username passed to save_vcenter is not valid.")
				raise VMwareSetupError(status="500", message="VC username passed to save_vcenter is not valid.")
		else:
			logger.error("No username passed to save_vcenter, cannot save nothing!")
			raise VMwareSetupError(status="500", message="No username passed to save_vcenter, cannot save nothing!")
		password = kwargs.get("password", False)
		if not password:
			logger.info("No password passed to save_vcenter, will not edit password, unless it is recreated")
		host_whitelist = kwargs.get("host_whitelist", "")
		host_blacklist = kwargs.get("host_blacklist", "")
		vc_collect_logs = kwargs.get("vc_collect_logs","")
		
		syslog_uri = kwargs.get("syslog_uri", None)
		syslog_collect_logs = kwargs.get("collect_syslog", None)
		syslog_validation_status = kwargs.get("syslog_validation_status", None)
		
		if vc_collect_logs=="1":
			vc_collect_logsflag=True
		else:
			vc_collect_logsflag=False
		vc_splunk_uri = kwargs.get("vc_splunk_uri", None)
		vc_splunk_username = kwargs.get("vc_splunk_username", None)
		vc_splunk_password = kwargs.get("vc_splunk_password", None)
		validated_vc_splunk_uri = None
		validated_vcsplunk_username = None
		if vc_splunk_uri:
			validated_vc_splunk_uri = re.search("^\s*https?:\/\/[A-Za-z0-9\.\-_]+:\d+\/?\s*$", vc_splunk_uri)
		local_session_key = cherrypy.session["sessionKey"]
		if vc_splunk_username:
			validated_vcsplunk_username = re.search("[\r\n\t]", vc_splunk_username)
		#handle syslog stuff
		self._save_syslog_info(local_session_key, vc, syslog_uri, syslog_collect_logs, syslog_validation_status)		 
		
		#handle vc log stuff
		forwarder_stanza = TAVMwareVCenterForwarderStanza.from_name(vc, "Splunk_TA_vmware", host_path=local_host_path, session_key=local_session_key)
		if vc_splunk_uri is None or vc_splunk_username is None or validated_vc_splunk_uri is None or validated_vcsplunk_username is not None:
			logger.info("VC Splunk Forwarder URI and/or Username not passed to save_vcenter, will attempt to shut down log forwarding...")
			if forwarder_stanza:
				# Get credentials of before set it to null
				spl_stored_cred = SplunkStoredCredential.from_name(SplunkStoredCredential.build_name(forwarder_stanza.host, forwarder_stanza.user), app="Splunk_TA_vmware", owner="nobody", host_path=local_host_path, session_key=local_session_key)
				if spl_stored_cred:
					if not self._toggle_vc_inputs(forwarder_stanza.host, forwarder_stanza.user, spl_stored_cred.clear_password, vc, disable=True):
						logger.error("failed to disable the vc forwarder inputs for vc=%s", vc)
					else:
						logger.info("successfully disabled the vc forwarder inputs for vc=%s", vc)
				else:
					logger.info("No vc splunk forwarder cred found for vc=%s, cannot deactivate inputs.", vc)
				#Deactivate log forwarding here
				logger.info("Forwarder stanza exists. Updating infomation for vc=%s, creating new forwarder stanza", vc)
				forwarder_stanza.host = vc_splunk_uri
				forwarder_stanza.user = vc_splunk_username
				forwarder_stanza.vc_collect_logs = vc_collect_logsflag
				if not forwarder_stanza.passive_save():
					logger.error("problem updating the splunk forwarder stanza for vc=%s, stanza will have to be regenerated", vc)
			else:
				logger.info("No vc splunk forwarder found for vc=%s, nothing to deactivate.", vc)
		else:
			logger.info("Enabling/confirming log forwarding for vc=%s...", vc)
			spl_stored_cred = SplunkStoredCredential.from_name(SplunkStoredCredential.build_name(vc_splunk_uri, vc_splunk_username), app="Splunk_TA_vmware", owner="nobody", host_path=local_host_path, session_key=local_session_key)
			if not forwarder_stanza:
				logger.info("No stored forwarder infomation for vc=%s, creating new forwarder stanza with vc_splunk_uri=%s...", vc, vc_splunk_uri)
				forwarder_stanza = TAVMwareVCenterForwarderStanza("Splunk_TA_vmware", "nobody", vc, sessionKey=local_session_key, host_path=local_host_path)
				forwarder_stanza.host = vc_splunk_uri
				forwarder_stanza.user = vc_splunk_username
				forwarder_stanza.vc_collect_logs = vc_collect_logsflag
				if not forwarder_stanza.passive_save():
					logger.error("problem saving splunk forwarder stanza for vc=%s and vc_splunk_uri=%s, stanza will have to be regenerated", vc, vc_splunk_uri)
			else:
				logger.info("Forwarder stanza exists. Updating infomation for vc=%s, creating new forwarder stanza with vc_splunk_uri=%s...", vc, vc_splunk_uri)
				forwarder_stanza.host = vc_splunk_uri
				forwarder_stanza.user = vc_splunk_username
				forwarder_stanza.vc_collect_logs = vc_collect_logsflag
				if not forwarder_stanza.passive_save():
					logger.error("problem updating the splunk forwarder stanza for vc=%s and vc_splunk_uri=%s, stanza will have to be regenerated", vc, vc_splunk_uri)
			
			if not spl_stored_cred:
				logger.info("No stored forwarder credentials for vc=%s, creating new stored credential with vc_splunk_uri=%s...", vc, vc_splunk_uri)
				spl_stored_cred = SplunkStoredCredential("Splunk_TA_vmware", "nobody", vc_splunk_username, sessionKey=local_session_key, host_path=local_host_path)
				spl_stored_cred.realm = vc_splunk_uri
				spl_stored_cred.password = vc_splunk_password
				spl_stored_cred.username = vc_splunk_username
				if not spl_stored_cred.passive_save():
					logger.error("Failed to save vc splunk forwarder credential: realm={0} username={1}".format(vc_splunk_uri, vc_splunk_username))
			else:
				if not vc_splunk_password or spl_stored_cred.clear_password == vc_splunk_password:
					#stored password is the same as the normal/unedited we don't need to do anything special
					vc_splunk_password = spl_stored_cred.clear_password
				else:
					logger.info("Password for splunk forwarder on vc=%s with vc_splunk_uri=%s changed, updating it secure storage", vc, vc_splunk_uri)
					spl_stored_cred = SplunkStoredCredential("Splunk_TA_vmware", "nobody", username, sessionKey=local_session_key, host_path=local_host_path)
					spl_stored_cred.realm = vc_splunk_uri
					spl_stored_cred.password = vc_splunk_password
					spl_stored_cred.username = vc_splunk_username
					if not spl_stored_cred.passive_save():
						logger.error("Failed to save vc splunk forwarder credential: realm={0} username={1}".format(vc_splunk_uri, vc_splunk_username))

			if self._toggle_vc_inputs(vc_splunk_uri, vc_splunk_username, vc_splunk_password, vc, disable=False):
				logger.info("successfully enabled vc splunk forwarder inputs on vc=%s", vc)
			else:
				forwarder_stanza.addon_validation=False
				forwarder_stanza.credential_validation=False
				if not forwarder_stanza.passive_save():
					logger.error("problem updating the splunk forwarder stanza for vc=%s and vc_splunk_uri=%s, stanza will have to be regenerated", vc, vc_splunk_uri)
						
				logger.error("failed to enable vc splunk forwarder inputs on vc=%s", vc)
				
		status = 200
		#First check that the stanza exists and the vc is alone in it
		vc_stanza = TAVMwareCollectionStanza.from_name(name, "Splunk_TA_vmware", host_path=local_host_path, session_key=local_session_key)
		if not vc_stanza:
			logger.info("creating new vc stanza for stanza_name={0} vc={1}".format(name, vc))
			vc_stanza = TAVMwareCollectionStanza("Splunk_TA_vmware", "nobody", name, sessionKey=local_session_key, host_path=local_host_path)
			status = 201
			cherrypy.response.headers["Location"] = vc_stanza.get_id()
		else:
			#check that we are the only target in the stanza
			if len(vc_stanza.target) > 1:
				logger.error("Cannot GUI manage multi-target stanza, stanza_name={0}".format(name))
				raise VMwareSetupError(status="500", message="Cannot GUI manage multi-target stanza, stanza_name={0}, refresh immediately".format(name))
			if name != vc:
				logger.warning("name of vc={0} and stanza_name={1} are inconsistent, stanza will be recreated".format(vc, name))
				#Determine that a stanza does not exist under the name
				new_vc_stanza = TAVMwareCollectionStanza.from_name(vc, "Splunk_TA_vmware", host_path=local_host_path, session_key=local_session_key)
				if new_vc_stanza:
					logger.error("Stanza already exists for vc={1}, cannot repurpose stanza_name={0} for that vc or we'd have a duplicate".format(name, vc))
					raise VMwareSetupError(status="500", message="Stanza already exists for vc={1}, cannot repurpose stanza_name={0} for that vc or we'd have a duplicate".format(name, vc))
				else:
					new_vc_stanza = TAVMwareCollectionStanza("Splunk_TA_vmware", "nobody", vc, sessionKey=local_session_key, host_path=local_host_path)
					for field in vc_stanza.model_fields:
						setattr(new_vc_stanza, field, getattr(vc_stanza, field))
					if not vc_stanza.passive_delete():
						logger.error("Could not delete vc stanza with stanza_name={0} this may result in data duplicaction".format(name))
						raise VMwareSetupError(status="500", message="Stanza could not be remade for vc={1}, cannot repurpose stanza_name={0} for that vc or we'd have a duplicate".format(name, vc))
					#This usually means that the password also needs to go
					stored_cred = SplunkStoredCredential.from_name(SplunkStoredCredential.build_name(name, vc_stanza.username), app="Splunk_TA_vmware", owner="nobody", host_path=local_host_path, session_key=local_session_key)
					if stored_cred:
						if not password:
							password = stored_cred.clear_password
							logger.info("Recreating secure storage of password for vc={0}".format(vc))
						logger.info("Deleting outmoded credential")
						if not stored_cred.passive_delete():
							logger.error("Could not delete outmoded credential it may linger")
					vc_stanza = new_vc_stanza
		#Actually make the changes
		vc_stanza.target = [vc]
		if vc_stanza.username != username:
			#Need to redo the password for new username
			stored_cred = SplunkStoredCredential.from_name(SplunkStoredCredential.build_name(name, vc_stanza.username), app="Splunk_TA_vmware", owner="nobody", host_path=local_host_path, session_key=local_session_key)
			if stored_cred:
				if not password:
					password = stored_cred.clear_password
					logger.info("Recreating secure storage of password for vc={0}".format(vc))
				logger.info("Deleting outmoded credential")
				if not stored_cred.passive_delete():
					logger.error("Could not delete outmoded credential it may linger")
			vc_stanza.username = username
		if password:
			new_cred = SplunkStoredCredential("Splunk_TA_vmware", "nobody", username, sessionKey=local_session_key, host_path=local_host_path)
			new_cred.realm = vc
			new_cred.password = password
			new_cred.username = username
			if not new_cred.passive_save():
				logger.error("Failed to save credential: realm={0} username={1}".format(vc, username))
		vc_stanza.managed_host_blacklist = host_blacklist
		vc_stanza.managed_host_whitelist = host_whitelist

		vc_stanza.target_type = "vc"
		if vc_stanza.passive_save():
			cherrypy.response.status = status
		else:
			raise VMwareSetupError(status=500, message="Could not save vc_stanza={0}".format(str(vc_stanza)))
	
	@route('/:app/:action=delete_vcenter/:name')
	@expose_page(must_login=True, methods=['DELETE'])
	def delete_vcenter(self, app, action, name):
		"""
		Given the vc info, delete the vc from ta_vmware_collection.conf
		REQUEST PARAMS:
			REQUIRED:
			name - the stanza name
		RESPONSE:
			200 (deleted) or 500 (error)
		"""
		if name:
			validated_stanza_name = re.search("^[A-Za-z0-9\.\-_]+$", name)
			if validated_stanza_name is None:
				logger.error("VC stanza_name passed to delete_vcenter is not valid.")
				raise VMwareSetupError(status="500", message="VC stanza_name passed to delete_vcenter is not valid.")
		else:
			logger.error("No stanza_name passed to delete_vcenter, cannot delete nothing!")
			raise VMwareSetupError(status="500", message="No stanza name passed to delete_vcenter, cannot delete nothing!")
		local_session_key = cherrypy.session["sessionKey"]
		vc_stanza = TAVMwareCollectionStanza.from_name(name, "Splunk_TA_vmware", host_path=local_host_path, session_key=local_session_key)
		vc = vc_stanza.target[0]
		username = vc_stanza.username
		if not vc_stanza:
			logger.error("Could not find stanza for stanza_name={0} cannot delete".format(name))
			raise VMwareSetupError(status="500", message="Could not find stanza for stanza_name={0} cannot delete".format(name))
		else:
			logger.info("Deleting vc stanza_name=%s credentials for username=%s", name, vc_stanza.username)
			stored_cred = SplunkStoredCredential.from_name(SplunkStoredCredential.build_name(vc, username), app="Splunk_TA_vmware", owner="nobody", host_path=local_host_path, session_key=local_session_key)
			if not stored_cred.passive_delete():
				logger.error("Could not delete obsolete credential it may linger")
				raise VMwareSetupError(status="500", message="Failed to clear syslog configuration: {0}")
			if not vc_stanza.passive_delete():
				raise VMwareSetupError(status="500", message="Failed to delete vc collection stanza={0}".format(str(vc_stanza)))
		syslog_stanza = TAVMwareSyslogForwarderStanza.from_name(vc, "Splunk_TA_vmware", host_path=local_host_path, session_key=local_session_key)
		if not syslog_stanza:
			logger.info("Could not find syslog forwarder stanza for stanza_name={0} cannot delete one that does not exist, proceeding with credential deletion".format(name))
		else:
			logger.info("Deleting obsolete syslog_stanza={0}".format(str(syslog_stanza)))
			if not syslog_stanza.passive_delete():
				logger.error("Could not delete obsolete credential it may linger")
				raise VMwareSetupError(status="500", message="Failed to clear syslog configuration: {0}")
	
	@route('/:app/:action=save_unmanaged_host')
	@expose_page(must_login=True, methods=['POST'])
	def save_unmanaged_host(self, app, action, **kwargs):
		"""
		Given the host info, modify ta_vmware_collection.conf
		REQUEST PARAMS:
			REQUIRED:
			name - the stanza name
			host - the host's domain
			username - the username to use
			password - the password to use
		RESPONSE:
			200 (update), 201 (created) or 500 (error)
		"""
		host = kwargs.get("host", False)
		if host:
			validated_hostwhitelist = re.search("[A-Za-z0-9\.\-_]", host)
			validated_hostblacklist = re.search("[\r\n\t]", host)
			if validated_hostwhitelist is None or validated_hostblacklist is not None:
				logger.error("Host passed to save_unmanaged_host is not valid.")
				raise VMwareSetupError(status="500", message="Host passed to save_unmanaged_host is not valid.")
		else:
			logger.error("No host passed to save_unmanaged_host, cannot save nothing!")
			raise VMwareSetupError(status="500", message="No host name passed to save_unmanaged_host, cannot save nothing!")

		name = kwargs.get("name", host)
		if name:
			validated_namewhitelist = re.search("[A-Za-z0-9\.\-_]", name)
			validated_nameblacklist = re.search("[\r\n\t]", name)
			if validated_namewhitelist is None or validated_nameblacklist is not None:
				logger.error("Host stanza passed to save_unmanaged_host is not valid.")
				raise VMwareSetupError(status="500", message="Host stanza passed to save_unmanaged_host is not valid.")
		else:
			logger.info("No name passed to save_unmanaged, will use vc instead")
			name = host
		username = kwargs.get("username", False)
		if username:
			validated_username = re.search("[\r\n\t]", username)
			if validated_username is not None:
				logger.error("Username passed to save_unmanaged is not valid.")
				raise VMwareSetupError(status="500", message="Username passed to save_unmanaged is not valid.")
		else:
			logger.error("No username passed to save_unmanaged, cannot save nothing!")
			raise VMwareSetupError(status="500", message="No username passed to save_unmanaged, cannot save nothing!")
		password = kwargs.get("password", False)
		if not password:
			logger.info("No password passed to save_unamanged, will not edit password, unless it is recreated")
		local_session_key = cherrypy.session["sessionKey"]
		status = 200
		#First check that the stanza exists and the vc is alone in it
		host_stanza = TAVMwareCollectionStanza.from_name(name, "Splunk_TA_vmware", host_path=local_host_path, session_key=local_session_key)
		if not host_stanza:
			logger.info("creating new unmanaged host stanza for stanza_name={0} vc={1}".format(name, host))
			host_stanza = TAVMwareCollectionStanza("Splunk_TA_vmware", "nobody", name, sessionKey=local_session_key, host_path=local_host_path)
			status = 201
			cherrypy.response.headers["Location"] = host_stanza.get_id()
		else:
			#check that we are the only target in the stanza
			if len(host_stanza.target) > 1:
				logger.error("Cannot GUI manage multi-target stanza, stanza_name={0}".format(name))
				raise VMwareSetupError(status="500", message="Cannot GUI manage multi-target stanza, stanza_name={0}, refresh immediately".format(name))
			if name != host:
				logger.warning("name of host={0} and stanza_name={1} are inconsistent, stanza will be recreated".format(host, name))
				#Determine that a stanza does not exist under the name
				new_host_stanza = TAVMwareCollectionStanza.from_name(host, "Splunk_TA_vmware", host_path=local_host_path, session_key=local_session_key)
				if new_host_stanza:
					logger.error("Stanza already exists for host={1}, cannot repurpose stanza_name={0} for that host or we'd have a duplicate".format(name, host))
					raise VMwareSetupError(status="500", message="Stanza already exists for host={1}, cannot repurpose stanza_name={0} for that host or we'd have a duplicate".format(name, host))
				else:
					new_host_stanza = TAVMwareCollectionStanza("Splunk_TA_vmware", "nobody", host, sessionKey=local_session_key, host_path=local_host_path)
					for field in host_stanza.model_fields:
						setattr(new_host_stanza, field, getattr(host_stanza, field))
					if not host_stanza.passive_delete():
						logger.error("Could not delete host stanza with stanza_name={0} this may result in data duplicaction".format(name))
						raise VMwareSetupError(status="500", message="Stanza could not be remade for host={1}, cannot repurpose stanza_name={0} for that vc or we'd have a duplicate".format(name, host))
					#This usually means that the password also needs to go
					stored_cred = SplunkStoredCredential.from_name(SplunkStoredCredential.build_name(name, host_stanza.username), app="Splunk_TA_vmware", owner="nobody", host_path=local_host_path, session_key=local_session_key)
					if stored_cred:
						if not password:
							password = stored_cred.clear_password
							logger.info("Recreating secure storage of password for host={0}".format(host))
						logger.info("Deleting outmoded credential")
						if not stored_cred.passive_delete():
							logger.error("Could not delete outmoded credential it may linger")
					host_stanza = new_host_stanza
		#Actually make the changes
		host_stanza.target = [host]
		if host_stanza.username != username:
			#Need to redo the password for new username
			stored_cred = SplunkStoredCredential.from_name(SplunkStoredCredential.build_name(name, host_stanza.username), app="Splunk_TA_vmware", owner="nobody", host_path=local_host_path, session_key=local_session_key)
			if stored_cred:
				if not password:
					password = stored_cred.clear_password
					logger.info("Recreating secure storage of password for host={0}".format(host))
				logger.info("Deleting outmoded credential")
				if not stored_cred.passive_delete():
					logger.error("Could not delete outmoded credential it may linger")
			host_stanza.username = username
		if password:
			new_cred = SplunkStoredCredential("Splunk_TA_vmware", "nobody", username, sessionKey=local_session_key, host_path=local_host_path)
			new_cred.realm = host
			new_cred.password = password
			new_cred.username = username
			if not new_cred.passive_save():
				logger.error("Failed to save credential: realm={0} username={1}".format(host, username))
		host_stanza.target_type = "unmanaged"
		if host_stanza.passive_save():
			cherrypy.response.status = status
		else:
			raise VMwareSetupError(status=500, message="Could not save host_stanza={0}".format(str(host_stanza)))
		
	
	@route('/:app/:action=delete_unmanaged_host/:name')
	@expose_page(must_login=True, methods=['DELETE'])
	def delete_unmanaged_host(self, app, action, name):
		"""
		Given the vc info, delete the vc from ta_vmware_collection.conf
		REQUEST PARAMS:
			REQUIRED:
			name - the stanza name
			host - the host's domain
		RESPONSE:
			200 (deleted) or 500 (error)
		"""
		if name:
			validated_namewhitelist = re.search("[A-Za-z0-9\.\-_]", name)
			validated_nameblacklist = re.search("[\r\n\t]", name)
			if validated_namewhitelist is None or validated_nameblacklist is not None:
				logger.error("Stanza_name passed to delete_unmanaged_host is not valid.")
				raise VMwareSetupError(status="500", message="Stanza_name passed to delete_unmanaged_host is not valid.")

		else:
			logger.error("No stanza_name passed to delete_unmanaged_host, cannot delete nothing!")
			raise VMwareSetupError(status="500", message="No stanza name passed to delete_unmanaged_host, cannot delete nothing!")
		local_session_key = cherrypy.session["sessionKey"]
		host_stanza = TAVMwareCollectionStanza.from_name(name, "Splunk_TA_vmware", host_path=local_host_path, session_key=local_session_key)
		if not host_stanza:
			logger.error("Could not find stanza for stanza_name={0} cannot delete".format(name))
			raise VMwareSetupError(status="500", message="Could not find stanza for stanza_name={0} cannot delete".format(name))
		else:
			logger.info("Deleting vc stanza_name=%s credentials for username=%s", name, host_stanza.username)
			stored_cred = SplunkStoredCredential.from_name(SplunkStoredCredential.build_name(host_stanza.target[0], host_stanza.username), app="Splunk_TA_vmware", owner="nobody", host_path=local_host_path, session_key=local_session_key)
			if stored_cred:
				logger.info("Deleting obsolete credential")
				if not stored_cred.passive_delete():
					logger.error("Could not delete obsolete credential it may linger")
			if not host_stanza.passive_delete():
				raise VMwareSetupError(status="500", message="Failed to delete vc collection stanza={0}".format(str(host_stanza)))
	
	#===========================================================================
	# UTILITY METHODS
	#===========================================================================
	def _get_full_conf_data(self):
		"""
		Get the conf data and return it as a dict
		"""
		conf_data = {}
		user = cherrypy.session['user']['name']
		local_session_key = cherrypy.session['sessionKey']
		logger.debug("user=%s requested collection configuration page", user)
		
		# Get the Collection Scheduler Stanza
		

		configured_heads = en.getEntities("/data/inputs/ta_vmware_collection_scheduler/puff", "Splunk_TA_vmware", "nobody", sessionKey=local_session_key, hostPath=local_host_path)
		logger.info("Configure heads {0} ".format(configured_heads))
		for head_name, config in configured_heads.iteritems():
			conf_data["isSchedulerDisabled"] = util.normalizeBoolean(config.get("disabled"))

		#Get all nodes
		stanzas = HydraNodeStanza.all(sessionKey=local_session_key)
		stanzas = stanzas.filter_by_app("Splunk_TA_vmware")
		stanzas._owner = "nobody"
		nodes = [{"host_path": stanza.host, "username": stanza.user, "credential_validation": stanza.credential_validation, "addon_validation": stanza.addon_validation, "heads": stanza.heads} for stanza in stanzas]
		conf_data["nodes"] = nodes
		
		#Get all vc and unamanged host
		stanzas = TAVMwareCollectionStanza.all(sessionKey=local_session_key)
		stanzas = stanzas.filter_by_app("Splunk_TA_vmware")
		stanzas._owner = "nobody"
		vcenters = []
		unmanaged_hosts = []
		parse_errors = []
		for stanza in stanzas:
			if stanza.target_type == "vc":
				if len(stanza.target) != 1:
					logger.error("Multiple targets for stanza={0} in ta_vmware_collection.conf, this stanza will be ignored for GUI purposes. full_stanza='{1}'".format(stanza.name, str(stanza)))
					parse_errors.append({"stanza_name":stanza.name, "error": "Cannot manage multi-target stanza via GUI"})
				else:
					tmp = {}
					tmp["target"] = stanza.target[0]
					tmp["managed_host_blacklist"] = stanza.managed_host_blacklist
					tmp["managed_host_whitelist"] = stanza.managed_host_whitelist
					tmp["credential_validation"] = stanza.credential_validation
					tmp["username"] = stanza.username
					tmp["stanza_name"] = stanza.name

					forwarder_stanza = TAVMwareVCenterForwarderStanza.from_name(stanza.target[0], "Splunk_TA_vmware", "nobody", session_key=local_session_key, host_path=local_host_path)
					syslog_stanza = TAVMwareSyslogForwarderStanza.from_name(stanza.target[0], "Splunk_TA_vmware", "nobody", session_key=local_session_key, host_path=local_host_path)
					if forwarder_stanza:
						tmp["vc_collect_logs"] = forwarder_stanza.vc_collect_logs
						if forwarder_stanza.vc_collect_logs:
							tmp["forwarder_uri"] = forwarder_stanza.host
							tmp["forwarder_username"] = forwarder_stanza.user
							tmp["forwarder_credential_validation"] = forwarder_stanza.credential_validation
							tmp["forwarder_addon_validation"] = forwarder_stanza.addon_validation
					else:
						tmp["vc_collect_logs"] = 0
						tmp["forwarder_uri"] = ""
						tmp["forwarder_username"] = ""
						tmp["forwarder_credential_validation"] = ""
						tmp["forwarder_addon_validation"] = ""							
					if syslog_stanza:
						tmp["syslog_uri"] = syslog_stanza.uri or ""
						tmp["syslog_collect_logs"] = syslog_stanza.status or 0
						tmp["syslog_validation_status"] = syslog_stanza.validation_status or 0
						tmp["syslog_config_status_msg"] = syslog_stanza.config_status_msg or ""
					else:
						tmp["syslog_uri"] = ""
						tmp["syslog_collect_logs"] = 0 
						tmp["syslog_validation_status"] = 0
						tmp[syslog_cofig_status_msg] = ""
					vcenters.append(tmp)
			elif stanza.target_type == "unmanaged":
				if len(stanza.target) != 1:
					logger.error("Multiple targets for stanza={0} in ta_vmware_collection.conf, this stanza will be ignored for GUI purposes. full_stanza='{1}'".format(stanza.name, str(stanza)))
					parse_errors.append({"stanza_name":stanza.name, "error": "Cannot manage multi-target stanza via GUI"})
				else:
					tmp = {}
					tmp["target"] = stanza.target[0]
					tmp["username"] = stanza.username
					tmp["credential_validation"] = stanza.credential_validation
					tmp["stanza_name"] = stanza.name
					unmanaged_hosts.append(tmp)
			else:
				logger.error("Unknown target_type={0} for stanza={1} in ta_vmware_collection.conf, this stanza will be ignored for GUI purposes. full_stanza='{2}'".format(stanza.target_type, stanza.name, str(stanza)))
				parse_errors.append({"stanza_name":stanza.name, "error": "Could not establish target type for stanza"})
		conf_data["vcenters"] = vcenters
		conf_data["unmanaged_hosts"] = unmanaged_hosts
		conf_data["parse_errors"] = parse_errors
		
		return conf_data
	
	def _toggle_vc_inputs(self, host_path, username, password, vc, disable=True):
		"""
		toggle on or off all of the inputs in Splunk TA vCenter, default is disable
		
		RETURNS nothing
		"""
		status = True
		try:
			remote_session_key = getRemoteSessionKey(username, password, host_path)
		except ServerNotFoundError:
			logger.error("Could not find vc_splunk_forwarder=%s", host_path)
			remote_session_key = None
		except splunk.SplunkdConnectionException:
			logger.error("Could not find splunkd on vc_splunk_forwarder=%s", host_path)
			remote_session_key = None
		except splunk.AuthenticationFailed:
			logger.error("Could not log into splunkd on vc_splunk_forwarder=%s, credentials are definitely bad", host_path)
			remote_session_key = None
		except Exception:
			remote_session_key = None
		if remote_session_key is None:
			logger.error("Could not log into vc_splunk_forwarder=%s with the credentials provided, cannot manage the inputs on that instance", host_path)
			status = False
		else:
			input_uris = ["/servicesNS/nobody/Splunk_TA_vcenter/data/inputs/monitor/%24ALLUSERSPROFILE%5CApplication%20Data%5CVMware%5CVMware%20VirtualCenter%5CLogs",
						"/servicesNS/nobody/Splunk_TA_vcenter/data/inputs/monitor/%24PROGRAMFILES%5CVMware%5CInfrastructure%5Ctomcat%5Clogs"]
			for uri in input_uris:
				path = host_path.rstrip("/") + uri
				if disable:
					postargs = {"host": vc}
					action = "disable"
				else:
					postargs = {"host": vc}
					action = "enable"
				try:
					logger.info("Adjusting input with rest request on path=% with postargs=%s and secondary action=%s", path, postargs, action)
					splunk_rest_request(path, sessionKey=remote_session_key, method="POST", postargs=postargs, raiseAllErrors=True)
					path = path + "/" + action
					splunk_rest_request(path, sessionKey=remote_session_key, method="POST", raiseAllErrors=True)
				except ServerNotFoundError:
					logger.exception("Could not reach vc_splunk_forwarder={0}", host_path)
					status = False
				except Exception as e:
					message = "Problem editing inputs on the remote vc_splunk_forwarder={0}: ".format(host_path) + e.message
					logger.exception(message)
					status = False
		return status
