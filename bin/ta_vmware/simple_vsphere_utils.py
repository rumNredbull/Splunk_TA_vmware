#Copyright (C) 2005-2017 Splunk Inc. All Rights Reserved.
import urllib2
import cookielib
from xml.dom import minidom
from xml.sax.saxutils import escape, quoteattr

class ConnectionFailure(Exception):
	def __init__(self, reason="Could not connect and retrieve service instance. ", server=None):
		if server is not None:
			reason = reason + "For vSphere server: " + str(server)
		self.args = reason
		self.reason = reason
	def __str__(self):
		return repr(self.reason)

class LoginFailure(Exception):
	def __init__(self, reason="Could not login with provided credentials. ", server=None):
		if server is not None:
			reason = reason + "For vSphere server: " + str(server)
		self.args = reason
		self.reason = reason
	def __str__(self):
		return repr(self.reason)

class vSphereService(object):
	"""
	Very simple utilities for interacting with vSphere without parsing wsdl
	"""
	def __init__(self, url, username=None, password=None, sessionkey=None, domain=None):
		"""
		Service object exists for managing versions and such cleanly
		ARGS:
			url - the vsphere service provider url/domain
			username - the login username to use
			password - the login password to use
		"""
		self.service_url = self._make_vsphere_uri(url)
		if sessionkey:
			service_info = self._get_service_instance(sessionkey=sessionkey, domain=domain)
		else:
			service_info = self._get_service_instance()
		if service_info == False:
			raise ConnectionFailure(server=self.service_url)
		else:
			self.opener, self.version = service_info
			if self.version == "5.x":
				self.headers = {'SOAPAction': u'"urn:vim25/5.1"', 'Soapaction': u'"urn:vim25/5.1"', 'Content-Type': 'text/xml; charset=utf-8', 'Content-type': 'text/xml; charset=utf-8'}
			else:
				self.headers = {'SOAPAction': u'"urn:vim25/4.1"', 'Soapaction': u'"urn:vim25/4.1"', 'Content-Type': 'text/xml; charset=utf-8', 'Content-type': 'text/xml; charset=utf-8'}
		if sessionkey is None and not self._login(username, password):
			raise LoginFailure(server=self.service_url)

	def create_session_cookie(self, domain, value, version=0, name='vmware_soap_session',
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

	def _make_vsphere_uri(self, domain):
		"""
		Give it a domain or a url and returns one that looks like https://domain/sdk
		"""
		if not domain.startswith("https://") and not domain.startswith("http://"):
			domain = "https://" + domain
		if not domain.endswith("/sdk") and not domain.endswith("/sdk/"):
			if domain.endswith("/"):
				domain = domain + "sdk"
			else:
				domain = domain + "/sdk"
		return domain
	
	def _get_service_instance(self, url=None, sessionkey=None, domain=None):
		"""
		quick and dirty request to check creds on a vc
		ARGS:
			url - the url to try to auth to, e.g. https://my-vc.splunk.com/sdk
			
		RETURNS opener for future requests
		"""
		if url is None:
			url = self.service_url
		
		cj = cookielib.LWPCookieJar()

		if sessionkey is not None:
			cookie = self.create_session_cookie(domain, value=sessionkey)
			cj.set_cookie(cookie)

		#this opener is used for all requests to ensure that cookies are handled properly
		opener = urllib2.build_opener(urllib2.HTTPCookieProcessor(cj))
		#First we assume the server is 5.x
		request_body = """<?xml version="1.0" encoding="UTF-8"?>
			<SOAP-ENV:Envelope xmlns:ns0="http://schemas.xmlsoap.org/soap/envelope/" xmlns:ns1="urn:vim25" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:SOAP-ENV="http://schemas.xmlsoap.org/soap/envelope/">
			<SOAP-ENV:Header/>
			  <ns0:Body>
				<ns1:RetrieveServiceContent>
				<ns1:_this xsi:type="ServiceInstance">ServiceInstance</ns1:_this>
				</ns1:RetrieveServiceContent>
			  </ns0:Body>
			</SOAP-ENV:Envelope>
			"""
		request = urllib2.Request(url, data=request_body)
		success = True
		try:
			handle = opener.open(request, timeout=15)
			if handle.code != 200:
				success = False
			else:
				version = "5.x"
		except:
			success = False
		
		if not success:
			#Now we try as if it were 4.1
			request_body = """<?xml version="1.0" encoding="UTF-8"?>
				<SOAP-ENV:Envelope xmlns:ns0="http://schemas.xmlsoap.org/soap/envelope/" xmlns:ns1="urn:vim25" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:SOAP-ENV="http://schemas.xmlsoap.org/soap/envelope/">
				<SOAP-ENV:Header/>
				  <ns0:Body>
					<ns1:RetrieveServiceContent>
					<ns1:_this type="ServiceInstance">ServiceInstance</ns1:_this>
					</ns1:RetrieveServiceContent>
				  </ns0:Body>
				</SOAP-ENV:Envelope>
				"""
			request = urllib2.Request(url, data=request_body)
			try:
				handle = opener.open(request, timeout=15)
				if handle.code != 200:
					return False
				else:
					version = "4.1"
			except:
				return False
		
		#Determine if we are an unmanaged host by inspecting the service instance
		service_instance_xml = handle.read()
		service_instance_dom = minidom.parseString(service_instance_xml)
		session_manager_node = service_instance_dom.getElementsByTagName("sessionManager")[0]
		self.session_manager_moid = session_manager_node.firstChild.data
		
		return opener, version
	
	def _login(self, username, password):
		"""
		quick and dirty request to check creds on a vc
		ARGS:
			username - username to use
			password - password to use
		
		RETURNS True if successful, False
		"""
		request_body = """<?xml version="1.0" encoding="UTF-8"?>
			<SOAP-ENV:Envelope xmlns:ns0="http://schemas.xmlsoap.org/soap/envelope/" xmlns:ns1="urn:vim25" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:SOAP-ENV="http://schemas.xmlsoap.org/soap/envelope/">
			  <SOAP-ENV:Header/>
			  <ns0:Body>
				 <ns1:Login>
					<ns1:_this type="SessionManager">""" + escape(self.session_manager_moid) + """</ns1:_this>
					<ns1:userName>""" + escape(username) + """</ns1:userName>
					<ns1:password>""" + escape(password) + """</ns1:password>
				 </ns1:Login>
			  </ns0:Body>
			</SOAP-ENV:Envelope>
			"""
		request = urllib2.Request(self.service_url, data=request_body, headers=self.headers)
		try:
			handle = self.opener.open(request)
			if handle.code == 200:
				return True
			else:
				return False
		except urllib2.HTTPError:
			return False
	
	def logout(self):
		"""
		Quick and dirty way to log out of the service instance
		
		RETURNS True if successful, False if not
		"""
		request_body = """<?xml version="1.0" encoding="UTF-8"?>
			<SOAP-ENV:Envelope xmlns:ns0="urn:vim25" xmlns:ns1="http://schemas.xmlsoap.org/soap/envelope/" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:SOAP-ENV="http://schemas.xmlsoap.org/soap/envelope/">
			   <SOAP-ENV:Header/>
			   <ns1:Body>
			      <ns0:Logout>
			         <ns0:_this type="SessionManager">""" + escape(self.session_manager_moid) + """</ns0:_this>
			      </ns0:Logout>
			   </ns1:Body>
			</SOAP-ENV:Envelope>
			"""
		request = urllib2.Request(self.service_url, data=request_body, headers=self.headers)
		try:
			handle = self.opener.open(request)
			if handle.code == 200:
				return True
			else:
				return False
		except urllib2.HTTPError:
			return False
	
	def get_host_list(self, exclude_disconnected=True):
		"""
		quick and dirty request to get a list of hosts from a vcenter
		ARGS:
			exclude_disconnected - if true will not return hosts not actively connected to the vc
		
		RETURNS list of hosts if successful, empty list if not
		"""
		try:
			request_body = """<?xml version="1.0" encoding="UTF-8"?>
			<SOAP-ENV:Envelope xmlns:SOAP-ENV="http://schemas.xmlsoap.org/soap/envelope/" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:ns1="urn:vim25" xmlns:ns0="http://schemas.xmlsoap.org/soap/envelope/">
			<SOAP-ENV:Header/>
			<ns0:Body>
			    <ns1:RetrieveProperties>
			        <ns1:_this type="PropertyCollector">propertyCollector</ns1:_this>
			        <ns1:specSet xsi:type="ns1:PropertyFilterSpec">
			            <ns1:propSet>
			                <ns1:type>HostSystem</ns1:type>
			                <ns1:all>false</ns1:all>
			                <ns1:pathSet>name</ns1:pathSet>
			            </ns1:propSet>
			            <ns1:propSet>
							<ns1:type>HostSystem</ns1:type>
							<ns1:pathSet>summary.runtime.connectionState</ns1:pathSet>
						</ns1:propSet>
						<ns1:propSet>
							<ns1:type>HostSystem</ns1:type>
							<ns1:pathSet>summary.runtime.powerState</ns1:pathSet>
						</ns1:propSet>
						<ns1:propSet>
							<ns1:type>HostSystem</ns1:type>
							<ns1:pathSet>config.product.name</ns1:pathSet>
						</ns1:propSet>
						<ns1:propSet>
							<ns1:type>HostSystem</ns1:type>
							<ns1:pathSet>config.product.version</ns1:pathSet>
						</ns1:propSet>
			            <ns1:objectSet>
			                <ns1:obj type="Folder">group-d1</ns1:obj>
			                <ns1:skip>false</ns1:skip>
			                <ns1:selectSet xsi:type="ns1:TraversalSpec">
			                    <ns1:name>visitFolders</ns1:name>
			                    <ns1:type>Folder</ns1:type>
			                    <ns1:path>childEntity</ns1:path>
			                    <ns1:skip>false</ns1:skip>
			                    <ns1:selectSet>
			                        <ns1:name>visitFolders</ns1:name>
			                    </ns1:selectSet>
			                    <ns1:selectSet>
			                        <ns1:name>dcToHf</ns1:name>
			                    </ns1:selectSet>
			                    <ns1:selectSet>
			                        <ns1:name>dcToVmf</ns1:name>
			                    </ns1:selectSet>
			                    <ns1:selectSet>
			                        <ns1:name>dcToDs</ns1:name>
			                    </ns1:selectSet>
			                    <ns1:selectSet>
			                        <ns1:name>dcToNetf</ns1:name>
			                    </ns1:selectSet>
			                    <ns1:selectSet>
			                        <ns1:name>crToH</ns1:name>
			                    </ns1:selectSet>
			                    <ns1:selectSet>
			                        <ns1:name>crToRp</ns1:name>
			                    </ns1:selectSet>
			                    <ns1:selectSet>
			                        <ns1:name>HToVm</ns1:name>
			                    </ns1:selectSet>
			                    <ns1:selectSet>
			                        <ns1:name>rpToVm</ns1:name>
			                    </ns1:selectSet>
			                </ns1:selectSet>
			                <ns1:selectSet xsi:type="ns1:TraversalSpec">
			                    <ns1:name>dcToDs</ns1:name>
			                    <ns1:type>Datacenter</ns1:type>
			                    <ns1:path>datastoreFolder</ns1:path>
			                    <ns1:skip>false</ns1:skip>
			                    <ns1:selectSet>
			                        <ns1:name>visitFolders</ns1:name>
			                    </ns1:selectSet>
			                </ns1:selectSet>
			                <ns1:selectSet xsi:type="ns1:TraversalSpec">
			                    <ns1:name>dcToNetf</ns1:name>
			                    <ns1:type>Datacenter</ns1:type>
			                    <ns1:path>networkFolder</ns1:path>
			                    <ns1:skip>false</ns1:skip>
			                    <ns1:selectSet>
			                        <ns1:name>visitFolders</ns1:name>
			                    </ns1:selectSet>
			                </ns1:selectSet>
			                <ns1:selectSet xsi:type="ns1:TraversalSpec">
			                    <ns1:name>vAppToRp</ns1:name>
			                    <ns1:type>VirtualApp</ns1:type>
			                    <ns1:path>resourcePool</ns1:path>
			                    <ns1:skip>false</ns1:skip>
			                    <ns1:selectSet>
			                        <ns1:name>rpToRp</ns1:name>
			                    </ns1:selectSet>
			                    <ns1:selectSet>
			                        <ns1:name>vAppToRp</ns1:name>
			                    </ns1:selectSet>
			                </ns1:selectSet>
			                <ns1:selectSet xsi:type="ns1:TraversalSpec">
			                    <ns1:name>dcToVmf</ns1:name>
			                    <ns1:type>Datacenter</ns1:type>
			                    <ns1:path>vmFolder</ns1:path>
			                    <ns1:skip>false</ns1:skip>
			                    <ns1:selectSet>
			                        <ns1:name>visitFolders</ns1:name>
			                    </ns1:selectSet>
			                </ns1:selectSet>
			                <ns1:selectSet xsi:type="ns1:TraversalSpec">
			                    <ns1:name>dcToHf</ns1:name>
			                    <ns1:type>Datacenter</ns1:type>
			                    <ns1:path>hostFolder</ns1:path>
			                    <ns1:skip>false</ns1:skip>
			                    <ns1:selectSet>
			                        <ns1:name>visitFolders</ns1:name>
			                    </ns1:selectSet>
			                </ns1:selectSet>
			                <ns1:selectSet xsi:type="ns1:TraversalSpec">
			                    <ns1:name>crToH</ns1:name>
			                    <ns1:type>ComputeResource</ns1:type>
			                    <ns1:path>host</ns1:path>
			                    <ns1:skip>false</ns1:skip>
			                </ns1:selectSet>
			                <ns1:selectSet xsi:type="ns1:TraversalSpec">
			                    <ns1:name>crToRp</ns1:name>
			                    <ns1:type>ComputeResource</ns1:type>
			                    <ns1:path>resourcePool</ns1:path>
			                    <ns1:skip>false</ns1:skip>
			                    <ns1:selectSet>
			                        <ns1:name>rpToRp</ns1:name>
			                    </ns1:selectSet>
			                    <ns1:selectSet>
			                        <ns1:name>rpToVm</ns1:name>
			                    </ns1:selectSet>
			                </ns1:selectSet>
			                <ns1:selectSet xsi:type="ns1:TraversalSpec">
			                    <ns1:name>rpToRp</ns1:name>
			                    <ns1:type>ResourcePool</ns1:type>
			                    <ns1:path>resourcePool</ns1:path>
			                    <ns1:skip>false</ns1:skip>
			                    <ns1:selectSet>
			                        <ns1:name>rpToRp</ns1:name>
			                    </ns1:selectSet>
			                    <ns1:selectSet>
			                        <ns1:name>rpToVm</ns1:name>
			                    </ns1:selectSet>
			                </ns1:selectSet>
			                <ns1:selectSet xsi:type="ns1:TraversalSpec">
			                    <ns1:name>HToVm</ns1:name>
			                    <ns1:type>HostSystem</ns1:type>
			                    <ns1:path>vm</ns1:path>
			                    <ns1:skip>false</ns1:skip>
			                    <ns1:selectSet>
			                        <ns1:name>visitFolders</ns1:name>
			                    </ns1:selectSet>
			                </ns1:selectSet>
			                <ns1:selectSet xsi:type="ns1:TraversalSpec">
			                    <ns1:name>rpToVm</ns1:name>
			                    <ns1:type>ResourcePool</ns1:type>
			                    <ns1:path>vm</ns1:path>
			                    <ns1:skip>false</ns1:skip>
			                </ns1:selectSet>
			            </ns1:objectSet>
			        </ns1:specSet>
			    </ns1:RetrieveProperties>
			</ns0:Body>
			</SOAP-ENV:Envelope>
			"""
			request = urllib2.Request(self.service_url, data=request_body, headers=self.headers)
			handle = self.opener.open(request)
			resp_xml = minidom.parseString(handle.read())
			#Really assuming that the xml is all good here
			hosts = []
			for returnval in resp_xml.getElementsByTagName("returnval"):
				try:
					tmp = {}
					tmp["moid"] = returnval.getElementsByTagName("obj")[0].firstChild.data
					for propset in returnval.getElementsByTagName("propSet"):
						name = propset.getElementsByTagName("name")[0].firstChild.data
						val = propset.getElementsByTagName("val")[0].firstChild.data
						tmp[name] = val
					if exclude_disconnected:
						if tmp["summary.runtime.connectionState"] == "connected":
							hosts.append(tmp)
					else:
						hosts.append(tmp)
				except AttributeError:
					#Skipping the host which has one or more properties which has no value
					pass
				except Exception:
					#Skipping bad hosts
					pass
			return hosts
		except urllib2.HTTPError:
			return []
	
	def _send_envelope(self, request_body):
		"""
		send the given envelope to the server
		"""
		try:
			request = urllib2.Request(self.service_url, data=request_body, headers=self.headers)
			handle = self.opener.open(request)
			return handle.read()
		except urllib2.HTTPError:
			return ""

	def retrieve_Properties(self, host_moid, obj_type="HostSystem", pathSet="configManager"):
		'''
			Get provided host (moid) configManager values
			
			ARGS :
			 host_moid : host moid
			
			Return :
			  List of configurations if successful
			  otherwise empty list
		'''
		try:
			request_body = """<?xml version="1.0" encoding="UTF-8"?>
				<SOAP-ENV:Envelope xmlns:ns0="urn:vim25" xmlns:ns1="http://schemas.xmlsoap.org/soap/envelope/" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:SOAP-ENV="http://schemas.xmlsoap.org/soap/envelope/">
				   <SOAP-ENV:Header/>
				   <ns1:Body>
				      <ns0:RetrieveProperties>
				         <ns0:_this type="PropertyCollector">propertyCollector</ns0:_this>
				         <ns0:specSet>
				            <ns0:propSet>
				              <ns0:type>""" + escape(obj_type) + """</ns0:type>
				              <ns0:pathSet>""" + escape(pathSet) + """</ns0:pathSet>
				            </ns0:propSet>
				            <ns0:objectSet>
				                <ns0:obj type=""" + quoteattr(obj_type) + """>""" + escape(host_moid) + """</ns0:obj>
				                <ns0:skip>false</ns0:skip>
				            </ns0:objectSet>
				         </ns0:specSet>
				     </ns0:RetrieveProperties>
				   </ns1:Body>
				</SOAP-ENV:Envelope>
				"""
			request = urllib2.Request(self.service_url, data=request_body, headers=self.headers)
			handle = self.opener.open(request)
			resp_xml = minidom.parseString(handle.read())
			retVal = []
			for returnval in resp_xml.getElementsByTagName("returnval"):
				obj_spec = returnval.getElementsByTagName("obj")[0]
				response_data = {}
				obj_type = obj_spec.getAttribute('type')
				response_data[obj_type] = obj_spec.firstChild.data
				# propset
				for propset in returnval.getElementsByTagName("propSet"):
					propset_key = propset.getElementsByTagName("name")[0].firstChild.data
					propset_val_obj = propset.getElementsByTagName("val")[0]
					propset_val = []
					if obj_type == 'HostSystem':
						for element in propset_val_obj.childNodes:
							tmpDict = {}
							k = element.getAttribute("type")
							if element.firstChild.data is not None: 
								tmpDict[k] = element.firstChild.data
							else :
								tmpDict[k] = ""
							propset_val.append(tmpDict)
					elif obj_type == 'HostFirewallSystem':
						# get Default policy
						propset_val = self._get_host_firewallInfo(propset_val_obj)
					else :
						# Add parser as for prop val as per type of data
						pass
					response_data[propset_key] = propset_val
					retVal.append(response_data)
			return retVal
		except urllib2.HTTPError:
			return []

	def _get_host_firewallInfo(self, val_obj):
		firewall_info = {}
		# get Default values
		default_obj = val_obj.getElementsByTagName("defaultPolicy")
		if default_obj is not None:
			# Only on default value exists
			default_obj = default_obj[0]
			default_obj_val = {}
			for obj in default_obj.childNodes :
				if obj.firstChild.nodeType == obj.TEXT_NODE:
					default_obj_val[obj.tagName] = obj.firstChild.data
			firewall_info[default_obj.tagName] = default_obj_val
		# get rulesets
		ruleset_list = []
		for ruleset in val_obj.getElementsByTagName("ruleset"):
			# get rules
			ruleset_dict = {}
			rules_list = []
			for rule in ruleset.getElementsByTagName("rule"):
				rule_dict = {}
				for child in rule.childNodes :
					if child.firstChild.nodeType == child.TEXT_NODE:
						rule_dict[child.tagName] = child.firstChild.data
				rules_list.append(rule_dict)
			ruleset_dict['rule'] = rules_list
			# Other properties
			for prop_obj in ruleset.childNodes:
				if prop_obj.tagName == "rule":
					continue
				if prop_obj.firstChild.nodeType == prop_obj.TEXT_NODE:
					ruleset_dict[prop_obj.tagName] = prop_obj.firstChild.data
				else :
					ruleset_dict[prop_obj.tagName] = self._get_xml_node_info(prop_obj.childNodes)
			ruleset_list.append(ruleset_dict)
		firewall_info['ruleset'] = ruleset_list
		return firewall_info

	def _get_xml_node_info(self, list_obj):
		tempDict = {}
		for node in list_obj :
			if node.firstChild.nodeType == node.TEXT_NODE:
				tempDict[node.tagName] = node.firstChild.data
			else :
				tempDict[node.tagName] = self._get_xml_node_info(node.childNodes)
		return tempDict

	def query_options(self, config_manager_id, prop_name):
		'''
			Query option on provide config_manager
			
		'''
		try:
			request_body = """<?xml version="1.0" encoding="UTF-8"?>
				<SOAP-ENV:Envelope xmlns:ns0="urn:vim25" xmlns:ns1="http://schemas.xmlsoap.org/soap/envelope/" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:SOAP-ENV="http://schemas.xmlsoap.org/soap/envelope/">
				   <SOAP-ENV:Header/>
				   <ns1:Body>
				      <ns0:QueryOptions>
				         <ns0:_this type="OptionManager">""" + escape(config_manager_id) + """</ns0:_this>
				         <ns0:name>""" + escape(prop_name) + """</ns0:name>
				      </ns0:QueryOptions>
				   </ns1:Body>
				</SOAP-ENV:Envelope>
				"""
			retVal = []
			request = urllib2.Request(self.service_url, data=request_body, headers=self.headers)
			handle = self.opener.open(request)
			resp_xml = minidom.parseString(handle.read())
			for returnval in resp_xml.getElementsByTagName("returnval"):
				temp = {}
				key = returnval.getElementsByTagName("key")[0].firstChild.data
				# value can be empty
				if returnval.getElementsByTagName("value")[0].firstChild is not None:
					val = returnval.getElementsByTagName("value")[0].firstChild.data
				else :
					val = ""
				temp[key] = val
				retVal.append(temp)
			return retVal
		except urllib2.HTTPError:
			return None

	def update_options(self, config_manager_id, key, value, value_type="xsd:string"):
		'''
			A generic function to set property using Update Options cal
			ARGS :
			    config_manager_id : moid for which value needs to updated
			    key : Key name
			    value : value
			    value_type : value type
			Return value :
			    True if update operation is successful
			    False Otherwise
			
			Exception :  Throw  urllib2.HTTPError exception if any
		'''
		try:
			request_body = """<?xml version="1.0" encoding="UTF-8"?>
						<SOAP-ENV:Envelope xmlns:ns0="urn:vim25" xmlns:ns1="http://schemas.xmlsoap.org/soap/envelope/" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:SOAP-ENV="http://schemas.xmlsoap.org/soap/envelope/">
						   <SOAP-ENV:Header/>
						   <ns1:Body>
						      <ns0:UpdateOptions>
						         <ns0:_this type="OptionManager">""" + escape(config_manager_id) + """</ns0:_this>
						         <ns0:changedValue>
						            <ns0:key>""" + escape(key) + """</ns0:key>
						            <ns0:value xsi:type=""" + quoteattr(value_type) + """>""" + escape(value) + """</ns0:value>
						         </ns0:changedValue>
						      </ns0:UpdateOptions>
						   </ns1:Body>
						</SOAP-ENV:Envelope>
				"""
			request = urllib2.Request(self.service_url, data=request_body, headers=self.headers)
			handle = self.opener.open(request)
			if handle.code != 200:
				return False
			else:
				return True
		except urllib2.HTTPError:
			raise

	def enable_ruleset(self, obj_type, moid, id_name):
		'''
			Invoke EnableRuleSet operation to update any rule
			
			ARGS :
			     obj_type : Object type
			     moid : Moid of object
			     id_name : name of id
			 Return value :
			    True if update operation is successful
			    False Otherwise
			
			Exception :  Throw  urllib2.HTTPError exception if any
		'''
		try:
			request_body = """<?xml version="1.0" encoding="UTF-8"?>
							   <SOAP-ENV:Envelope xmlns:ns0="urn:vim25" xmlns:ns1="http://schemas.xmlsoap.org/soap/envelope/" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:SOAP-ENV="http://schemas.xmlsoap.org/soap/envelope/">
							    <SOAP-ENV:Header/>
							     <ns1:Body>
							      <ns0:EnableRuleset>
							       <ns0:_this type=""" + quoteattr(obj_type) + """>""" + escape(moid) + """</ns0:_this>
							        <ns0:id>""" + escape(id_name) + """</ns0:id>
							      </ns0:EnableRuleset>
							     </ns1:Body>
							   </SOAP-ENV:Envelope>     
				"""
			request = urllib2.Request(self.service_url, data=request_body, headers=self.headers)
			handle = self.opener.open(request)
			if handle.code != 200:
				return False
			else:
				return True
		except urllib2.HTTPError:
			raise

	#### These functions are being used to get Hierarchy information for perfCollections ###########
	def get_powerOn_vm_list(self, hostmoid):
		'''
			Get powerOn VM list for a host
			@param hostmoid : moid of host
			
			@return: list of tuple ( moid and type of object) of VMs which is powered on
		'''
		vm_list = []
		response = self.get_obj_list([{'type':'VirtualMachine','all':'false', 'pathSet':'name'}, {'type':'VirtualMachine','all':'false', 'pathSet':'summary.runtime.powerState'}], {'type':'HostSystem', 'moid':hostmoid})
		resp_xml = minidom.parseString(response)
		for returnval in resp_xml.getElementsByTagName("returnval"):
				# There will only one object in each return value
				obj =  returnval.getElementsByTagName('obj')[0]
				propsets = returnval.getElementsByTagName('propSet')
				for propset in propsets:
					if 'poweredOn' in propset.toxml():
						if obj and obj.firstChild and obj.firstChild.TEXT_NODE:
							vm_list.append((obj.firstChild.data, obj.getAttribute('type')))
		return vm_list


	def get_resourcepool_list(self, rootobj):
		'''
			Get resource moid
			@param rootobj : dict which contain root object moid and type for example {'type':'Folder', 'moid':'group-d1'}
			
			@return: list of tuple ( moid and type of object) of resources
		'''
		res_list = []
		response = self.get_obj_list([{'type':'ResourcePool','all':'false', 'pathSet':'name'}], rootobj)
		resp_xml = minidom.parseString(response)
		for returnval in resp_xml.getElementsByTagName("returnval"):
			# There will only one object in each return value
			obj =  returnval.getElementsByTagName('obj')[0]
			if obj and obj.firstChild and obj.firstChild.TEXT_NODE:
				res_list.append((obj.firstChild.data, obj.getAttribute('type')))

		return res_list
	
	def get_cluster_list(self, rootobj):
		'''
			Get resource moid
			@param rootobj : dict which contain root object moid and type for example {'type':'Folder', 'moid':'group-d1'}
			
			@return: list of tuple ( moid and type of object) of clusters
		'''
		res_list = []
		response = self.get_obj_list([{'type':'ClusterComputeResource','all':'false', 'pathSet':'name'}], rootobj)
		resp_xml = minidom.parseString(response)
		for returnval in resp_xml.getElementsByTagName("returnval"):
			# There will only one object in each return value
			obj =  returnval.getElementsByTagName('obj')[0]
			if obj and obj.firstChild and obj.firstChild.TEXT_NODE:
				res_list.append((obj.firstChild.data, obj.getAttribute('type')))

		return res_list
	
	def get_obj_list(self, propset, rootInfo):
		'''
		    @param propset: Array of dicts which hold the name, type and all properties value, eg
		    		   <ns1:propSet>
			                <ns1:type>VirtualMachine</ns1:type>
			                <ns1:all>false</ns1:all>
			                <ns1:pathSet>name</ns1:pathSet>
			            </ns1:propSet>
			            .... repeat for summary.runtime.powerState
			            [{'type':'VirtualMachine','all':'false', 'pathSet':'name'}, {'type':'VirtualMachine','all':'false', 'pathSet':'summary.runtime.powerState'}]
			        rootInfo : Root object name in form of dict. It should have type and moid of that type of object {'HostSystem', 'host-11'}
			        
		    
		'''
		try:
			request_body ="""<?xml version="1.0" encoding="UTF-8"?>
			<SOAP-ENV:Envelope xmlns:SOAP-ENV="http://schemas.xmlsoap.org/soap/envelope/" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:ns1="urn:vim25" xmlns:ns0="http://schemas.xmlsoap.org/soap/envelope/">
			<SOAP-ENV:Header/>	
			<ns0:Body>
			    <ns1:RetrieveProperties>
			        <ns1:_this type="PropertyCollector">propertyCollector</ns1:_this>
			        <ns1:specSet xsi:type="ns1:PropertyFilterSpec">"""
			for propName in propset:
				request_body = request_body + """
						<ns1:propSet>
			                <ns1:type>"""+escape(propName.get('type', None))+"""</ns1:type>
			                <ns1:all>"""+escape(str(propName.get('all', '')).lower())+"""</ns1:all>
			                <ns1:pathSet>"""+escape(propName.get('pathSet', None))+"""</ns1:pathSet>
			            </ns1:propSet>"""
			# Add object set
			request_body = request_body + """
			            <ns1:objectSet>
			                <ns1:obj type="""+quoteattr(rootInfo.get('type', None))+""">"""+escape(rootInfo.get('moid', None))+"""</ns1:obj>
			                <ns1:skip>false</ns1:skip>
			                <ns1:selectSet xsi:type="ns1:TraversalSpec">
			                    <ns1:name>visitFolders</ns1:name>
			                    <ns1:type>Folder</ns1:type>
			                    <ns1:path>childEntity</ns1:path>
			                    <ns1:skip>false</ns1:skip>
			                    <ns1:selectSet>
			                        <ns1:name>visitFolders</ns1:name>
			                    </ns1:selectSet>
			                    <ns1:selectSet>
			                        <ns1:name>dcToHf</ns1:name>
			                    </ns1:selectSet>
			                    <ns1:selectSet>
			                        <ns1:name>dcToVmf</ns1:name>
			                    </ns1:selectSet>
			                    <ns1:selectSet>
			                        <ns1:name>dcToDs</ns1:name>
			                    </ns1:selectSet>
			                    <ns1:selectSet>
			                        <ns1:name>dcToNetf</ns1:name>
			                    </ns1:selectSet>
			                    <ns1:selectSet>
			                        <ns1:name>crToH</ns1:name>
			                    </ns1:selectSet>
			                    <ns1:selectSet>
			                        <ns1:name>crToRp</ns1:name>
			                    </ns1:selectSet>
			                    <ns1:selectSet>
			                        <ns1:name>HToVm</ns1:name>
			                    </ns1:selectSet>
			                    <ns1:selectSet>
			                        <ns1:name>rpToVm</ns1:name>
			                    </ns1:selectSet>
			                </ns1:selectSet>
			                <ns1:selectSet xsi:type="ns1:TraversalSpec">
			                    <ns1:name>dcToDs</ns1:name>
			                    <ns1:type>Datacenter</ns1:type>
			                    <ns1:path>datastoreFolder</ns1:path>
			                    <ns1:skip>false</ns1:skip>
			                    <ns1:selectSet>
			                        <ns1:name>visitFolders</ns1:name>
			                    </ns1:selectSet>
			                </ns1:selectSet>
			                <ns1:selectSet xsi:type="ns1:TraversalSpec">
			                    <ns1:name>dcToNetf</ns1:name>
			                    <ns1:type>Datacenter</ns1:type>
			                    <ns1:path>networkFolder</ns1:path>
			                    <ns1:skip>false</ns1:skip>
			                    <ns1:selectSet>
			                        <ns1:name>visitFolders</ns1:name>
			                    </ns1:selectSet>
			                </ns1:selectSet>
			                <ns1:selectSet xsi:type="ns1:TraversalSpec">
			                    <ns1:name>vAppToRp</ns1:name>
			                    <ns1:type>VirtualApp</ns1:type>
			                    <ns1:path>resourcePool</ns1:path>
			                    <ns1:skip>false</ns1:skip>
			                    <ns1:selectSet>
			                        <ns1:name>rpToRp</ns1:name>
			                    </ns1:selectSet>
			                    <ns1:selectSet>
			                        <ns1:name>vAppToRp</ns1:name>
			                    </ns1:selectSet>
			                </ns1:selectSet>
			                <ns1:selectSet xsi:type="ns1:TraversalSpec">
			                    <ns1:name>dcToVmf</ns1:name>
			                    <ns1:type>Datacenter</ns1:type>
			                    <ns1:path>vmFolder</ns1:path>
			                    <ns1:skip>false</ns1:skip>
			                    <ns1:selectSet>
			                        <ns1:name>visitFolders</ns1:name>
			                    </ns1:selectSet>
			                </ns1:selectSet>
			                <ns1:selectSet xsi:type="ns1:TraversalSpec">
			                    <ns1:name>dcToHf</ns1:name>
			                    <ns1:type>Datacenter</ns1:type>
			                    <ns1:path>hostFolder</ns1:path>
			                    <ns1:skip>false</ns1:skip>
			                    <ns1:selectSet>
			                        <ns1:name>visitFolders</ns1:name>
			                    </ns1:selectSet>
			                </ns1:selectSet>
			                <ns1:selectSet xsi:type="ns1:TraversalSpec">
			                    <ns1:name>crToH</ns1:name>
			                    <ns1:type>ComputeResource</ns1:type>
			                    <ns1:path>host</ns1:path>
			                    <ns1:skip>false</ns1:skip>
			                </ns1:selectSet>
			                <ns1:selectSet xsi:type="ns1:TraversalSpec">
			                    <ns1:name>crToRp</ns1:name>
			                    <ns1:type>ComputeResource</ns1:type>
			                    <ns1:path>resourcePool</ns1:path>
			                    <ns1:skip>false</ns1:skip>
			                    <ns1:selectSet>
			                        <ns1:name>rpToRp</ns1:name>
			                    </ns1:selectSet>
			                    <ns1:selectSet>
			                        <ns1:name>rpToVm</ns1:name>
			                    </ns1:selectSet>
			                </ns1:selectSet>
			                <ns1:selectSet xsi:type="ns1:TraversalSpec">
			                    <ns1:name>rpToRp</ns1:name>
			                    <ns1:type>ResourcePool</ns1:type>
			                    <ns1:path>resourcePool</ns1:path>
			                    <ns1:skip>false</ns1:skip>
			                    <ns1:selectSet>
			                        <ns1:name>rpToRp</ns1:name>
			                    </ns1:selectSet>
			                    <ns1:selectSet>
			                        <ns1:name>rpToVm</ns1:name>
			                    </ns1:selectSet>
			                </ns1:selectSet>
			                <ns1:selectSet xsi:type="ns1:TraversalSpec">
			                    <ns1:name>HToVm</ns1:name>
			                    <ns1:type>HostSystem</ns1:type>
			                    <ns1:path>vm</ns1:path>
			                    <ns1:skip>false</ns1:skip>
			                    <ns1:selectSet>
			                        <ns1:name>visitFolders</ns1:name>
			                    </ns1:selectSet>
			                </ns1:selectSet>
			                <ns1:selectSet xsi:type="ns1:TraversalSpec">
			                    <ns1:name>rpToVm</ns1:name>
			                    <ns1:type>ResourcePool</ns1:type>
			                    <ns1:path>vm</ns1:path>
			                    <ns1:skip>false</ns1:skip>
			                </ns1:selectSet>
			            </ns1:objectSet>
			        </ns1:specSet>
			    </ns1:RetrieveProperties>
			</ns0:Body>
			</SOAP-ENV:Envelope>
			"""
			request = urllib2.Request(self.service_url, data=request_body, headers=self.headers)
			handle = self.opener.open(request)
			return handle.read()
		except urllib2.HTTPError:
			raise