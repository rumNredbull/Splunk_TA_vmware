# Copyright (C) 2005-2016 Splunk Inc. All Rights Reserved.
import suds
import os
import inspect
from suds.plugin import MessagePlugin
from vim25.mo import ManagedObject, ServiceInstance, ServerConnection

class VimFault(Exception):
	def __init__(self, fault):
		self.fault = fault
		self.fault_type = fault.__class__.__name__
		self._fault_dict = {}
		if type(fault) == suds.WebFault:
			for attr in fault:
				self._fault_dict[attr[0]] = attr[1]
			Exception.__init__(self, "%s: %s" % (self.fault_type, self._fault_dict))
		else:
			Exception.__init__(self, "%s" % fault)

class Vim25Client(object):
	def __init__(self, server_url=None, debugmode=False, **kwargs):
		self.soapClient = suds.client.Client(url="https://"+server_url+"/sdk/vimService?wsdl", **kwargs)
		self.soapClient.set_options(location="https://"+server_url+"/sdk")
		#For Future use in cache control
		#self.soapCache = self.soapClient.options.cache
		self.moCache = None
		if debugmode:
			import logging
			logging.basicConfig(filename="suds.log", level=logging.DEBUG)
			logging.getLogger('suds.transport').setLevel(logging.DEBUG)
		
	def handle_exception(self, e):
		if type(e).__name__ == "WebFault":
			if len(e.fault.faultstring) > 0:
				raise
			detail = e.document.childAtPath("/Envelope/Body/Fault/detail")
			fault_type = detail.getChildren()[0].name
			fault = self.soapClient.factory.create('ns0:' + fault_type)
			if isinstance(e.fault.detail[0], list):
				for attr in e.fault.detail[0]:
					setattr(fault, attr[0], attr[1])
			else:
				fault["text"] = e.fault.detail[0]
			raise VimFault(fault)
		elif isinstance(e, Exception):
			raise VimFault(e)
			
	def __getattr__(self, t):
		"""
		This is a catch-all method for invoking web services methods through WSClient (a suds client).
		See the definition of _invoke in WSClient and of service attribute in suds.client.CLient.
		Note that the kwargs are transformed to convert managed entity objects (and arrays) into
		MORs and MOR arrays.
		"""
		def vimSvcWrapper(_this, **kwargs):
			for arg in kwargs:
				if isinstance(kwargs[arg], ManagedObject):
					kwargs[arg] = kwargs[arg].getMOR()
				elif (isinstance(kwargs[arg], list) and len(kwargs[arg]) > 0
					  and isinstance(kwargs[arg][0], ManagedObject)):
					kwargs[arg] = [mor.getMOR() for mor in kwargs[arg]]
			return self.invoke(t, _this, **kwargs)
		return vimSvcWrapper

	def new (self, t, **kwargs):
		obj = self.soapClient.factory.create("ns0:%s" % t)
		for n, v in kwargs.items():
			setattr(obj, n, v)
		return obj

	def isinstance(self, obj, _type):
		return type(obj) == type(_type())
		
	def invoke(self, method, _this, **kwargs):
		try:
			targetFunc = getattr(self.soapClient.service, method)
			result = targetFunc(_this, **kwargs)
		except Exception, e:
			self.handle_exception(e)

		return result
		
	def vim_wrap(self, obj):
		if isinstance(obj, list):
			return [self.vim_wrap(i) for i in obj]
		try:
			if isinstance(obj, suds.sudsobject.Object):
				members = dict(filter(lambda (n, m): not n.startswith('__') and not inspect.isroutine(m), inspect.getmembers(obj)))
				return self.new(obj.__class__.__name__, **members)
		except:
			return obj
			
		return obj
		
	def createServiceInstance(self, server_url=None, username=None, password=None, sessioncookie=None):
		# ServiceInstance creates a ServerConnection object during its initialization
	    # ServerConnection has a reference to this client (in the vimService variable)
		# This client also stores a reference to the ServerConnection (self.sc),
		# assigned by ServiceInstance during the initialization process
		self.serviceInstance = ServiceInstance(self, server_url, username, password, sessioncookie)

	def setServerConnection(self, sc):
		self.sc = sc
	
	def createMORs(self, mors=[]):
		return [mor.getMOR() for mor in mors]

	def createExactManagedObject(self, mor):
		if not self.moCache:
			import vim25.mo
			self.moCache = dict(filter(lambda (name, obj): inspect.isclass(obj), inspect.getmembers(vim25.mo)))
		return self.moCache.get(mor._type)(self.sc, mor) if self.moCache.has_key(mor._type) else None

	def createExactManagedEntity(self, mor):
		return self.createExactManagedObject(mor)

	def createExactManagedEntities(self, mors=[]):
		return [self.createExactManagedEntity(mor) for mor in mors]

	def createManagedEntities(self, mors):
		return [self.createExactManagedEntity(mor) for mor in mors] if mors else []

	def convertProperty(self, dynaPropVal):
		propertyValue = dynaPropVal
		# if dynaPropVal is an array type, need to convert into []

		return propertyValue

	def createObjectSpec(self, mor, skip, selSet):
		return self.new('ObjectSpec', obj=mor, skip=skip, selectSet=selSet)

	def createPropertySpec(self, tp, allProp, pathSet):
		return self.new('PropertySpec', type=tp, all=allProp, pathSet=pathSet)

	def createSelectionSpec(self, names):
		return [self.new('SelectionSpec', name=name) for name in names]

	def createTraversalSpec(self, name, tp, path, selSpec):
		sp = selSpec
		if len(sp)>0 and isinstance(sp[0], str):
			sp = self.createSelectionSpec(sp)
			
		return self.new('TraversalSpec', name=name, type=tp, path=path, skip=False,selectSet=sp)
	
	def buildPropertySpecArray(self, typeProplists):
		pSpecs = []
	
		for tp in typeProplists:
			tpe = tp[0]
			props = tp[1:]
			al = len(props)==0
	
			pSpecs.append(self.createPropertySpec(tpe, al, props))
	
		return pSpecs;
	
class SoapFixer(MessagePlugin):
	"""
	We need this because suds doesn't play well with elements declared as anyType in the WSDL schema.
	If we are working with any field labeled as xsd:anyType, we must intercept that SOAP envelope
	and set the type to xsd:int or xsd:string, whichever is appropriate.
	"""
	def marshalled(self, context):
		def check_int(s):
			if s is None or s == "": return False
			if s[0] in ('-', '+'): return s[1:].isdigit()
			return s.isdigit()
			# TODO: figure out if this is an optimal way to check this path.
			# Should we also check that Body/UpdateOptions/_this has type "OptionManager"?  E.g.:
			# context.envelope.childAtPath("Body/UpdateOptions/_this") is not None and
			# context.envelope.childAtPath("Body/UpdateOptions/_this").get('type') == "OptionManager" and
			# ......
		if context.envelope.childAtPath("Body/UpdateOptions/changedValue") is not None:
			for elt in context.envelope.childrenAtPath("Body/UpdateOptions/changedValue"):
				val = elt.getChild('value')
				xsd_type = 'xsd:int' if val is not None and check_int(val.getText()) else 'xsd:string'
				val.set('xsi:type', xsd_type)


