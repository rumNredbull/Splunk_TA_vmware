# Copyright (C) 2005-2016 Splunk Inc. All Rights Reserved.
#Core Python imports
import json

#TA-vmware imports
from vim25.mo import ManagedObjectReference
from vim25 import logger
from vim25 import utils
from vim25.connection import Connection
from suds import WebFault


# Start Class Object definitions.
class _targetConfig(object):
	targetEntities = [
		"VirtualMachine",
		"HostSystem",
		"Folder",
		"Datacenter",
		"ComputeResource",
		"ClusterComputeResource",
		"Datastore",
		"ResourcePool"
		]
	Hierarchy = {
		"VirtualMachine":["name", "parent", "runtime.host", "resourcePool"],
		"HostSystem":["name", "parent"],
		"Folder":["name", "parent"],
		"Datacenter":["name", "parent"],
		"ComputeResource":["name", "parent"],
		"ClusterComputeResource":["name", "parent"],
		"ResourcePool":["name", "parent"],
		"Datastore":["name", "parent"]
		}
	VirtualMachine = {
		"VirtualMachine":[
			"name",
			"parent",
			"capability",
			"config",
			"datastore",
			"environmentBrowser",
			"guest",
			"guestHeartbeatStatus",
			"layoutEx",
			"network",
			"parentVApp",
			"resourceConfig",
			"resourcePool",
			"rootSnapshot",
			"snapshot",
			"storage",
			"summary"
			]
		}
	@property
	def HostSystem(self): 
		host_props_base = [
			"name",
			"parent",
			"capability",
			"datastore",
			"config.hyperThread",
			"network",
			"summary",
			"vm"
		]
		if not Connection.vc_version or Connection.vc_version[0] == '4': 
			props = host_props_base
		else:
			props = host_props_base + [ "licensableResource" ]
		return { "HostSystem": props }
	# Missing HostSystem.harware... but it seems... useless... or should say, 100 pages of junk for 2 things worth value
	HostSystemSummary = {
		"HostSystem":[
			"summary"
		]
	}
	HostSystemSystemResources = {
		"HostSystem":[
			"systemResources"
		]
	}
	PerfInventory = {
	 	"VirtualMachine":[
			"name",
			"runtime.host",
			"summary.runtime.powerState"
		]
	}
	HostList = {
	 	"HostSystem":[
			"name"
		]
	}
	HostListConnectedPowered = {
	 	"HostSystem":[
			"name",
			"summary.runtime.connectionState",
			"summary.runtime.powerState"
		]
	}
	PerfResourcePoolList = {
		"ResourcePool":[
			"name"
		]
	}
	ResourcePool = {
		"ResourcePool":[
			"name",
			"parent",
			"config",
			"owner",
			"resourcePool",
			"runtime",
			"summary"
		]
	}
	PerfClusterComputeResourceList = {
		"ClusterComputeResource":[
			"name"
			]
	}
	ClusterComputeResource = {
		"ClusterComputeResource":[
			"name",
			"parent",
			"actionHistory",
			"configurationEx",
			"drsFault",
			"recommendation",
			"migrationHistory"
		]
	}
	Datastore = {
		"Datastore":[
			"name",
			"parent",
			"capability",
			"host",
			"info",
			"iormConfiguration",
			"summary",
			"vm"
		]
	}

targetConfig = _targetConfig()

class CurrentViewManager(Connection):
	cViewRefList = None
	if cViewRefList and len(cViewRefList) > 0:
		cViewRef = cViewRefList[-1]
	else:
		cViewRef = None
	@classmethod
	def updateViewMgr(cls):
		''' After creation / deletion of a view, this method updates cViewRefList with a list
		of all currently active views for the user session
		'''
		cls.viewMgrRef = Connection.svcInstance.getViewManager()
	@classmethod
	def updateViewList(cls):
		''' After creation / deletion of a view, this method updates cViewRefList with a list
		of all currently active views for the user session, selects the last created view as
		the target view for filter creation.
		'''
		cls.cViewRefList = cls.viewMgrRef.getViewList()
		if len(cls.cViewRefList) > 0:
			cls.cViewRef = cls.cViewRefList[-1]
		else:
			cls.cViewRef = None
	@classmethod
	def buildView(cls, entityList):
		''' Creates a viewManger object that will traverse from the root folder and select
		a list of objects specified in the entityList.  This view can then be used as an object
		to pass to propertyCollectors to traverse a large set of managed objects.  Example:
		If you wanted to collect all virtual machines in the root folder, you'd simply call
		buildview(["VirtualMachine"])'''
		cls.viewMgrRef.createContainerView(cls.rootFolder, entityList, True)
		cls.updateViewList()
	@classmethod
	def destroyView(cls, viewListIndex):
		''' Used to remove a view that's been created.  Specify the index list of the target
		view to remove.  Views are accessed on PCollector.cViewRefList
		'''
		try:
			cls.cViewRefList[viewListIndex].destroyView()
			cls.updateViewList()
		except Exception as e:
			logger.error("Missing View, or view list index out of range: %s", str(e))
			logger.exception(e)

class PropCollector(CurrentViewManager):
	def __init__(self, mor=None):
		try:
			CurrentViewManager.updateViewMgr()
			CurrentViewManager.updateViewList()
			if mor:
				if type(mor) != str:
					raise
				else:
					tempMOR = ManagedObjectReference(value=mor, _type="PropertyCollector")
					# tempMOR = Connection.vim25client.new('_this', value=mor, _type="PropertyCollector")
					self.targetCollector = Connection.vim25client.createExactManagedObject(mor=tempMOR)
			else:
				self.targetCollector = CurrentViewManager.propColl.createPropertyCollector()
			if not CurrentViewManager.cViewRef:
				CurrentViewManager.buildView(targetConfig.targetEntities)
			self.oSpec = None
			self.tSpec = CurrentViewManager.tSpec
			self.filterList = self.targetCollector.getFilter('filter')
			self.fSpecList = []
			self.pSpecList = []
		except Exception as e:
			logger.error("Error, when specifying an mor, please pass just the mor value, not an object: %s", str(e))
			logger.exception(e)
		
	def updateFilterList(self):
		''' After creation / deletion of a filter, this method updates filterList with a list
		of all currently active filters for the user session
		'''
		self.filterList = self.targetCollector.getFilter('filter')
		
	def buildFilterSpecList(self, targetDict):
		''' Takes the current connection object and a dictionary of target items to pull
		during property collection.  Example, if I wanted the names of all virtual machines,
		I'd pass in a dict of {"VirtualMachine":"name"}.  If I wanted both the name and the
		parent of a virtual machine, my dict would look like:
		{"VirtualMachine":["name","parent"]}.  This command requires a view reference.  Please
		use 'buildView' prior to running this method.
		'''
		self.pSpecList = []
		self.oSpec = Connection.vim25client.new('ObjectSpec', obj=CurrentViewManager.cViewRef.getMOR(), skip=True)
		self.oSpec.selectSet.append(self.tSpec)
		for targetType, targetPaths in targetDict.items():
			if type(targetPaths) == str:
				self.pSpecList.append(Connection.vim25client.new('PropertySpec', type=targetType, pathSet=targetPaths))
			elif type(targetPaths) == list:
				for targetPath in targetPaths:
					self.pSpecList.append(Connection.vim25client.new('PropertySpec', type=targetType, pathSet=targetPath))
		self.fSpecList.append(Connection.vim25client.new('PropertyFilterSpec', objectSet=self.oSpec, propSet=self.pSpecList))
	
	def emptyFilterSpecList(self):
		''' Empties the fSpecList attribute on the class object.  Useful for creating multiple
		filters to use with checkForUpdate method.  For instance, if you wanted to create a 
		hierarchy that lists the name and parent of vm's, hosts, clusters, folders and datacenters,
		you'd create a spec list for {"VirtualMachine":["name","parent"]}, then run the buildFilter
		method, then emptyFilterSpecList, then buildFilterSpecList with {"HostSystem":["name","parent"]}
		, empty, rinse and repeat until finished.  At the end you will have 5 items in your 
		FilterList that will all be called and record changes with one checkForUpdates method.
		'''
		self.fSpecList = []
	
	def buildFilter(self, filtrList, partUpdates):
		''' This method will create a filter managed object for propertyCollectors.
		this filter will remain persistent until destroyFilter() is called or the session
		is closed. This method is most often called after buildFilterList.
		'''
		self.targetCollector.createFilter(spec=filtrList, partialUpdates=partUpdates)
		self.updateFilterList()
	
	def destroyFilter(self, filterListIndex):
		''' Used to remove a filter that's been created.  Specify the index list of the target
		filter to remove.  Filters are accessed on PCollector.filterList
		'''
		try:
			self.filterList[filterListIndex].destroyPropertyFilter()
			self.updateFilterList()
		except Exception as e:
			logger.error("Missing filter, or filter list out of range: %s", str(e))
			logger.exception(e)

	def collectPropertiesEx(self, specList):
		'''Preforms a full collection of the specList passed.  Will not retain any information
		or update status.  Any filter created during this process is destroyed after collection.
		this method will be most often used with buildFilterList.
		'''
		ro = Connection.vim25client.new('RetrieveOptions')
		try:
			props = self.targetCollector.retrievePropertiesEx(specSet=specList, options=ro)
			yield props.objects
			while hasattr(props, 'token'):
				lastToken = str(props.token)
				props = self.targetCollector.continueRetrievePropertiesEx(token=lastToken)
				yield props.objects
		except Exception as e:
			logger.error("collect properties ex fail: %s", str(e))
			logger.exception(e)
	
	def checkForUpdates(self, ver=None, maxObjUpdatesWaitOp=None):
		''' Used to check for any updated changes on ALL created filters.  An optional version
		can be specified to check for a difference between the specified version and the current
		configuration.  This method will return null if there are no differences between the 
		the specified versions.  Submitting a version of "None" will cause a full dump of the filters
		at the creation of the first checkForUpdates() call
		'''
		try:
			lastVersion = ver
			waitOptions = Connection.vim25client.new('WaitOptions', maxWaitSeconds=0, maxObjectUpdates=maxObjUpdatesWaitOp)
			data = self.targetCollector.waitForUpdatesEx(version=ver, options=waitOptions)
			if data:
				lastVersion = getattr(data, 'version')
				# Version may have _ hence trim it
				if lastVersion.find('_') >= 0:
					lastVersion = lastVersion[0:lastVersion.find('_')]
					# When result set in chunks then we need to do this hack
					# If there is subversion, it always start with oldversion_subversion and last truncated
					# result data contains actual increased version so increasing version by 1 to have right
					# count for all object
					lastVersion = int(str(lastVersion)) + 1
				yield lastVersion, data
				while hasattr(data, 'truncated'):
					version = data.version
					data = self.targetCollector.waitForUpdatesEx(version=version, options=waitOptions)
					# Version may have _, hence trim it, also increase by 1 as described above
					if version.find('_') >= 0:
						mainVer = version[0:version.find('_')]
						mainVer = int(str(mainVer)) + 1
					else:
						mainVer = version
					yield mainVer, data
		except Exception as e:
			logger.error("[Inventory] checkForUpdates Failure")
			logger.exception(e)

	def dumpCollector(self):
		'''Preforms a full dump of the currently set fSpecList.
		'''
		ro = Connection.vim25client.new('RetrieveOptions')
		try:
			props = self.targetCollector.retrievePropertiesEx(specSet=self.fSpecList, options=ro)
			return props
		except Exception as e:
			logger.error("dump collector took a dump: %s", str(e))
			logger.exception(e)
			
# End of Class Definitions, starting collection functions.

def CreateHierarchyCollector(managedObjectReference=None, targetConfigObject=None, updateType="update", version=None, oneTime=False, addlTargetConfig=None):
	''' Primary method to create collecting inventory.  managedObjectReference is to reference a propertyCollector
	that has already been created.  You can pass the MOR value to this method, and it will create a reference
	to that existing property collector.  You do not need to specify targetEntityType when using a MOR reference.
	For all new property collectors (like the first run), you should use targetEntityType.  This will reference
	the entity out of the targetConfig class for what properties to collect.  updateType is to be used in
	conjunction with an existing MOR, "update" will allow the user to submit a version for checking differences,
	while "recycle" will destroy the property collector and then create a new property collector.
	"addlTargetConfig" will include any additional properties that need to be collected, as specified in the conf file.
	It also create filterspec and filter as well before return property collector object
	
	Returns: version, property collector object, targetConfigObject (the returned configuration target for chaining to a formatter), mor (The returned MOR to
	the created / updated property collector, version
	'''
	try:
		logger.debug("[Inventory] CollectInventory called with these options: managedObjectReference:{0}, targetConfigObject:{1}, updateType:{2}, version:{3}, oneTime:{4}, addlTargetConfig: {5}".format(managedObjectReference, targetConfigObject, updateType, version, oneTime, addlTargetConfig))

		configObject = getattr(targetConfig, targetConfigObject)
		if  addlTargetConfig:
			configObject['HostSystem'].extend(addlTargetConfig)
			logger.debug("[Inventory] CollectInventory: Addl properties added for 'HostSystem', configObject now contains:"+str(configObject))
                                            
		if managedObjectReference:
			logger.debug("[Inventory] Received an MOR.  Rebuilding old collector.")
			hierarchyCollector = PropCollector(mor=managedObjectReference)
			if updateType=="recycle":
				try:
					logger.debug("[Inventory] Old collector being recycled")
					hierarchyCollector.targetCollector.destroyPropertyCollector()
				except WebFault as wf:
					if str(wf) == "Server raised fault: 'The object has already been deleted or has not been completely created'":
						logger.debug("[Inventory] Destroy Collector called with a non-existing collector, assuming deleted and creating new.")
					else:
						raise wf
				mor=None
				version=None
				hierarchyCollector = PropCollector()
				mor = str(hierarchyCollector.targetCollector.getMOR().value)
				logger.debug("[Inventory] Recycled collector MOR:{0}".format(mor))
				hierarchyCollector.buildFilterSpecList(configObject)
				hierarchyCollector.buildFilter(hierarchyCollector.fSpecList, partUpdates=True)
			if oneTime == True:
				logger.debug("[Inventory] OneTime collection is set to true with existing MOR.")
				hierarchyCollector.buildFilterSpecList(configObject)
			mor = str(hierarchyCollector.targetCollector.getMOR().value)
			return version, hierarchyCollector, targetConfigObject, mor
		else:
			logger.debug("[Inventory] Creating new collector.")
			hierarchyCollector = PropCollector()
			mor = str(hierarchyCollector.targetCollector.getMOR().value)
			logger.debug("[Inventory] New collector MOR:{0}".format(mor))
			hierarchyCollector.buildFilterSpecList(configObject)
			hierarchyCollector.buildFilter(hierarchyCollector.fSpecList, partUpdates=True)
			return version, hierarchyCollector, targetConfigObject, mor
	except Exception as e:
		logger.error("error in creating hierarchy collector")
		logger.exception(e)
		raise e

def DestroyHierarchyCollector(hierarchyCollector):
	'''
	    Destroy Property collector
	    @param hierarchyCollector: PropertyCollector object
	'''
	if hierarchyCollector is None or hierarchyCollector.targetCollector is None:
		logger.error("Hierarchy collector can not be destroy as it is passed as null value.")
		return
	hierarchyCollector.targetCollector.destroyPropertyCollector()


def Jsonify(target):
	try:
		return json.dumps(target)
	except Exception as e:
		logger.error("Error trying to jsonify object")
		logger.exception(e)


def FlattenCombinedData(data, version=None):
	''' Takes a combinedData object from a processed dataSet and formats the output
	for splunk.  
	'''
	for filterItem in data.filterSet:
		for objectItem in filterItem.objectSet:
			tempFullObject=dict(utils.CheckAttribute(objectItem))
			tempFullObject=utils.Folderize(tempFullObject)
			if 'kind' in tempFullObject:
				del tempFullObject['kind']
			if 'obj' in tempFullObject:
				tempFullObject['moid'] = tempFullObject['obj']['moid']
				tempFullObject['type'] = tempFullObject['obj']['type']
				tempFullObject['rootFolder'] = { 'moid':Connection.rootFolder.getMOR().value }
				if version:
					tempFullObject['collectionVersion'] = version
				del tempFullObject['obj']
			yield Jsonify(tempFullObject)
