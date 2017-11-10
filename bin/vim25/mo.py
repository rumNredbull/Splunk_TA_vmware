# Copyright (C) 2005-2016 Splunk Inc. All Rights Reserved.
import time
import suds.sudsobject

if_true = lambda c, a, b: a if c else b

class ServerConnection(object):
	def __init__(self, url, vimService, serviceInstance=None):
		self.url = url
		self.userSession = None
		self.serviceInstance = serviceInstance
		self.vimService = vimService

	def setSessionCookie(self, scookie):
		transport = getattr(self.vimService.soapClient.options, 'transport')
		transport.cookiejar.set_cookie(scookie)

	def getSessionCookie(self):
		transport = getattr(self.vimService.soapClient.options, 'transport')
		for c in transport.cookiejar:
			if c.name=='vmware_soap_session':
				return c
		return None

	def getUserSession(self): return self.userSession

	def setUserSession(self, userSession): self.userSession = userSession

	def getSessionStr(self):
		return self.vimService.getWsc().getCookie()

	def logout(self):
		if self.vimService!=None:
			self.serviceInstance.getSessionManager().logout()
			self.vimService = None
			self.serviceInstance = None

	def getServiceInstance(self):
		return self.serviceInstance;

	def getVimService(self):
		return self.vimService

	def getUrl(self):
		return self.url

	def getUsername(self):
		return self.userSession.userName

	def setServiceInstance(self, si):
		self.serviceInstance = si

class ManagedObject(object):
	def __init__(self, sc=None, mor=None):
		self.serverConnection = sc
		self.mor = mor

	def _convert(self, obj):
		return getattr(obj, obj.__class__.__name__[7:]) if obj.__class__.__name__.startswith('ArrayOf') else obj.val

	def getCurrentProperty(self, pName):
		propertyValue = None

		objContent = self.retrieveObjectProperties([pName])
		if objContent!=None:
			dynaProps = objContent.propSet
			if dynaProps != None and len(dynaProps)>0:
				propertyValue = self._convert(dynaProps[0])

		return propertyValue

	def retrieveObjectProperties(self, prop):

		oSpec = self.serverConnection.getVimService().createObjectSpec(self.getMOR(), False, None)
		pSpec = self.serverConnection.getVimService().createPropertySpec(self.getMOR()._type, None, prop)

		pfSpec = self.serverConnection.getVimService().new('PropertyFilterSpec')
		pfSpec.objectSet = [oSpec]
		pfSpec.propSet = [pSpec]

		pc = self.getServerConnection().getServiceInstance().getPropertyCollector()

		ocs = pc.retrieveProperties([pfSpec])

		if ocs!=None and len(ocs)>0:
			return ocs[0]

		return None

	def setMOR(self, mor):
		self.mor = mor

	def getMOR(self):
		return self.mor

	def getVimService(self):
		return self.serverConnection.getVimService()

	def getServerConnection(self):
		return self.serverConnection

	def setServerConnection(self, sc):
		self.serverConnection = sc

	def getPropertyByPath(self, propPath):
		return self.getCurrentProperty(propPath)

	def getVms(self, propName):
		return self.getManagedObjects(propName)

	def getManagedObject(self, pName):
		mor = self.getCurrentProperty(pName)
		return self.serverConnection.getVimService().createExactManagedObject(mor) if mor != None else None

	def getPropertiesByPaths(self, propPaths):
		pht = self.serverConnection.getVimService().retrieveProperties( [ManagedObject(self)], self.getMOR().getType(), propPaths)
		return pht[0] if pht!=None and len(pht)>0 else None

	def getManagedObjects(self, propName, mixedType=False):
		objs = self.getCurrentProperty(propName);
		mors = []

		if objs.__class__.__name__=='ArrayOfManagedObjectReference':
			mors = objs.ManagedObjectReference

		return self.serverConnection.getVimService().createExactManagedEntities(mors)

	def getDatastores(self, propName):
		return self.getManagedObjects(propName)

	def getNetworks(self, propName):
		return self.getManagedObjects(propName, True)

	def getFilter(self, propName):
		return self.getManagedObjects(propName)

	def getResourcePools(self, propName):
		return self.getManagedObjects(propName, True)

	def getTasks(self, propName):
		return self.getManagedObjects(propName)

	def getScheduledTasks(self, propName):
		return self.getManagedObjects(propName)

	def getViews(self, propName):
		return self.getManagedObjects(propName)

	def getHosts(self, propName):
		return self.getManagedObjects(propName)

	def waitForValues(self, filterProps, endWaitProps, expectedVals):
		version = ''
		endVals = []
		filterVals = []

		oSpec = self.serverConnection.getVimService().createObjectSpec(self.getMOR(), False, None)
		pSpec = self.serverConnection.getVimService().createPropertySpec(self.getMOR().getType(),
									filterProps == None or len(filterProps) == 0, filterProps)

		spec = self.serverConnection.getVimService().new('PropertyFilterSpec')
		spec.setObjectSet([oSpec])
		spec.setPropSet([pSpec])

		pc = self.getServerConnection().getServiceInstance().getPropertyCollector()
		pf = pc.createFilter(spec, True)

		reached = False;

		while (not reached):
			updateset = pc.waitForUpdates(version)
			if updateset == None : continue

			version = updateset.getVersion()
			filtupary = updateset.getFilterSet()
			if filtupary == None: continue

			for filtup in filtupary:
				if filtup == None: continue
				objupary = filtup.getObjectSet()
				for objup in objupary:
					if objup == None: continue;
					propchgary = objup.getChangeSet()
					for propchg in propchgary:
						self._updateValues(endWaitProps, endVals, propchg)
						self._updateValues(filterProps, filterVals, propchg)

			for chgi in range(0, len(endVals)) and not reached:
				for vali in range(0, len(expectedVals[chgi])) and not reached:
					expctdval = expectedVals[chgi][vali]
					reached = (expctdval == endVals[chgi]) or reached;
		pf.destroyPropertyFilter();

		return filterVals;

	def _updateValues(self, props, vals, propchg):
		for p in range(0, props):
			if props[p] in propchg.getName():
				vals[p] = propchg.getVal() if propchg.getOp() != self.serverConnection.getVimService().PropertyChangeOp().remove else ''

class ExtensibleManagedObject(ManagedObject):
	def __init__(self, sc, mor):
		super(ExtensibleManagedObject, self).__init__(sc, mor)


class ManagedEntity(ExtensibleManagedObject):

	def __init__(self, sc, mor):
		super(ManagedEntity, self).__init__(sc, mor)

	def getAlarmActionEnabled(self):
		aae = self.getCurrentProperty('alarmActionsEnabled')
		if aae!=None: return aae
		else: return False

	def getName(self):
		return self.getCurrentProperty('name')

	def getConfigIssue(self):
		return self.getCurrentProperty('configIssue')

	def getConfigStatus(self):
		return self.getCurrentProperty('configStatus')

	def getCustomValue(self):
		return self.getCurrentProperty('customValue')

	def getDeclaredAlarmState(self):
		return self.getCurrentProperty('declaredAlarmState')

	def getDisabledMethod(self):
		return self.getCurrentProperty('disabledMethod')

	def getEffectiveRole(self):
		return self.getCurrentProperty('effectiveRole')

	def getOverallStatus(self):
		return self.getCurrentProperty('overallStatus')

	def getParent(self):
		return self.getManagedObject('parent')

	def getPermission(self):
		return self.getCurrentProperty('permission')

	def getRecentTasks(self):
		return self.getTasks('recentTask')

	def getTag(self):
		return self.getCurrentProperty('tag')

	def getTriggeredAlarmState(self):
		return self.getCurrentProperty('triggeredAlarmState')

	def destroy_Task(self):
		taskMor = self.getVimService().Destroy_Task(self.getMOR())
		return Task(self.getServerConnection(), taskMor)

	def reload(self):
		self.getVimService().Reload(self.getMOR())

	def rename_Task(self, newName):
		taskMor = self.getVimService().Rename_Task(self.getMOR(), newName=newName)
		return Task(self.getServerConnection(), taskMor)


class Alarm(ExtensibleManagedObject):

	def __init__(self, sc, mor):
		super(Alarm, self).__init__(sc, mor)

	def getAlarmInfo(self):
		return self.getCurrentProperty('info')

	def getAssociatedEntity(self):
		return self.getCurrentProperty('info.entity')

	def reconfigureAlarm(self, spec):
		self.getVimService().ReconfigureAlarm(self.getMOR(), spec=spec)

	def removeAlarm(self):
		self.getVimService().RemoveAlarm(self.getMOR())


class AlarmManager(ManagedObject):
	def __init__(self, sc, mor):
		super(AlarmManager, self).__init__(sc, mor)

	def getDefaultExpression(self):
		return self.getCurrentProperty('defaultExpression')

	def getDescription(self):
		return self.getCurrentProperty('description')

	def acknowledgeAlarm(self, alarm, entity):
		self.getVimService().AcknowledgeAlarm(self.getMOR(), alarm=alarm, entity=entity)

	def areAlarmActionsEnabled(self, entity):
		return self.getVimService().AreAlarmActionsEnabled(self.getMOR(), entity=entity)

	def enableAlarmActions(self, entity, enabled):
		self.getVimService().EnableAlarmActions(self.getMOR(), entity=entity, enabled=enabled)

	def createAlarm(self, entity, alarmSpec):
		mor = self.getVimService().CreateAlarm(self.getMOR(), entity=entity, spec=alarmSpec)
		return Alarm(self.getServerConnection(), mor)

	def getAlarm(self, entity=None):
		mors = self.getVimService().GetAlarm(self.getMOR(), entity=entity)
		if mors == None: return []

		return [Alarm(self.getServerConnection(), m) for m in mors]

	def getAlarmState(self, entity):
		return self.getVimService().GetAlarmState(self.getMOR(), entity=entity)


class AuthorizationManager(ManagedObject):
	def __init__(self, sc, mor):
		super(AuthorizationManager, self).__init__(sc, mor)

	def getDescription(self):
		return self.getCurrentProperty('description')

	def getPrivilegeList(self):
		return self.getCurrentProperty('privilegeList')

	def getRoleList(self):
		return self.getCurrentProperty('roleList')

	def addAuthorizationRole(self, name, privIds=None):
		return self.getVimService().AddAuthorizationRole(self.getMOR(), name=name, privIds=privIds)

	def hasPrivilegeOnEntity(self, entity, sessionId, privId=None):
		return self.getVimService().HasPrivilegeOnEntity(self.getMOR(), entity=entity, sessionId=sessionId, privId=privId)

	def mergePermissions(self, srcRoleId, dstRoleId):
		self.getVimService().MergePermissions(self.getMOR(), srcRoleId=srcRoleId, dstRoleId=dstRoleId)

	def removeAuthorizationRole(self, roleId, failIfUsed):
		self.getVimService().RemoveAuthorizationRole(self.getMOR(), roleId=roleId, failIfUsed=failIfUsed)

	def removeEntityPermission(self, entity, user, isGroup):
		self.getVimService().RemoveEntityPermission(self.getMOR(), entity=entity, user=user, isGroup=isGroup)

	def resetEntityPermissions(self, entity, permissions=None):
		self.getVimService().ResetEntityPermissions(self.getMOR(), entity=entity, permissions=permissions)

	def retrieveEntityPermissions(self, entity, inherited):
		return self.getVimService().RetrieveEntityPermissions(self.getMOR(), entity=entity, inherited=inherited)

	def retrieveAllPermissions(self):
		return self.getVimService().RetrieveAllPermissions(self.getMOR())

	def retrieveRolePermissions(self, roleId):
		return self.getVimService().RetrieveRolePermissions(self.getMOR(), roleId=roleId)

	def setEntityPermissions(self, entity, permissions=None):
		self.getVimService().SetEntityPermissions(self.getMOR(), entity=entity, permissions=permissions)

	def updateAuthorizationRole(self, roleId, newName, privIds=None):
		self.getVimService().UpdateAuthorizationRole(self.getMOR(), roleId=roleId, newName=newName, privIds=privIds)

class ComputeResource(ManagedEntity):
	def __init__(self, sc, mor):
		super(ComputeResource, self).__init__(sc, mor)

	def getConfigurationEx(self):
		return self.getCurrentProperty('configurationEx')

	def getDatastores(self):
		return self.getDatastores('datastore')

	def getNetworks(self):
		return ManagedEntity.getNetworks(self, 'network')

	def getHosts(self):
		return ManagedEntity.getHosts(self, 'host')


	def getResourcePool(self):
		return self.getManagedObject('resourcePool')

	def getEnvironmentBrowser(self):
		return self.getManagedObject('environmentBrowser')

	def getSummary(self):
		return self.getCurrentProperty('summary')

	def reconfigureComputeResource_Task(self, spec, modify):
		taskMOR = self.getVimService().ReconfigureComputeResource_Task(self.getMOR(), spec=spec, modify=modify)
		return Task(self.getServerConnection(), taskMOR)

class ClusterComputeResource(ComputeResource):
	def __init__(self, sc, mor):
		super(ClusterComputeResource, self).__init__(sc, mor)

	def getActionHistory(self):
		return self.getCurrentProperty('actionHistory')

	def getConfiguration(self):
		return self.getCurrentProperty('configuration')

	def getDrsFault(self):
		return self.getCurrentProperty('drsFault')

	def getDrsRecommendation(self):
		return self.getCurrentProperty('drsRecommendation')

	def getMigrationHistory(self):
		return self.getCurrentProperty('migrationHistory')

	def getRecommendation(self):
		return self.getCurrentProperty('recommendation')

	def addHost_Task(self, spec, asConnected, resourcePool=None, targetlicense=None):
		taskMOR = self.getVimService().AddHost_Task(self.getMOR(), spec=spec, asConnected=asConnected, resourcePool=resourcePool, license=targetlicense)
		return Task(self.getServerConnection(), taskMOR)

	def applyRecommendation(self, key):
		self.getVimService().ApplyRecommendation(self.getMOR(), key=key)

	def cancelRecommendation(self, key):
		self.getVimService().CancelRecommendation(self.getMOR(), key=key)

	def clusterEnterMaintenanceMode(self, hosts, option=None):
		return self.getVimService().ClusterEnterMaintenanceMode(self.getMOR(), host=hosts, option=option)

	def moveHostInto_Task(self, host, resourcePool=None):
		taskMOR = self.getVimService().MoveHostInto_Task(self.getMOR(), host=host, resourcePool=resourcePool)
		return Task(self.getServerConnection(), taskMOR)

	def moveInto_Task(self, hosts):
		taskMOR = self.getVimService().MoveInto_Task(self.getMOR(), host=hosts)
		return Task(self.getServerConnection(), taskMOR)

	def recommendHostsForVm(self, vm, pool=None):
		return self.getVimService().RecommendHostsForVm(self.getMOR(), vm=vm, pool=pool)

	def reconfigureCluster_Task(self, spec, modify):
		taskMOR = self.getVimService().ReconfigureCluster_Task(self.getMOR(), spec=spec, modify=modify)
		return Task(self.getServerConnection(), taskMOR)

	def refreshRecommendation(self):
		self.getVimService().RefreshRecommendation(self.getMOR())

	def retrieveDasAdvancedRuntimeInfo(self):
		return self.getVimService().RetrieveDasAdvancedRuntimeInfo(self.getMOR())


class Profile(ManagedObject):
	def __init(self, sc, mor):
		super(Profile, self).__init__(sc, mor)

	def getComplianceStatus(self):
		return self.getCurrentProperty('info')

	def getConfig(self):
		return self.getCurrentProperty('config')

	def getCreatedTime(self):
		return self.getCurrentProperty('createdTime')

	def getDescriptioin(self):
		return self.getCurrentProperty('description')

	def getEntity(self):
		return self.getManagedObjects('entity')

	def getModifiedTime(self):
		return self.getCurrentProperty('modifiedTime')

	def getName(self):
		return self.getCurrentProperty('name')

	def associateProfile(self, mes):
		self.getVimService().AssociateProfile(self.getMOR(), entity=mes)

	def checkProfileCompliance_Task(self, mes=None):
		taskMor = self.getVimService().CheckProfileCompliance_Task(self.getMOR(), entity=mes)
		return Task(self.getServerConnection(), taskMor)

	def destroyProfile(self):
		self.getVimService().DestroyProfile(self.getMOR())

	def exportProfile(self):
		return self.getVimService().ExportProfile(self.getMOR())


	def dissociateProfile(self, mes=None):
		self.getVimService().DissociateProfile(self.getMOR(), entity=mes)

	def retrieveDescription(self):
		return self.getVimService().RetrieveDescription(self.getMOR())


class ClusterProfile(Profile):
	def __init__(self, sc, mor):
		super(ClusterProfile, self).__init__(sc, mor)

	def updateClusterProfile(self, config):
		self.getVimService().UpdateClusterProfile(self.getMOR(), config=config)


class ProfileManager(ManagedObject):
	def __init__(self, sc, mor):
		super(ProfileManager, self).__init__(sc, mor)

	def getProfile(self):
		mors = self.getCurrentProperty('profile')
		return self._convert2Profiles(mors)

	def createProfile(self, createSpec):
		profileMor = self.getVimService().CreateProfile(self.getMOR(), createSpec=createSpec)
		return Profile(self.getServerConnection(), profileMor)

	def findAssociatedProfile(self, entity):
		mors = self.getVimService().FindAssociatedProfile(self.getMOR(), entity=entity)
		return self._convert2Profiles(mors)

	def queryPolicyMetadata(self, policyName, profile=None):
		return self.getVimService().QueryPolicyMetadata(self.getMOR(), policyName=policyName, profile=profile)

	def _convert2Profiles(self, mors):
		pfs = []
		for p in mors:
			pfs.append(Profile(self.getServerConnection(), p))

		return pfs


class ClusterProfileManager(ProfileManager):
	def __init__(self, sc, mor):
		super(ClusterProfileManager, self).__init__(sc, mor)


class View(ManagedObject):
	def __init__(self, sc, mor):
		super(View, self).__init__(sc, mor)

	def destroyView(self):
		self.getVimService().DestroyView(self.getMOR())

class ManagedObjectView(View):
	def __init__(self, sc, mor):
		super(ManagedObjectView, self).__init__(sc, mor)

	def getView(self):
		return self.getManagedObjects('view', True)


class ContainerView(ManagedObjectView):
	def __init__(self, sc, mor):
		super(ContainerView, self).__init__(sc, mor)


	def getContainer(self):
		return self.getManagedObject('container')


	def getRecursive(self):
		return self.getCurrentProperty('recursive').booleanValue()

	def getType(self):
		return self.getCurrentProperty('type')

class InventoryView(ManagedObjectView):
	def __init__(self, sc, mor):
		super(InventoryView, self).__init__(sc, mor)

	def closeInventoryViewFolder(self, entities):
		mors = self.getVimService().CloseInventoryViewFolder(self.getMOR(), entity=entities)
		return self.serverConnection.getVimService().createManagedEntities(self.getServerConnection(), mors)

	def openInventoryViewFolder(self, entities):
		mors = self.getVimService().OpenInventoryViewFolder(self.getMOR(), entity=entities)
		return self.serverConnection.getVimService().createManagedEntities(self.getServerConnection(), mors)


class ListView(ManagedObjectView):
	def __init__(self, sc, mor):
		super(ListView, self).__init__(sc, mor)

	def modifyListView(self, adds=None, removes=None):
		mors = self.getVimService().ModifyListView(self.getMOR(), add=adds, remove=removes)
		return self.serverConnection.getVimService().createManagedEntities(self.getServerConnection(), mors)

	def resetListView(self, entities=None):
		mors = self.getVimService().ResetListView(self.getMOR(), obj=entities)
		return self.serverConnection.getVimService().createManagedEntities(self.getServerConnection(), mors)

	def resetListViewFromView(self, view):
		self.getVimService().ResetListViewFromView(self.getMOR(), view=view)

class ViewManager (ManagedObject):
	def __init__(self, sc, mor):
		super(ViewManager, self).__init__(sc, mor)

	def getViewList(self):
		return self.getViews('viewList')


	def createContainerView(self, container, types, recursive):
		return ContainerView(self.getServerConnection(),
				self.getVimService().CreateContainerView(self.getMOR(), container=container, type=types, recursive=recursive))
	def createInventoryView(self):
		return InventoryView(self.getServerConnection(),
				self.getVimService().CreateInventoryView(self.getMOR()))

	def createListView(self, mos=None):
		return ListView(self.getServerConnection(),
				self.getVimService().CreateListView(self.getMOR(), obj=mos))

	def createListViewFromView(self, view):
		mor = self.getVimService().CreateListViewFromView(self.getMOR(), view=view)
		return ListView(self.getServerConnection(), mor)

class CustomFieldsManager(ManagedObject):
	def __init__(self, sc, mor):
		super(CustomFieldsManager, self).__init__(sc, mor)

	def getField(self):
		return self.getCurrentProperty('field')

	def addCustomFieldDef(self, name, moType=None, fieldDefPolicy=None, fieldPolicy=None):
		return self.getVimService().AddCustomFieldDef(self.getMOR(), name=name, moType=moType, fieldDefPolicy=fieldDefPolicy, fieldPolicy=fieldPolicy)

	def removeCustomFieldDef(self, key):
		self.getVimService().RemoveCustomFieldDef(self.getMOR(), key=key)

	def renameCustomFieldDef(self, key, name):
		self.getVimService().RenameCustomFieldDef(self.getMOR(), key=key, name=name)

	def setField(self, entity, key, value):
		self.getVimService().SetField(self.getMOR(), entity=entity, key=key, value=value)

class CustomizationSpecManager(ManagedObject):
	def __init__(self, sc, mor):
		super(CustomizationSpecManager, self).__init__(sc, mor)

	def getEncryptionKey(self):
		return self.getCurrentProperty('encryptionKey')

	def getInfo(self):
		return self.getCurrentProperty('info')

	def checkCustomizationResources(self, guestOs):
		self.getVimService().CheckCustomizationResources(self.getMOR(), guestOs=guestOs)

	def createCustomizationSpec(self, item):
		self.getVimService().CreateCustomizationSpec(self.getMOR(), item=item)

	def customizationSpecItemToXml(self, item):
		return self.getVimService().CustomizationSpecItemToXml(self.getMOR(), item=item)

	def deleteCustomizationSpec(self, name):
		self.getVimService().DeleteCustomizationSpec(self.getMOR(), name=name)

	def doesCustomizationSpecExist(self, name):
		return self.getVimService().DoesCustomizationSpecExist(self.getMOR(), name=name)

	def duplicateCustomizationSpec(self, name, newName):
		self.getVimService().DuplicateCustomizationSpec(self.getMOR(), name=name, newName=newName)

	def getCustomizationSpec(self, name):
		return self.getVimService().GetCustomizationSpec(self.getMOR(), name=name)

	def overwriteCustomizationSpec(self, item):
		self.getVimService().OverwriteCustomizationSpec(self.getMOR(), item=item)

	def renameCustomizationSpec(self, name, newName):
		self.getVimService().RenameCustomizationSpec(self.getMOR(), name=name, newName=newName)

	def xmlToCustomizationSpecItem(self, specItemXml):
		return self.getVimService().XmlToCustomizationSpecItem(self.getMOR(), specItemXml=specItemXml)


class Datacenter(ManagedEntity):
	def __init__(self, sc, mor):
		super(Datacenter, self).__init__(sc, mor)

	def getVmFolder(self): return self.getManagedObject('vmFolder')

	def getHostFolder(self):return self.getManagedObject('hostFolder')

	def getDatastores(self): return ManagedEntity.getDatastores(self, 'datastore')

	def getDatastoreFolder(self): return self.getManagedObject('datastoreFolder')

	def getNetworkFolder(self): return self.getManagedObject('networkFolder')

	def getNetworks(self): return ManagedEntity.getNetworks(self, 'network')

	def powerOnMultiVM_Task(self, vm, option=None):
		tmor = self.getVimService().PowerOnMultiVM_Task(self.getMOR(), vm=vm, option=option)
		return Task(self.getServerConnection(), tmor)

	def queryConnectionInfo(self, hostname, port, username, password, sslThumbprint=None):
		return self.getVimService().QueryConnectionInfo(self.getMOR(), hostname=hostname, port=port, username=username, password=password, sslThumbprint=sslThumbprint)


class Datastore(ManagedEntity):
	def __init__(self, sc, mor):
		super(Datastore, self).__init__(sc, mor)

	def getBrowser(self): return self.getManagedObject('browser')

	def getCapability(self): return self.getCurrentProperty('capability')

	def getHost(self): return self.getCurrentProperty('host')

	def getInfo(self): return self.getCurrentProperty('info')

	def getIormConfiguration(self): return self.getCurrentProperty('iormConfiguration')

	def getSummary(self): return self.getCurrentProperty('summary')

	def getVms(self): return ManagedEntity.getVms(self, 'vm')

	def datastoreEnterMaintenanceMode(self): return self.getVimService().DatastoreEnterMaintenanceMode(self.getMOR())

	def datastoreExitMaintenanceMode_Task(self):
		taskMor = self.getVimService().DatastoreExitMaintenanceMode_Task(self.getMOR())
		return Task(self.getServerConnection(), taskMor)

	def destroyDatastore(self): self.getVimService().DestroyDatastore(self.getMOR())

	def refreshDatastore(self): self.getVimService().RefreshDatastore(self.getMOR())

	def refreshDatastoreStorageInfo(self): self.getVimService().RefreshDatastoreStorageInfo(self.getMOR())

	def renameDatastore(self, newName): self.getVimService().RenameDatastore(self.getMOR(), newName=newName)

	def updateVirtualMachineFiles_Task(self, mountPathDatastoreMapping):
		mor = self.getVimService().UpdateVirtualMachineFiles_Task(self.getMOR(), mountPathDatastoreMapping=mountPathDatastoreMapping)
		return Task(self.getServerConnection(), mor)

class DiagnosticManager(ManagedObject):
	def __init__(self, sc, mor):
		super(DiagnosticManager, self).__init__(sc, mor)

	def browseDiagnosticLog(self, host, key, start=None, lines=None):
		return self.getVimService().BrowseDiagnosticLog(self.getMOR(),
														host=host, key=key, start=start, lines=lines)

	def generateLogBundles_Task(self, includeDefault, host=None):
		mor = self.getVimService().GenerateLogBundles_Task(self.getMOR(),
														   includeDefault=includeDefault, host=host)
		return Task(self.getServerConnection(), mor)

	def queryDescriptions(self, host=None):
		return self.getVimService().QueryDescriptions(self.getMOR(), host=host)

class Network(ManagedEntity):
	def __init__(self, sc, mor):
		super(Network, self).__init__(sc, mor)

	def getHosts(self) : return ManagedEntity.getHosts(self, 'host')

	def getName(self): return self.getCurrentProperty('name')

	def getSummary(self): return self.getCurrentProperty('summary')

	def getVms(self): return ManagedEntity.getVms('vm')

	def destroyNetwork(self): self.getVimService().DestroyNetwork(self.getMOR())


class DistributedVirtualPortgroup(Network):
	def __init__(self, sc, mor):
		super(DistributedVirtualPortgroup, self).__init__(sc, mor)

	def getConfig(self): return self.getCurrentProperty('config')

	def getKey(self): return self.getCurrentProperty('key')

	def getPortKeys(self): return self.getCurrentProperty('portKeys')

	def reconfigureDVPortgroup_Task(self, spec):
		mor = self.getVimService().ReconfigureDVPortgroup_Task(self.getMOR(), spec=spec)
		return Task(self.getServerConnection(), mor)


class DistributedVirtualSwitch(ManagedEntity):
	def __init__(self, sc, mor):
		super(DistributedVirtualSwitch, self).__init__(sc, mor)


	def getCapability(self): return self.getCurrentProperty('capability')

	def getConfig(self): return self.getCurrentProperty('config')

	def getNetworkResourcePool(self): return self.getCurrentProperty('networkResourcePool')

	def getPortgroup(self):
		pgMors = self.getCurrentProperty('portgroup')
		if pgMors==None: return []

		dvpgs = []
		for dv in pgMors:
			dvpgs.append(DistributedVirtualPortgroup(self.getServerConnection(), dv))

		return dvpgs;


	def getSummary(self): return self.getCurrentProperty('summary')

	def getUuid(self): return self.getCurrentProperty('uuid')

	def addDVPortgroup_Task(self, spec):
		taskMor = self.getVimService().AddDVPortgroup_Task(self.getMOR(), spec=spec)
		return Task(self.getServerConnection(), taskMor)

	def addNetworkResourcePool(self, configSpec):
		self.getVimService().AddNetworkResourcePool(self.getMOR(), configSpec=configSpec)

	def enableNetworkResourceManagement(self, enable):
		self.getVimService().EnableNetworkResourceManagement(self.getMOR(), enable=enable)

	def fetchDVPortKeys(self, criteria=None):
		return self.getVimService().FetchDVPortKeys(self.getMOR(), criteria=criteria)

	def fetchDVPorts(self, criteria=None):
		return self.getVimService().FetchDVPorts(self.getMOR(), criteria=criteria)

	def mergeDvs_Task(self, dvs):
		taskMor = self.getVimService().MergeDvs_Task(self.getMOR(), dvs=dvs)
		return Task(self.getServerConnection(), taskMor)


	def moveDVPort_Task(self, portKeys, destinationPortgroupKey=None):
		taskMor = self.getVimService().MoveDVPort_Task(self.getMOR(), portKey=portKeys, destinationPortgroupKey=destinationPortgroupKey)
		return Task(self.getServerConnection(), taskMor)

	def performDvsProductSpecOperation_Task(self, operation, productSpec=None):
		taskMor = self.getVimService().PerformDvsProductSpecOperation_Task(self.getMOR(), operation=operation, productSpec=productSpec)
		return Task(self.getServerConnection(), taskMor)

	def queryUsedVlanIdInDvs(self):
		return self.getVimService().QueryUsedVlanIdInDvs(self.getMOR())

	def reconfigureDvs_Task(self, spec):
		taskMor = self.getVimService().ReconfigureDvs_Task(self.getMOR(), spec=spec)
		return Task(self.getServerConnection(), taskMor)

	def rectifyDvsHost_Task(self, hosts=None):
		mor = self.getVimService().RectifyDvsHost_Task(self.getMOR(), hosts=hosts)
		return Task(self.getServerConnection(), mor)

	def refreshDVPortState(self, portKeys=None):
		self.getVimService().RefreshDVPortState(self.getMOR(), portKeys=portKeys)

	def removeNetworkResourcePool(self, key):
		self.getVimService().RemoveNetworkResourcePool(self.getMOR(), key=key)

	def updateDvsCapability(self, capability):
		self.getVimService().UpdateDvsCapability(self.getMOR(), capability=capability)

	def updateNetworkResourcePool(self, configSpec):
		self.getVimService().UpdateNetworkResourcePool(self.getMOR(), configSpec=configSpec)

	def reconfigureDVPort_Task(self, port):
		mor = self.getVimService().ReconfigureDVPort_Task(self.getMOR(), port=port)
		return Task(self.getServerConnection(), mor)



class DistributedVirtualSwitchManager(ManagedObject):
	def __init__(self, sc, mor):
		super(DistributedVirtualSwitchManager, sc).__init__(sc, mor)

	def queryAvailableDvsSpec(self):
		return self.getVimService().QueryAvailableDvsSpec(self.getMOR())

	def queryCompatibleHostForExistingDvs(self, container, recursive, dvs):
		mors = self.getVimService().QueryCompatibleHostForExistingDvs(self.getMOR(), container=container, recursive=recursive, dvs=dvs)

		hosts=[]
		for m in mors:
			hosts.append(HostSystem(self.getServerConnection(), m))

		return hosts

	def queryCompatibleHostForNewDvs(self, container, recursive, switchProductSpec=None):
		mors = self.getVimService().QueryCompatibleHostForNewDvs(self.getMOR(), container=container, recursive=recursive, switchProductSpec=switchProductSpec)

		hosts = []
		for m in mors:
			hosts.append(HostSystem(self.getServerConnection(), m))

		return hosts

	def queryDvsCompatibleHostSpec(self, switchProductSpec=None):
		return self.getVimService().QueryDvsCompatibleHostSpec(self.getMOR(), switchProductSpec=switchProductSpec)

	def queryDvsCheckCompatibility(self, hostContainer, dvsProductSpec=None, hostFilterSpec=None):
		return self.getVimService().QueryDvsCheckCompatibility(self.getMOR(), hostContainer=hostContainer, dvsProductSpec=dvsProductSpec, hostFilterSpec=hostFilterSpec)

	def queryDvsConfigTarget(self, host=None, dvs=None):
		return self.getVimService().QueryDvsConfigTarget(self.getMOR(), host=host, dvs=dvs)

	def queryDvsByUuid(self, uuid):
		mor = self.getVimService().QueryDvsByUuid(self.getMOR(), uuid=uuid)
		return DistributedVirtualSwitch(self.getServerConnection(), mor)

	def queryDvsFeatureCapability(self, switchProductSpec=None):
		return self.getVimService().QueryDvsFeatureCapability(self.getMOR(), switchProductSpec=switchProductSpec)

	def rectifyDvsOnHost_Task(self, hosts):
		taskMor = self.getVimService().RectifyDvsOnHost_Task(self.getMOR(), hosts=hosts)
		return Task(self.getServerConnection(), taskMor)

class EnvironmentBrowser(ManagedObject):
	def __init__(self, sc, mor):
		super(EnvironmentBrowser, self).__init__(sc, mor)

	def getDatastoreBrowser(self):
		return self.getManagedObject('datastoreBrowser')

	def queryConfigOption(self, key=None, host=None):
		return self.getVimService().QueryConfigOption(self.getMOR(), key=key, host=host)

	def queryConfigOptionDescriptor(self):
		return self.getVimService().QueryConfigOptionDescriptor(self.getMOR())

	def queryConfigTarget(self, host=None):
		return self.getVimService().QueryConfigTarget(self.getMOR(), host=host)

	def queryTargetCapabilities(self, host=None):
		return self.getVimService().QueryTargetCapabilities(self.getMOR(), host=host)

class HistoryCollector(ManagedObject):
	def __init__(self, sc, mor):
		super(HistoryCollector, self).__init__(sc, mor)

	def destroyCollector(self):
		self.getVimService().DestroyCollector(self.getMOR())

	def resetCollector(self):
		self.getVimService().ResetCollector(self.getMOR())

	def rewindCollector(self):
		self.getVimService().RewindCollector(self.getMOR())

	def setCollectorPageSize(self, maxCount):
		self.getVimService().SetCollectorPageSize(self.getMOR(), maxCount=maxCount)


class EventHistoryCollector(HistoryCollector):
	def __init__(self, sc, mor):
		super(EventHistoryCollector, self).__init__(sc, mor)

	def getFilter(self):
		return self.getCurrentProperty('filter')

	def getLatestPage(self):
		return self.getCurrentProperty('latestPage')

	def readNextEvents(self, maxCount):
		return self.getVimService().ReadNextEvents(self.getMOR(), maxCount=maxCount)

	def readPreviousEvents(self, maxCount):
		return self.getVimService().ReadPreviousEvents(self.getMOR(), maxCount=maxCount)

class EventManager(ManagedObject):
	def __init__(self, sc, mor):
		super(EventManager, self).__init__(sc, mor)

	def getDescription(self):
		return self.getCurrentProperty('description')

	def getLatestEvent(self):
		return self.getCurrentProperty('latestEvent')

	def getMaxCollector(self):
		return self.getCurrentProperty('maxCollector').intValue()

	def createCollectorForEvents(self, targetfilter):
		return EventHistoryCollector(self.getServerConnection(),
				self.getVimService().CreateCollectorForEvents(self.getMOR(), filter=targetfilter))

	def logUserEvent(self, entity, msg):
		self.getVimService().LogUserEvent(self.getMOR(), entity=entity, msg=msg)

	def postEvent(self, eventToPost, taskInfo=None):
		self.getVimService().PostEvent(self.getMOR(), eventToPost=eventToPost, taskInfo=taskInfo)

	def queryEvents(self, targetfilter):
		return self.getVimService().QueryEvents(self.getMOR(), filter=targetfilter)

	def retrieveArgumentDescription(self, eventTypeId):
		return self.getVimService().RetrieveArgumentDescription(self.getMOR(), eventTypeId=eventTypeId)

class ExtensionManager(ManagedObject):
	def __init__(self, sc, mor):
		super(ExtensionManager, self).__init__(sc, mor)

	def getExtensionList(self):
		return self.getCurrentProperty('extensionList')

	def queryManagedBy(self, extensionKey):
		mors = self.getVimService().QueryManagedBy(self.getMOR(), extensionKey=extensionKey)
		return self.serverConnection.getVimService().createManagedEntities(self.getServerConnection(), mors)

	def setPublicKey(self, extensionKey, publicKey):
		self.getVimService().SetPublicKey(self.getMOR(), extensionKey=extensionKey, publicKey=publicKey)

	def unregisterExtension(self, extensionKey):
		self.getVimService().UnregisterExtension(self.getMOR(), extensionKey=extensionKey)

	def updateExtension(self, extension):
		self._encodeUrl(extension);

		self.getVimService().UpdateExtension(self.getMOR(), extension=extension)

	def registerExtension(self, extensionKey):
		self._encodeUrl(extensionKey)
		self.getVimService().RegisterExtension(self.getMOR(), extensionKey=extensionKey)

	def findExtension(self, extensionKey):
		return self.getVimService().FindExtension(self.getMOR(), extensionKey=extensionKey)

	def _encodeUrl(self, extension):
		if extension.client!=None:
			for eci in extension.client:
				eci = eci.replace('&', '&amp')
		if extension.server!=None:
			for eci in extension.server:
				eci = eci.replace('&', '&amp')


class FileManager(ManagedObject):
	def __init__(self, sc, mor):
		super(FileManager, self).__init__(sc, mor)

	def changeOwner(self, name, datacenter, owner):
		self.getVimService().ChangeOwner(self.getMOR(), name=name, datacenter=datacenter, owner=owner)

	def copyDatastoreFile_Task(self, sourceName, sourceDatacenter, destinationName, destinationDatacenter=None, force=None):
		taskMor = self.getVimService().CopyDatastoreFile_Task(self.getMOR(), sourceName=sourceName, sourceDatacenter=sourceDatacenter, destinationName=destinationName, destinationDatacenter=destinationDatacenter, force=force)
		return Task(self.getServerConnection(), taskMor)

	def deleteDatastoreFile_Task(self, name, datacenter=None):
		taskMor = self.getVimService().DeleteDatastoreFile_Task(self.getMOR(), name=name, datacenter=datacenter)
		return Task(self.getServerConnection(), taskMor)

	def makeDirectory(self, name, datacenter=None, createParentDirectories=None):
		self.getVimService().MakeDirectory(self.getMOR(), name=name, datacenter=datacenter, createParentDirectories=createParentDirectories)

	def moveDatastoreFile_Task(self, sourceName, sourceDatacenter, destinationName, destinationDatacenter=None, force=None):
		taskMor = self.getVimService().MoveDatastoreFile_Task(self.getMOR(), sourceName=sourceName, sourceDatacenter=sourceDatacenter, destinationName=destinationName, destinationDatacenter=destinationDatacenter, force=force)
		return Task(self.getServerConnection(), taskMor)


class Folder(ManagedEntity):
	def __init__(self, sc, mor):
		super(Folder, self).__init__(sc, mor)

	def getChildEntity(self):
		mors = self.getCurrentProperty('childEntity')

		if mors == None: return []

		mes = []

		for m in mors:
			mes.append(self.serverConnection.getVimService().createExactManagedEntity(m))

		return mes;

	def getChildType(self): return self.getCurrentProperty('childType')

	def addStandaloneHost_Task(self, spec, compResSpec, addConnected, targetlicense=None):
		return Task(self.getServerConnection(),
			self.getVimService().AddStandaloneHost_Task(self.getMOR(), spec=spec, compResSpec=compResSpec, addConnected=addConnected, license=targetlicense))

	def createCluster(self, name, spec):
		return ClusterComputeResource(self.getServerConnection(),
			self.getVimService().CreateCluster(self.getMOR(), name=name, spec=spec) )

	def createClusterEx(self, name, spec):
		return ClusterComputeResource(self.getServerConnection(),
			self.getVimService().CreateClusterEx(self.getMOR(), name=name, spec=spec) )

	def createDatacenter(self, name):
		return Datacenter(self.getServerConnection(),
			self.getVimService().CreateDatacenter(self.getMOR(), name=name) )

	def createDVS_Task(self, spec):
		taskMor = self.getVimService().CreateDVS_Task(self.getMOR(), spec=spec)
		return Task(self.getServerConnection(), taskMor)


	def createFolder(self, name):
		return Folder(self.getServerConnection(),
			self.getVimService().CreateFolder(self.getMOR(), name=name) )

	def createStoragePod(self, name):
		mor = self.getVimService().CreateStoragePod(self.getMOR(), name=name)
		return StoragePod(self.getServerConnection(), mor)

	def createVM_Task(self, config, pool, host=None):
		return Task(self.getServerConnection(),
			self.getVimService().CreateVM_Task(self.getMOR(), config=config, pool=pool, host=host) )

	def moveIntoFolder_Task(self, targetlist):
		return Task( self.getServerConnection(),
			self.getVimService().MoveIntoFolder_Task(self.getMOR(), list=targetlist) )

	def registerVM_Task(self, path, name, asTemplate, pool=None, host=None):
		return Task( self.getServerConnection(),
			self.getVimService().RegisterVM_Task(self.getMOR(), path=path, name=name, asTemplate=asTemplate, pool=pool, host=host) )

	def unregisterAndDestroy_Task(self):
		return Task( self.getServerConnection(),
			self.getVimService().UnregisterAndDestroy_Task(self.getMOR()) )


class GuestAuthManager(ManagedObject):
	def __init__(self, sc, mor, vm):
		super(GuestAuthManager, self).__init__(sc, mor)
		self.vm = vm

	def getVM(self): return self.vm

	def acquireCredentialsInGuest(self, vm, requestedAuth, sessionID=None):
		return self.getVimService().AcquireCredentialsInGuest(self.getMOR(), vm=vm, requestedAuth=requestedAuth, sessionID=sessionID)

	def releaseCredentialsInGuest(self, vm, auth):
		self.getVimService().ReleaseCredentialsInGuest(self.getMOR(), vm=vm, auth=auth)

	def ValidateCredentialsInGuest(self, vm, auth):
		self.getVimService().ValidateCredentialsInGuest(self.getMOR(), vm=vm, auth=auth)


class GuestFileManager(ManagedObject):
	def __init__(self, sc, mor, vm):
		super(GuestFileManager, self).__init__(sc, mor)
		self.vm = vm

	def getVM(self): return self.vm

	def changeFileAttributesInGuest(self, vm, auth, guestFilePath, fileAttributes):
		self.getVimService().ChangeFileAttributesInGuest(self.getMOR(), vm=vm, auth=auth, guestFilePath=guestFilePath, fileAttributes=fileAttributes)

	def createTemporaryDirectoryInGuest(self, vm, auth, prefix, suffix, directoryPath=None):
		return self.getVimService().CreateTemporaryDirectoryInGuest(self.getMOR(), vm=vm, auth=auth, prefix=prefix, suffix=suffix, directoryPath=directoryPath)

	def createTemporaryFileInGuest(self, vm, auth, prefix, suffix, directoryPath=None):
		return self.getVimService().CreateTemporaryFileInGuest(self.getMOR(), vm=vm, auth=auth, prefix=prefix, suffix=suffix, directoryPath=directoryPath)

	def deleteDirectoryInGuest(self, vm, auth, directoryPath, recursive):
		self.getVimService().DeleteDirectoryInGuest(self.getMOR(), vm=vm, auth=auth, directoryPath=directoryPath, recursive=recursive)

	def deleteFileInGuest(self, vm, auth, filePath):
		self.getVimService().DeleteFileInGuest(self.getMOR(), vm=vm, auth=auth, filePath=filePath)

	def initiateFileTransferFromGuest(self, vm, auth, guestFilePath):
		return self.getVimService().InitiateFileTransferFromGuest(self.getMOR(), vm=vm, auth=auth, guestFilePath=guestFilePath)

	def initiateFileTransferToGuest(self, vm, auth, guestFilePath, fileAttributes, fileSize, overwrite):
		return self.getVimService().InitiateFileTransferToGuest(self.getMOR(), vm=vm, auth=auth, guestFilePath=guestFilePath, fileAttributes=fileAttributes, fileSize=fileSize, overwrite=overwrite)

	def listFilesInGuest(self, vm, auth, filePath, index=None, maxResults=None, matchPattern=None):
		return self.getVimService().ListFilesInGuest(self.getMOR(), vm=vm, auth=auth, filePath=filePath, index=index, maxResults=maxResults, matchPattern=matchPattern)

	def makeDirectoryInGuest(self, vm, auth, directoryPath, createParentDirectories):
		return self.getVimService().MakeDirectoryInGuest(self.getMOR(), vm=vm, auth=auth, directoryPath=directoryPath, createParentDirectories=createParentDirectories)

	def moveDirectoryInGuest(self, auth, srcDirectoryPath, dstDirectoryPath):
		self.getVimService().MoveDirectoryInGuest(self.etMOR(), self.vm.getMOR(), auth, srcDirectoryPath, dstDirectoryPath)

	def moveFileInGuest(self, vm, auth, srcFilePath, dstFilePath, overwrite):
		self.getVimService().MoveFileInGuest(self.getMOR(), vm=vm, auth=auth, srcFilePath=srcFilePath, dstFilePath=dstFilePath, overwrite=overwrite)


class GuestOperationsManager(ManagedObject):
	def __init__(self, sc, mor):
		super(GuestOperationsManager, self).__init__(sc, mor)


	def getAuthManager(self, vm):
		mor = self.getCurrentProperty('authManager')
		return GuestAuthManager(self.getServerConnection(), mor, vm)


	def getFileManager(self, vm):
		mor = self.getCurrentProperty('fileManager')
		return GuestFileManager(self.getServerConnection(), mor, vm)

	def getProcessManager(self, vm):
		mor = self.getCurrentProperty('processManager')
		return GuestProcessManager(self.getServerConnection(), mor, vm)

class GuestProcessManager(ManagedObject):
	def __init__(self, sc, mor, vm):
		super(GuestProcessManager, self).__init__(sc, mor)
		self.vm = vm

	def getVM(self): return self.vm

	def listProcessesInGuest(self, vm, auth, pids=None):
		return self.getVimService().ListProcessesInGuest(self.getMOR(), vm=vm, auth=auth, pids=pids)

	def readEnvironmentVariableInGuest(self, vm, auth, names=None):
		return self.getVimService().ReadEnvironmentVariableInGuest(self.getMOR(), vm=vm, auth=auth, names=names)

	def startProgramInGuest(self, vm, auth, spec):
		return self.getVimService().StartProgramInGuest(self.getMOR(), vm=vm, auth=auth, spec=spec)

	def terminateProcessInGuest(self, vm, auth, pid):
		self.getVimService().TerminateProcessInGuest(self.getMOR(), vm=vm, auth=auth, pid=pid)


class HostAuthenticationStore(ManagedObject):
	def __init__(self, sc, mor):
		super(HostAuthenticationStore, self).__init__(sc, mor)


	def getInfo(self):
		return self.getCurrentProperty('info')


class HostDirectoryStore(HostAuthenticationStore):
	def __init__(self, sc, mor):
		super(HostDirectoryStore, self).__init__(sc, mor)


class HostActiveDirectoryAuthentication(HostDirectoryStore):
	def __init__(self, sc, mor):
		super(HostActiveDirectoryAuthentication, self).__init__(sc, mor)

	def importCertificateForCAM_Task(self, certPath, camServer):
		mor = self.getVimService().ImportCertificateForCAM_Task(self.getMOR(), certPath=certPath, camServer=camServer)
		return Task(self.getServerConnection(), mor)

	def joinDomain_Task(self, domainName, userName, password):
		mor = self.getVimService().JoinDomain_Task(self.getMOR(), domainName=domainName, userName=userName, password=password)
		return Task(self.getServerConnection(), mor)

	def joinDomainWithCAM_Task(self, domainName, camServer):
		mor = self.getVimService().JoinDomainWithCAM_Task(self.getMOR(), domainName=domainName, camServer=camServer)
		return Task(self.getServerConnection(), mor)

	def leaveCurrentDomain_Task(self, force):
		mor = self.getVimService().LeaveCurrentDomain_Task(self.getMOR(), force=force)
		return Task(self.getServerConnection(), mor)

class HostAuthenticationManager(ManagedObject):
	def __init__(self, sc, mor):
		super(HostAuthenticationManager, self).__init__(sc, mor)


	def getSupportedStore(self):
		mors = self.getCurrentProperty('supportedStore')
		hass = []
		for m in mors:
			hass.append(self.getServerConnection(), m)

		return hass

class HostAutoStartManager(ManagedObject):
	def __init__(self, sc, mor):
		super(HostAutoStartManager, self).__init__(sc, mor)

	def getConfig(self): self.getCurrentProperty('config')

	def autoStartPowerOff(self): self.getVimService().AutoStartPowerOff(self.getMOR())

	def autoStartPowerOn(self): self.getVimService().AutoStartPowerOn(self.getMOR())

	def reconfigureAutostart(self, spec): self.getVimService().ReconfigureAutostart(self.getMOR(), spec=spec)


class HostBootDeviceSystem(ManagedObject):
	def __init__(self, sc, mor):
		super(HostBootDeviceSystem, self).__init__(sc, mor)

	def queryBootDevices(self): return self.getVimService().QueryBootDevices(self.getMOR())

	def updateBootDevice(self): return self.getVimServie().UpdateBootDevice(self.getMOR())


class HostCacheConfigurationManager(ManagedObject):
	def __init__(self, sc, mor):
		super(HostCacheConfigurationManager, self).__init__(sc, mor)

	def getCacheConfigurationInfo(self): return self.getCurrentProperty('cacheConfigurationInfo')

	def configureHostCache_Task(self, spec):
		taskMor = self.getVimService().ConfigureHostCache_Task(self.getMOR(), spec=spec)
		return Task(self.getServerConnection(), taskMor)


class HostCpuSchedulerSystem(ManagedObject):
	def __init__(self, sc, mor):
		super(HostCpuSchedulerSystem, self).__init__(sc, mor)

	def getHyperthreadInfo(self):
		return self.getCurrentProperty('hyperthreadInfo')

	def disableHyperThreading(self):
		self.getVimService().DisableHyperThreading(self.getMOR())

	def enableHyperThreading(self):
		self.getVimService().EnableHyperThreading(self.getMOR())


class HostDatastoreBrowser(ManagedObject):
	def __init__(self, sc, mor):
		super(HostDatastoreBrowser, self).__init__(sc, mor)

	def getDatastores(self):
		return self.getDatastores('datastore')

	def getSupportedType(self):
		return self.getCurrentProperty('supportedType')

	def deleteFile(self, datastorePath):
		self.getVimService().DeleteFile(self.getMOR(), datastorePath=datastorePath)

	def searchDatastore_Task(self, datastorePath, searchSpec):
		return Task(self.getServerConnection(), self.getVimService().SearchDatastore_Task(self.getMOR(), datastorePath=datastorePath, searchSpec=searchSpec))

	def searchDatastoreSubFolders_Task(self, datastorePath, searchSpec=None):
		return Task(self.getServerConnection(), self.getVimService().SearchDatastoreSubFolders_Task(self.getMOR(), datastorePath=datastorePath, searchSpec=searchSpec))


class HostDatastoreSystem(ManagedObject):
	def __init__(self, sc, mor):
		super(HostDatastoreSystem, self).__init__(sc, mor)


	def getCapabilities(self):
		return self.getCurrentProperty('capabilities')

	def getDatastores(self):
		return self.getDatastores('datastore')

	def configureDatastorePrincipal(self, userName, password=None):
		self.getVimService().ConfigureDatastorePrincipal(self.getMOR(), userName=userName, password=password)

	def createLocalDatastore(self, name, path):
		mor = self.getVimService().CreateLocalDatastore(self.getMOR(), name=name, path=path)
		return Datastore(self.getServerConnection(), mor)

	def createNasDatastore(self, spec):
		mor = self.getVimService().CreateNasDatastore(self.getMOR(), spec=spec)
		return Datastore(self.getServerConnection(), mor)

	def createVmfsDatastore(self, spec):
		mor = self.getVimService().CreateVmfsDatastore(self.getMOR(), spec=spec)
		return Datastore(self.getServerConnection(), mor)

	def expandVmfsDatastore(self, datastore, spec):
		mor = self.getVimService().ExpandVmfsDatastore(self.getMOR(), datastore=datastore, spec=spec)
		return Datastore(self.getServerConnection(), mor)

	def extendVmfsDatastore(self, datastore, spec):
		mor = self.getVimService().ExtendVmfsDatastore(self.getMOR(), datastore=datastore, spec=spec)
		return Datastore(self.getServerConnection(), mor)

	def queryAvailableDisksForVmfs(self, datastore=None):
		return self.getVimService().QueryAvailableDisksForVmfs(self.getMOR(), datastore=datastore)

	def queryVmfsDatastoreCreateOptions(self, devicePath, vmfsMajorVersion=None):
		return self.getVimService().QueryVmfsDatastoreCreateOptions(self.getMOR(), devicePath=devicePath, vmfsMajorVersion=vmfsMajorVersion)

	def queryVmfsDatastoreExtendOptions(self, datastore, devicePath, suppressExpandCandidates=None):
		return self.getVimService().QueryVmfsDatastoreExtendOptions(self.getMOR(), datastore=datastore, devicePath=devicePath, suppressExpandCandidates=suppressExpandCandidates)

	def queryVmfsDatastoreExpandOptions(self, datastore):
		return self.getVimService().QueryVmfsDatastoreExpandOptions(self.getMOR(), datastore=datastore)

	def queryUnresolvedVmfsVolumes(self):
		return self.getVimService().QueryUnresolvedVmfsVolumes(self.getMOR())

	def removeDatastore(self, datastore):
		self.getVimService().RemoveDatastore(self.getMOR(), datastore=datastore)

	def resignatureUnresolvedVmfsVolume_Task(self, resolutionSpec):
		taskMor = self.getVimService().ResignatureUnresolvedVmfsVolume_Task(self.getMOR(), resolutionSpec=resolutionSpec)
		return Task(self.getServerConnection(), taskMor)

	def updateLocalSwapDatastore(self, datastore=None):
		self.getVimService().UpdateLocalSwapDatastore(self.getMOR(), datastore=datastore)

class HostDateTimeSystem(ManagedObject):
	def __init__(self, sc, mor):
		super(HostDateTimeSystem, self).__init__(sc, mor)

	def getDateTimeInfo(self):
		return self.getCurrentProperty('dateTimeInfo')

	def queryAvailableTimeZones(self):
		return self.getVimService().QueryAvailableTimeZones(self.getMOR())

	def queryDateTime(self):
		return self.getVimService().QueryDateTime(self.getMOR())

	def refreshDateTimeSystem(self):
		self.getVimService().RefreshDateTimeSystem(self.getMOR())

	def updateDateTime(self, dateTime):
		self.getVimService().UpdateDateTime(self.getMOR(), dateTime=dateTime)

	def updateDateTimeConfig(self, config):
		self.getVimService().UpdateDateTimeConfig(self.getMOR(), config=config)

class HostDiagnosticSystem(ManagedObject):
	def __init__(self, sc, mor):
		super(HostDiagnosticSystem, self).__init__(sc, mor)

	def getActivePartition(self):
		return self.getCurrentProperty('activePartition')

	def createDiagnosticPartition(self, spec):
		self.getVimService().CreateDiagnosticPartition(self.getMOR(), spec=spec)

	def queryAvailablePartition(self):
		return self.getVimService().QueryAvailablePartition(self.getMOR())

	def queryPartitionCreateDesc(self, diskUuid, diagnosticType):
		return self.getVimService().QueryPartitionCreateDesc(self.getMOR(), diskUuid=diskUuid, diagnosticType=diagnosticType)

	def queryPartitionCreateOptions(self, storageType, diagnosticType):
		return self.getVimService().QueryPartitionCreateOptions(self.getMOR(), storageType=storageType, diagnosticType=diagnosticType)

	def selectActivePartition(self, partition=None):
		self.getVimService().SelectActivePartition(self.getMOR(), partition=partition)


class HostEsxAgentHostManager(ManagedObject):
	def __init__(self, sc, mor):
		super(HostEsxAgentHostManager, self).__init__(sc, mor)

	def getCacheConfigurationInfo(self):
		return self.getCurrentProperty('configInfo')

	def esxAgentHostManagerUpdateConfig(self, configInfo):
		self.getVimService().EsxAgentHostManagerUpdateConfig(self.getMOR(), configInfo=configInfo)


class HostFirewallSystem(ExtensibleManagedObject):
	def __init__(self, sc, mor):
		super(HostFirewallSystem, self).__init__(sc, mor)

	def getFirewallInfo(self):
		return self.getCurrentProperty('firewallInfo')

	def disableRuleset(self, targetid):
		self.getVimService().DisableRuleset(self.getMOR(), id=targetid)

	def enableRuleset(self, targetid):
		self.getVimService().EnableRuleset(self.getMOR(), id=targetid)

	def refreshFirewall(self):
		self.getVimService().RefreshFirewall(self.getMOR())

	def updateDefaultPolicy(self, defaultPolicy):
		self.getVimService().UpdateDefaultPolicy(self.getMOR(), defaultPolicy=defaultPolicy)

	def updateRuleset(self, targetid, spec):
		self.getVimService().UpdateRuleset(self.getMOR(), id=targetid, spec=spec)


class HostFirmwareSystem(ManagedObject):
	def __init__(self, sc, mor):
		super(HostFirmwareSystem, self).__init__(sc, mor)

	def backupFirmwareConfiguration(self):
		return self.getVimService().BackupFirmwareConfiguration(self.getMOR())

	def queryFirmwareConfigUploadURL(self):
		return self.getVimService().QueryFirmwareConfigUploadURL(self.getMOR())

	def resetFirmwareToFactoryDefaults(self):
		self.getVimService().ResetFirmwareToFactoryDefaults(self.getMOR())

	def restoreFirmwareConfiguration(self, force):
		self.getVimService().RestoreFirmwareConfiguration(self.getMOR(), force=force)

class HostHealthStatusSystem(ManagedObject):
	def __init__(self, sc, mor):
		super(HostHealthStatusSystem, self).__init__(sc, mor)

	def getRuntime(self):
		return self.getCurrentProperty('runtime')

	def refreshHealthStatusSystem(self):
		self.getVimService().RefreshHealthStatusSystem(self.getMOR())

	def resetSystemHealthInfo(self):
		self.getVimService().ResetSystemHealthInfo(self.getMOR())

class HostImageConfigManager(ManagedObject):
	def __init__(self, sc, mor):
		super(HostImageConfigManager, self).__init__(sc, mor)

	def hostImageConfigGetAcceptance(self):
		return self.getVimService().HostImageConfigGetAcceptance(self.getMOR())

	def hostImageConfigGetProfile(self):
		return self.getVimService().HostImageConfigGetProfile(self.getMOR())

	def updateHostImageAcceptanceLevel(self, newAcceptanceLevel):
		self.getVimService().UpdateHostImageAcceptanceLevel(self.getMOR(), newAcceptanceLevel=newAcceptanceLevel)


class HostKernelModuleSystem(ManagedObject):
	def __init__(self, sc, mor):
		super(HostKernelModuleSystem, self).__init__(sc, mor)

	def queryConfiguredModuleOptionString(self, name):
		return self.getVimService().QueryConfiguredModuleOptionString(self.getMOR(), name=name)

	def queryModules(self):
		return self.getVimService().QueryModules(self.getMOR())

	def updateModuleOptionString(self, name, options):
		self.getVimService().UpdateModuleOptionString(self.getMOR(), name=name, options=options)


class HostLocalAccountManager(ManagedObject):
	def __init__(self, sc, mor):
		super(HostLocalAccountManager, self).__init__(sc, mor)

	def assignUserToGroup(self, user, group):
		self.getVimService().AssignUserToGroup(self.getMOR(), user=user, group=group)

	def createGroup(self, group):
		self.getVimService().CreateGroup(self.getMOR(), group=group)

	def createUser(self, user):
		self.getVimService().CreateUser(self.getMOR(), user=user)

	def removeGroup(self, groupName):
		self.getVimService().RemoveGroup(self.getMOR(), groupName=groupName)

	def removeUser(self, userName):
		self.getVimService().RemoveUser(self.getMOR(), userName=userName)

	def unassignUserFromGroup(self, user, group):
		self.getVimService().UnassignUserFromGroup(self.getMOR(), user=user, group=group)

	def updateUser(self, user):
		self.getVimService().UpdateUser(self.getMOR(), user=user)


class HostLocalAuthentication(HostAuthenticationStore):
	def __init__(self, sc, mor):
		super(HostLocalAuthentication, self).__init__(sc, mor)


class HostMemorySystem(ExtensibleManagedObject):
	def __init__(self, sc, mor):
		super(HostMemorySystem, self).__init__(sc, mor)

	def getConsoleReservationInfo(self):
		return self.getCurrentProperty('consoleReservationInfo')

	def getVirtualMachineReservationInfo(self):
		return self.getCurrentProperty('virtualMachineReservationInfo')

	def reconfigureServiceConsoleReservation(self, cfgBytes):
		self.getVimService().ReconfigureServiceConsoleReservation(self.getMOR(), cfgBytes=cfgBytes)

	def reconfigureVirtualMachineReservation(self, spec):
		self.getVimService().ReconfigureVirtualMachineReservation(self.getMOR(), spec=spec)


class HostNetworkSystem(ExtensibleManagedObject):
	def __init__(self, sc, mor):
		super(HostNetworkSystem, self).__init__(sc, mor)

	def getCapabilities(self):
		return self.getCurrentProperty('capabilities')

	def getConsoleIpRouteConfig(self):
		return self.getCurrentProperty('consoleIpRouteConfig')

	def getDnsConfig(self):
		return self.getCurrentProperty('dnsConfig')

	def getIpRouteConfig(self):
		return self.getCurrentProperty('ipRouteConfig')

	def getNetworkConfig(self):
		return self.getCurrentProperty('networkConfig')

	def getNetworkInfo(self):
		return self.getCurrentProperty('networkInfo')

	def getOffloadCapabilities(self):
		return self.getCurrentProperty('offloadCapabilities')

	def addPortGroup(self, portgrp):
		self.getVimService().AddPortGroup(self.getMOR(), portgrp=portgrp)

	def addServiceConsoleVirtualNic(self, portgroup, nic):
		return self.getVimService().AddServiceConsoleVirtualNic(self.getMOR(), portgroup=portgroup, nic=nic)

	def addVirtualNic(self, portgroup, nic):
		return self.getVimService().AddVirtualNic(self.getMOR(), portgroup=portgroup, nic=nic)

	def addVirtualSwitch(self, vswitchName, spec=None):
		self.getVimService().AddVirtualSwitch(self.getMOR(), vswitchName=vswitchName, spec=spec)

	def queryNetworkHint(self, device=None):
		return self.getVimService().QueryNetworkHint(self.getMOR(), device=device)

	def refreshNetworkSystem(self):
		self.getVimService().RefreshNetworkSystem(self.getMOR())

	def removePortGroup(self, pgName):
		self.getVimService().RemovePortGroup(self.getMOR(), pgName=pgName)

	def removeServiceConsoleVirtualNic(self, device):
		self.getVimService().RemoveServiceConsoleVirtualNic(self.getMOR(), device=device)

	def removeVirtualNic(self, device):
		self.getVimService().RemoveVirtualNic(self.getMOR(), device=device)

	def removeVirtualSwitch(self, vswitchName):
		self.getVimService().RemoveVirtualSwitch(self.getMOR(), vswitchName=vswitchName)

	def restartServiceConsoleVirtualNic(self, device):
		self.getVimService().RestartServiceConsoleVirtualNic(self.getMOR(), device=device)

	def updateConsoleIpRouteConfig(self, config):
		self.getVimService().UpdateConsoleIpRouteConfig(self.getMOR(), config=config)

	def updateDnsConfig(self, config):
		self.getVimService().UpdateDnsConfig(self.getMOR(), config=config)

	def updateIpRouteConfig(self, config):
		self.getVimService().UpdateIpRouteConfig(self.getMOR(), config=config)

	def updateIpRouteTableConfig(self, config):
		self.getVimService().UpdateIpRouteTableConfig(self.getMOR(), config=config)

	def updateNetworkConfig(self, config, changeMode):
		self.getVimService().UpdateNetworkConfig(self.getMOR(), config=config, changeMode=changeMode)

	def updatePhysicalNicLinkSpeed(self, device, linkSpeed=None):
		self.getVimService().UpdatePhysicalNicLinkSpeed(self.getMOR(), device=device, linkSpeed=linkSpeed)

	def updatePortGroup(self, pgName, portgrp):
		self.getVimService().UpdatePortGroup(self.getMOR(), pgName=pgName, portgrp=portgrp)

	def updateServiceConsoleVirtualNic(self, device, nic):
		self.getVimService().UpdateServiceConsoleVirtualNic(self.getMOR(), device=device, nic=nic)

	def updateVirtualNic(self, device, nic):
		self.getVimService().UpdateVirtualNic(self.getMOR(), device=device, nic=nic)

	def updateVirtualSwitch(self, vswitchName, spec):
		self.getVimService().UpdateVirtualSwitch(self.getMOR(), vswitchName=vswitchName, spec=spec)


class HostPatchManager(ManagedObject):
	def __init__(self, sc, mor):
		super(HostPatchManager, self).__init__(sc, mor)

	def checkHostPatch_Task(self, metaUrls=None, bundleUrls=None, spec=None):
		taskMor = self.getVimService().CheckHostPatch_Task(self.getMOR(), metaUrls=metaUrls, bundleUrls=bundleUrls, spec=spec)
		return Task(self.getServerConnection(), taskMor)

	def installHostPatchV2_Task(self, metaUrls=None, bundleUrls=None, vibUrls=None, spec=None):
		taskMor = self.getVimService().InstallHostPatchV2_Task(self.getMOR(), metaUrls=metaUrls, bundleUrls=bundleUrls, vibUrls=vibUrls, spec=spec)
		return Task(self.getServerConnection(), taskMor)

	def installHostPatch_Task(self, repository, updateID, force=None):
		return Task(self.getServerConnection(), self.getVimService().InstallHostPatch_Task(self.getMOR(), repository=repository, updateID=updateID, force=force))

	def queryHostPatch_Task(self, spec=None):
		taskMor = self.getVimService().QueryHostPatch_Task(self.getMOR(), spec=spec)
		return Task(self.getServerConnection(), taskMor)

	def scanHostPatch_Task(self, repository, updateID=None):
		return Task(self.getServerConnection(), self.getVimService().ScanHostPatch_Task(self.getMOR(), repository=repository, updateID=updateID))

	def scanHostPatchV2_Task(self, metaUrls=None, bundleUrls=None, spec=None):
		taskMor = self.getVimService().ScanHostPatchV2_Task(self.getMOR(), metaUrls=metaUrls, bundleUrls=bundleUrls, spec=spec)
		return Task(self.getServerConnection(), taskMor)

	def stageHostPatch_Task(self, metaUrls=None, bundleUrls=None, vibUrls=None, spec=None):
		taskMor = self.getVimService().StageHostPatch_Task(self.getMOR(), metaUrls=metaUrls, bundleUrls=bundleUrls, vibUrls=vibUrls, spec=spec)
		return Task(self.getServerConnection(), taskMor)

	def uninstallHostPatch_Task(self, bulletinIds=None, spec=None):
		taskMor = self.getVimService().UninstallHostPatch_Task(self.getMOR(), bulletinIds=bulletinIds, spec=spec)
		return Task(self.getServerConnection(), taskMor)


class HostPciPassthruSystem(ExtensibleManagedObject):
	def __init__(self, sc, mor):
		super(HostPciPassthruSystem, self).__init__(sc, mor)

	def getPciPassthruInfo(self):
		return self.getCurrentProperty('pciPassthruInfo')

	def refresh(self):
		self.getVimService().Refresh(self.getMOR())

	def updatePassthruConfig(self, config):
		self.getVimService().UpdatePassthruConfig(self.getMOR(), config=config)


class HostPowerSystem(ManagedObject):
	def __init__(self, sc, mor):
		super(HostPowerSystem, self).__init__(sc, mor)

	def getInfo(self):
		return self.getCurrentProperty('info')

	def configurePowerPolicy(self, key):
		self.getVimService().ConfigurePowerPolicy(self.getMOR(), key=key)


class HostProfile(Profile):
	def __init__(self, sc, mor):
		super(HostProfile, self).__init__(sc, mor)


	def getReferenceHost(self):
		return self.getManagedObject('referenceHost')

	def executeHostProfile(self, host, deferredParam):
		return self.getVimService().ExecuteHostProfile(self.getMOR(), host=host, deferredParam=deferredParam)

	def updateHostProfile(self, config):
		self.getVimService().UpdateHostProfile(self.getMOR(), config=config)

	def updateReferenceHost(self, host=None):
		self.getVimService().UpdateReferenceHost(self.getMOR(), host=host)


class HostProfileManager(ProfileManager):
	def __init__(self, sc, mor):
		super(HostProfileManager, self).__init__(sc, mor)

	def applyHostConfig_Task(self, host, configSpec, userInput=None):
		taskMor = self.getVimService().ApplyHostConfig_Task(self.getMOR(), host=host, configSpec=configSpec, userInput=userInput)
		return Task(self.getServerConnection(), taskMor)

	def checkAnswerFileStatus_Task(self, host):
		taskMor = self.getVimService().CheckAnswerFileStatus_Task(self.getMOR(), host=host)
		return Task(self.getServerConnection(), taskMor)

	def createDefaultProfile(self, profileType, profileTypeName=None, profile=None):
		return self.getVimService().CreateDefaultProfile(self.getMOR(), profileType=profileType, profileTypeName=profileTypeName, profile=profile)

	def exportAnswerFile_Task(self, host):
		taskMor = self.getVimService().ExportAnswerFile_Task(self.getMOR(), host=host)
		return Task(self.getServerConnection(), taskMor)

	def generateConfigTaskList(self, configSpec, host):
		return self.getVimService().GenerateConfigTaskList(self.getMOR(), configSpec=configSpec, host=host)

	def queryAnswerFileStatus(self, host):
		return self.getVimService().QueryAnswerFileStatus(self.getMOR(), host=host)

	def queryHostProfileMetadata(self, profileName=None, profile=None):
		self.getVimService().QueryHostProfileMetadata(self.getMOR(), profileName=profileName, profile=profile)

	def queryProfileStructure(self, profile=None):
		return self.getVimService().QueryProfileStructure(self.getMOR(), profile=profile)

	def retrieveAnswerFile(self, host):
		return self.getVimService().RetrieveAnswerFile(self.getMOR(), host=host)

	def updateAnswerFile_Task(self, host, configSpec):
		taskMor = self.getVimService().UpdateAnswerFile_Task(self.getMOR(), host=host, configSpec=configSpec)
		return Task(self.getServerConnection(), taskMor)


class HostServiceSystem(ExtensibleManagedObject):
	def __init__(self, sc, mor):
		super(HostServiceSystem, self).__init__(sc, mor)

	def getServiceInfo(self):
		return self.getCurrentProperty('serviceInfo')

	def refreshServices(self):
		self.getVimService().RefreshServices(self.getMOR())

	def restartService(self, targetid):
		self.getVimService().RestartService(self.getMOR(), id=targetid)

	def startService(self, targetid):
		self.getVimService().StartService(self.getMOR(), id=targetid)

	def stopService(self, targetid):
		self.getVimService().StopService(self.getMOR(), id=targetid)

	def uninstallService(self, targetid):
		self.getVimService().UninstallService(self.getMOR(), id=targetid)

	def updateServicePolicy(self, targetid, policy):
		self.getVimService().UpdateServicePolicy(self.getMOR(), id=targetid, policy=policy)

class HostSnmpSystem(ManagedObject):
	def __init__(self, sc, mor):
		super(HostSnmpSystem, self).__init__(sc, mor)

	def getConfiguration(self):
		self.getCurrentProperty('configuration')

	def getLimits(self):
		return self.getCurrentProperty('limits')

	def reconfigureSnmpAgent(self, spec):
		self.getVimService().ReconfigureSnmpAgent(self.getMOR(), spec=spec)

	def sendTestNotification(self):
		self.getVimService().SendTestNotification(self.getMOR())


class HostStorageSystem(ExtensibleManagedObject):
	def __init__(self, sc, mor):
		super(HostStorageSystem, self).__init__(sc, mor)

	def getFileSystemVolumeInfo(self):
		return self.getCurrentProperty('fileSystemVolumeInfo')

	def getMultipathStateInfo(self):
		return self.getCurrentProperty('multipathStateInfo')

	def getStorageDeviceInfo(self):
		return self.getCurrentProperty('storageDeviceInfo')

	def getSystemFile(self):
		return self.getCurrentProperty('systemFile')

	def addInternetScsiSendTargets(self, iScsiHbaDevice, targets):
		self.getVimService().AddInternetScsiSendTargets(self.getMOR(), iScsiHbaDevice=iScsiHbaDevice, targets=targets)

	def addInternetScsiStaticTargets(self, iScsiHbaDevice, targets):
		self.getVimService().AddInternetScsiStaticTargets(self.getMOR(), iScsiHbaDevice=iScsiHbaDevice, targets=targets)

	def attachScsiLun(self, lunUuid):
		self.getVimService().AttachScsiLun(self.getMOR(), lunUuid=lunUuid)

	def attachVmfsExtent(self, vmfsPath, extent):
		self.getVimService().AttachVmfsExtent(self.getMOR(), vmfsPath=vmfsPath, extent=extent)

	def computeDiskPartitionInfo(self, devicePath, layout, partitionFormat=None):
		return self.getVimService().ComputeDiskPartitionInfo(self.getMOR(), devicePath=devicePath, layout=layout, partitionFormat=partitionFormat)

	def computeDiskPartitionInfoForResize(self, partition, blockRange, partitionFormat=None):
		return self.getVimService().ComputeDiskPartitionInfoForResize(self.getMOR(), partition=partition, blockRange=blockRange, partitionFormat=partitionFormat)

	def detachScsiLun(self, lunUuid):
		self.getVimService().DetachScsiLun(self.getMOR(), lunUuid=lunUuid)

	def disableMultipathPath(self, pathName):
		self.getVimService().DisableMultipathPath(self.getMOR(), pathName=pathName)

	def discoverFcoeHbas(self, fcoeSpec):
		self.getVimService().DiscoverFcoeHbas(self.getMOR(), fcoeSpec=fcoeSpec)

	def enableMultipathPath(self, pathName):
		self.getVimService().EnableMultipathPath(self.getMOR(), pathName=pathName)

	def expandVmfsExtent(self, vmfsPath, extent):
		self.getVimService().ExpandVmfsExtent(self.getMOR(), vmfsPath=vmfsPath, extent=extent)

	def formatVmfs(self, createSpec):
		self.getVimService().FormatVmfs(self.getMOR(), createSpec=createSpec)

	def markForRemoval(self, hbaName, remove):
		self.getVimService().MarkForRemoval(self.getMOR(), hbaName=hbaName, remove=remove)

	def mountVmfsVolume(self, vmfsUuid):
		self.getVimService().MountVmfsVolume(self.getMOR(), vmfsUuid=vmfsUuid)

	def queryPathSelectionPolicyOptions(self):
		return self.getVimService().QueryPathSelectionPolicyOptions(self.getMOR())

	def queryStorageArrayTypePolicyOptions(self):
		return self.getVimService().QueryStorageArrayTypePolicyOptions(self.getMOR())

	def queryUnresolvedVmfsVolume(self):
		return self.getVimService().QueryUnresolvedVmfsVolume(self.getMOR())

	def refreshStorageSystem(self):
		self.getVimService().RefreshStorageSystem(self.getMOR())

	def removeInternetScsiSendTargets(self, iScsiHbaDevice, targets):
		self.getVimService().RemoveInternetScsiSendTargets(self.getMOR(), iScsiHbaDevice=iScsiHbaDevice, targets=targets)

	def removeInternetScsiStaticTargets(self, iScsiHbaDevice, targets):
		self.getVimService().RemoveInternetScsiStaticTargets(self.getMOR(), iScsiHbaDevice=iScsiHbaDevice, targets=targets)

	def rescanAllHba(self):
		self.getVimService().RescanAllHba(self.getMOR())

	def rescanHba(self, hbaDevice):
		self.getVimService().RescanHba(self.getMOR(), hbaDevice=hbaDevice)

	def rescanVmfs(self):
		self.getVimService().RescanVmfs(self.getMOR())

	def resolveMultipleUnresolvedVmfsVolumes(self, resolutionSpec):
		return self.getVimService().ResolveMultipleUnresolvedVmfsVolumes(self.getMOR(), resolutionSpec=resolutionSpec)

	def retrieveDiskPartitionInfo(self, devicePath):
		return self.getVimService().RetrieveDiskPartitionInfo(self.getMOR(), devicePath=devicePath)

	def setMultipathLunPolicy(self, lunId, policy):
		self.getVimService().SetMultipathLunPolicy(self.getMOR(), lunId=lunId, policy=policy)

	def unmountForceMountedVmfsVolume(self, vmfsUuid):
		self.getVimService().UnmountForceMountedVmfsVolume(self.getMOR(), vmfsUuid=vmfsUuid)

	def unmountVmfsVolume(self, vmfsUuid):
		self.getVimService().UnmountVmfsVolume(self.getMOR(), vmfsUuid=vmfsUuid)

	def updateDiskPartitions(self, devicePath, spec):
		self.getVimService().UpdateDiskPartitions(self.getMOR(), devicePath=devicePath, spec=spec)

	def updateInternetScsiAlias(self, iScsiHbaDevice, iScsiAlias):
		self.getVimService().UpdateInternetScsiAlias(self.getMOR(), iScsiHbaDevice=iScsiHbaDevice, iScsiAlias=iScsiAlias)

	def updateInternetScsiAuthenticationProperties(self, iScsiHbaDevice, authenticationProperties, targetSet=None):
		self.getVimService().UpdateInternetScsiAuthenticationProperties(self.getMOR(), iScsiHbaDevice=iScsiHbaDevice, authenticationProperties=authenticationProperties, targetSet=targetSet)

	def updateInternetScsiAdvancedOptions(self, iScsiHbaDevice, targetSet, options):
		self.getVimService().UpdateInternetScsiAdvancedOptions(self.getMOR(), iScsiHbaDevice=iScsiHbaDevice, targetSet=targetSet, options=options)

	def updateInternetScsiDigestProperties(self, iScsiHbaDevice, targetSet, digestProperties):
		self.getVimService().UpdateInternetScsiDigestProperties(self.getMOR(), iScsiHbaDevice=iScsiHbaDevice, targetSet=targetSet, digestProperties=digestProperties)

	def updateScsiLunDisplayName(self, lunUuid, displayName):
		self.getVimService().UpdateScsiLunDisplayName(self.getMOR(), lunUuid=lunUuid, displayName=displayName)

	def updateInternetScsiDiscoveryProperties(self, iScsiHbaDevice, discoveryProperties):
		self.getVimService().UpdateInternetScsiDiscoveryProperties(self.getMOR(), iScsiHbaDevice=iScsiHbaDevice, discoveryProperties=discoveryProperties)

	def updateInternetScsiIPProperties(self, iScsiHbaDevice, ipProperties):
		self.getVimService().UpdateInternetScsiIPProperties(self.getMOR(), iScsiHbaDevice=iScsiHbaDevice, ipProperties=ipProperties)

	def updateInternetScsiName(self, iScsiHbaDevice, iScsiName):
		self.getVimService().UpdateInternetScsiName(self.getMOR(), iScsiHbaDevice=iScsiHbaDevice, iScsiName=iScsiName)

	def updateSoftwareInternetScsiEnabled(self, enabled):
		self.getVimService().UpdateSoftwareInternetScsiEnabled(self.getMOR(), enabled=enabled)

	def upgradeVmfs(self, vmfsPath):
		self.getVimService().UpgradeVmfs(self.getMOR(), vmfsPath=vmfsPath)

	def upgradeVmLayout(self, vmfsPath):
		self.getVimService().UpgradeVmfs(self.getMOR(), vmfsPath=vmfsPath)

class HostSystem(ManagedEntity):
	def __init__(self, sc, mor):
		super(HostSystem, self).__init__(sc, mor)
		self.configManager = None

	def getCapability(self):
		return self.getCurrentProperty('capability')

	def getConfig(self):
		return self.getCurrentProperty('config')

	def getDatastores(self):
		return self.getDatastores('datastore')

	def getDatastoreBrowser(self):
		return self.getManagedObject('datastoreBrowser')

	def getHardware(self):
		return self.getCurrentProperty('hardware')

	def getLicensableResource(self):
		return self.getCurrentProperty('licensableResource')

	def getNetworks(self):
		return self.getNetworks('network')

	def getRuntime(self):
		return self.getCurrentProperty('runtime')

	def getSummary(self):
		return self.getCurrentProperty('summary')

	def getSystemResources(self):
		return self.getCurrentProperty('systemResources')

	def getVms(self):
		return self.getVms('vm')

	def acquireCimServicesTicket(self):
		return self.getVimService().AcquireCimServicesTicket(self.getMOR())

	def disconnectHost(self):
		mor = self.getVimService().DisconnectHost_Task(self.getMOR())
		return Task(self.getServerConnection(), mor)

	def enterLockdownMode(self):
		self.getVimService().EnterLockdownMode(self.getMOR())

	def enterMaintenanceMode(self, host, option=None):
		mor = self.getVimService().EnterMaintenanceMode_Task(self.getMOR(), host=host, option=option)
		return Task(self.getServerConnection(), mor)

	def exitLockdownMode(self):
		self.getVimService().ExitLockdownMode(self.getMOR())

	def exitMaintenanceMode(self):
		mor = self.getVimService().ExitMaintenanceMode_Task(self.getMOR())
		return Task(self.getServerConnection(), mor)

	def powerDownHostToStandBy(self, timeoutSec, evacuatePoweredOffVms=None):
		mor = self.getVimService().PowerDownHostToStandBy_Task(self.getMOR(), timeoutSec=timeoutSec, evacuatePoweredOffVms=evacuatePoweredOffVms)
		return Task(self.getServerConnection(), mor)

	def powerUpHostFromStandBy(self, timeoutSec):
		mor = self.getVimService().PowerUpHostFromStandBy_Task(self.getMOR(), timeoutSec=timeoutSec)
		return Task(self.getServerConnection(), mor)

	def queryHostConnectionInfo(self):
		return self.getVimService().QueryHostConnectionInfo(self.getMOR())

	def queryMemoryOverhead(self, memorySize, videoRamSize, numVcpus):
		return self.getVimService().QueryMemoryOverhead(self.getMOR(), memorySize=memorySize, videoRamSize=videoRamSize, numVcpus=numVcpus)

	def queryMemoryOverheadEx(self, vmConfigInfo):
		return self.getVimService().QueryMemoryOverheadEx(self.getMOR(), vmConfigInfo=vmConfigInfo)

	def rebootHost(self, force):
		mor = self.getVimService().RebootHost_Task(self.getMOR(), force=force)
		return Task(self.getServerConnection(), mor)

	def reconfigureHostForDAS(self):
		mor = self.getVimService().ReconfigureHostForDAS_Task(self.getMOR())
		return Task(self.getServerConnection(), mor)

	def reconnectHost_Task(self, cnxSpec=None, reconnectSpec=None):
		mor = self.getVimService().ReconnectHost_Task(self.getMOR(), cnxSpec=cnxSpec, reconnectSpec=reconnectSpec)
		return Task(self.getServerConnection(), mor)

	def retrieveHardwareUptime(self):
		return self.getVimService().RetrieveHardwareUptime(self.getMOR())

	def shutdownHost_Task(self, force):
		mor = self.getVimService().ShutdownHost_Task(self.getMOR(), force=force)
		return Task(self.getServerConnection(), mor)

	def updateFlags(self, flagInfo):
		self.getVimService().UpdateFlags(self.getMOR(), flagInfo=flagInfo)

	def updateSystemResources(self, resourceInfo):
		self.getVimService().UpdateSystemResources(self.getMOR(), resourceInfo=resourceInfo)

	def updateIpmi(self, ipmiInfo):
		self.getVimService().UpdateIpmi(self.getMOR(), ipmiInfo=ipmiInfo)

	def _getConfigManager(self):
		if self.configManager==None:
			self.configManager = self.getCurrentProperty('configManager')
		return self.configManager

	def getOptionManager(self):
		return OptionManager(self.getServerConnection(),
				self._getConfigManager().advancedOption)

	def getHostAutoStartManager(self):
		return HostAutoStartManager(self.getServerConnection(),
				self._getConfigManager().autoStartManager)

	def getHostBootDeviceSystem(self):
		return self.serverConnection.getVimService().createExactManagedObject(self._getConfigManager().bootDeviceSystem)

	def getHostDateTimeSystem(self):
		return self.serverConnection.getVimService().createExactManagedObject(self._getConfigManager().dateTimeSystem)

	def getHostDiagnosticSystem(self):
		return self.serverConnection.getVimService().createExactManagedObject(self._getConfigManager().diagnosticSystem)

	def getHostEsxAgentHostManager(self):
		return self.serverConnection.getVimService().createExactManagedObject(self._getConfigManager().esxAgentHostManager)

	def getHostCacheConfigurationManager(self):
		return self.serverConnection.getVimService().createExactManagedObject(self._getConfigManager().cacheConfigurationManager)

	def getHostCpuSchedulerSystem(self):
		return self.serverConnection.getVimService().createExactManagedObject(self._getConfigManager().cpuScheduler)

	def getHostDatastoreSystem(self):
		return self.serverConnection.getVimService().createExactManagedObject(self._getConfigManager().datastoreSystem)

	def getHostFirmwareSystem(self):
		return self.serverConnection.getVimService().createExactManagedObject(self._getConfigManager().firmwareSystem)

	def getHostKernelModuleSystem(self):
		return self.serverConnection.getVimService().createExactManagedObject(self._getConfigManager().kernelModuleSystem)

	def getLicenseManager(self):
		return self.serverConnection.getVimService().createExactManagedObject(self._getConfigManager().licenseManager)

	def getHostPciPassthruSystem(self):
		return self.serverConnection.getVimService().createExactManagedObject(self._getConfigManager().pciPassthruSystem)

	def getHostVirtualNicManager(self):
		return self.serverConnection.getVimService().createExactManagedObject(self._getConfigManager().virtualNicManager)

	def getHealthStatusSystem(self):
		return self.serverConnection.getVimService().createExactManagedObject(self._getConfigManager().healthStatusSystem)

	def getHostFirewallSystem(self):
		return self.serverConnection.getVimService().createExactManagedObject(self._getConfigManager().firewallSystem)

	def getHostImageConfigManager(self):
		return self.serverConnection.getVimService().createExactManagedObject(self._getConfigManager().imageConfigManager)

	def getHostMemorySystem(self):
		return self.serverConnection.getVimService().createExactManagedObject(self._getConfigManager().memoryManager)

	def getHostNetworkSystem(self):
		return self.serverConnection.getVimService().createExactManagedObject(self._getConfigManager().networkSystem)

	def getHostPatchManager(self):
		return self.serverConnection.getVimService().createExactManagedObject(self._getConfigManager().patchManager)

	def getHostServiceSystem(self):
		return self.serverConnection.getVimService().createExactManagedObject(self._getConfigManager().serviceSystem)

	def getHostSnmpSystem(self):
		return self.serverConnection.getVimService().createExactManagedObject(self._getConfigManager().snmpSystem)

	def getHostStorageSystem(self):
		return self.serverConnection.getVimService().createExactManagedObject(self._getConfigManager().storageSystem)

	def getIscsiManager(self):
		return self.serverConnection.getVimService().createExactManagedObject(self._getConfigManager().iscsiManager)

	def getHostVMotionSystem(self):
		return self.serverConnection.getVimService().createExactManagedObject(self._getConfigManager().vmotionSystem)


class HostVirtualNicManager(ExtensibleManagedObject):
	def __init__(self, sc, mor):
		super(HostVirtualNicManager, self).__init__(sc, mor);

	def getInfo(self):
		return self.getCurrentProperty('info')

	def queryNetConfig(self, nicType):
		return self.getVimService().QueryNetConfig(self.getMOR(), nicType=nicType)

	def deselectVnicForNicType(self, nicType, device):
		self.getVimService().DeselectVnicForNicType(self.getMOR(), nicType=nicType, device=device)

	def selectVnicForNicType(self, nicType, device):
		self.getVimService().SelectVnicForNicType(self.getMOR(), nicType=nicType, device=device)


class HttpNfcLease(ManagedObject):
	def __init__(self, sc, mor):
		super(HttpNfcLease, self).__init__(sc, mor)

	def getError(self):
		return self.getCurrentProperty('error')

	def getInfo(self):
		return self.getCurrentProperty('info')

	def getInitializeProgress(self):
		return self.getCurrentProperty('initializeProgress')

	def getState(self):
		return self.getCurrentProperty('state')

	def httpNfcLeaseAbort(self, fault=None):
		self.getVimService().HttpNfcLeaseAbort(self.getMOR(), fault=fault)

	def httpNfcLeaseComplete(self):
		self.getVimService().HttpNfcLeaseComplete(self.getMOR())

	def httpNfcLeaseGetManifest(self):
		return self.getVimService().HttpNfcLeaseGetManifest(self.getMOR())

	def httpNfcLeaseProgress(self, percent):
		self.getVimService().HttpNfcLeaseProgress(self.getMOR(), percent=percent)


class InventoryNavigator(object):
	def __init__(self, sc, rootEntity):
		self.rootEntity = rootEntity
		self.selectionSpecs = None
		self.serverConnection = sc

	def handle_managedEntities(self, ocs, handler):
		handler([] if ocs==None else self._createManagedEntities(ocs))

	def searchManagedEntities (self, **args):
		assert args.has_key('type') or args.has_key('recurse')
		assert not (args.has_key('type') and args.has_key('typeinfo'))
		recurse = args.get('recurse') if args.has_key('recurse') else True

		if not args.has_key('typeinfo'):
			typeinfo = [[args.get('type'), 'name']] if args.has_key('type') else [['ManagedEntity']]
		else:
			typeinfo = args.get('typeinfo')

		if args.has_key('handler'):
			hdl = lambda ocs: self.handle_managedEntities(ocs, args.get('handler'))
			self._retrieveObjectContents (typeinfo, recurse, hdl)
		else:
			ocs = self._retrieveObjectContents (typeinfo, recurse)
			return [] if ocs==None else self._createManagedEntities(ocs)

	def _retrieveObjectContents(self, typeinfo, recurse, handler=None):
		pc = self.rootEntity.getServerConnection().getServiceInstance().getPropertyCollector();

		if recurse and self.selectionSpecs==None:
			ai = self.rootEntity.getServerConnection().getServiceInstance().getAboutInfo()

			self.selectionSpecs = if_true(ai.apiVersion.startswith('4')  or ai.apiVersion.startswith('5'),
										  self.serverConnection.getVimService().buildFullTraversalV4(), self.serverConnection.getVimService().buildFullTraversal())

		propspecary = self.serverConnection.getVimService().buildPropertySpecArray(typeinfo)

		os = self.serverConnection.getVimService().new('ObjectSpec', obj=self.rootEntity.getMOR(), skip=False, selectSet=self.selectionSpecs)
		spec = self.serverConnection.getVimService().new('PropertyFilterSpec', objectSet=[os], propSet=propspecary)

		return pc.retrieveProperties([spec]) if handler==None else pc.retrieveProperties([spec], handler)

	def _createManagedEntities(self, ocs):
		return [self.serverConnection.getVimService().createExactManagedEntity(m.obj) for m in ocs]

	def searchManagedEntity(self, tpe, name, handler=None):
		if tpe==None: tpe = 'ManagedEntity'

		typeinfo = [[tpe,  'name']]

		return self._retrieveObjectContents(typeinfo, True, lambda ocs: self.handle_ObjectContents(name, ocs, handler))

	def handle_ObjectContents(self, name, ocs, handler):
		for m in ocs:
			propSet = m.getPropSet()
			if (len(propSet)>0):
				nameInPropSet = propSet[0].getVal()
				if name == nameInPropSet:
					return handler(self.serverConnection.getVimService().createExactManagedEntity(m.obj))
		return handler(None)


class IpPoolManager(ManagedObject):
	def __init__(self, sc, mor):
		super(IpPoolManager, self).__init__(sc, mor)

	def createIpPool(self, dc, pool):
		return self.getVimService().CreateIpPool(self.getMOR(), dc=dc, pool=pool)

	def destroyIpPool(self, dc, targetid, force):
		self.getVimService().DestroyIpPool(self.getMOR(), dc=dc, id=targetid, force=force)

	def queryIpPools(self, dc):
		return self.getVimService().QueryIpPools(self.getMOR(), dc=dc)

	def updateIpPool(self, dc, pool):
		self.getVimService().UpdateIpPool(self.getMOR(), dc=dc, pool=pool)

class IscsiManager(ManagedObject):
	def __init__(self, sc, mor):
		super(IscsiManager, self).__init__(sc, mor)

	def bindVnic(self, iScsiHbaName, vnicDevice):
		self.getVimService().BindVnic(self.getMOR(), iScsiHbaName=iScsiHbaName, vnicDevice=vnicDevice)

	def queryBoundVnics(self, iScsiHbaName):
		return self.getVimService().QueryBoundVnics(self.getMOR(), iScsiHbaName=iScsiHbaName)

	def queryCandidateNics(self, iScsiHbaName):
		return self.getVimService().QueryCandidateNics(self.getMOR(), iScsiHbaName=iScsiHbaName)

	def queryMigrationDependencies(self, pnicDevice):
		return self.getVimService().QueryMigrationDependencies(self.getMOR(), pnicDevice=pnicDevice)

	def queryPnicStatus(self, pnicDevice):
		return self.getVimService().QueryPnicStatus(self.getMOR(), pnicDevice=pnicDevice)

	def queryVnicStatus(self, vnicDevice):
		return self.getVimService().QueryVnicStatus(self.getMOR(), vnicDevice=vnicDevice)

	def unbindVnic(self, iScsiHbaName, vnicDevice, force):
		self.getVimService().UnbindVnic(self.getMOR(), iScsiHbaName=iScsiHbaName, vnicDevice=vnicDevice, force=force)

class LicenseAssignmentManager(ManagedObject):
	def __init__(self, sc, mor):
		super(LicenseAssignmentManager, self).__init__(sc, mor)

	def queryAssignedLicenses(self, entityId=None):
		return self.getVimService().QueryAssignedLicenses(self.getMOR(), entityId=entityId)

	def removeAssignedLicense(self, entityId):
		self.getVimService().RemoveAssignedLicense(self.getMOR(), entityId=entityId)

	def updateAssignedLicense(self, entity, licenseKey, entityDisplayName=None):
		return self.getVimService().UpdateAssignedLicense(self.getMOR(), entity=entity, licenseKey=licenseKey, entityDisplayName=entityDisplayName)


class LicenseManager(ManagedObject):
	def __init__(self, sc, mor):
		super(LicenseManager, self).__init__(sc, mor)

	def getDiagnostics(self):
		return self.getCurrentProperty('diagnostics')

	def getEvaluation(self):
		return self.getCurrentProperty('evaluation')

	def getLicenseAssignmentManager(self):
		return self.getManagedObject('licenseAssignmentManager')

	def getLicenses(self):
		return self.getCurrentProperty('licenses')

	def getFeatureInfo(self):
		return self.getCurrentProperty('featureInfo')

	def getLicensedEdition(self):
		return self.getCurrentProperty('licensedEdition')

	def getSource(self):
		return self.getCurrentProperty('source')

	def getSourceAvailable(self):
		return self.getCurrentProperty('sourceAvailable')

	def addLicense(self, licenseKey, labels=None):
		return self.getVimService().AddLicense(self.getMOR(), licenseKey=licenseKey, labels=labels)

	def decodeLicense(self, licenseKey):
		return self.getVimService().DecodeLicense(self.getMOR(), licenseKey=licenseKey)

	def checkLicenseFeature(self, host, featureKey):
		return self.getVimService().CheckLicenseFeature(self.getMOR(), host=host, featureKey=featureKey)

	def configureLicenseSource(self, host, licenseSource):
		self.getVimService().ConfigureLicenseSource(self.getMOR(), host=host, licenseSource=licenseSource)

	def disableFeature(self, host, featureKey):
		self.getVimService().DisableFeature(self.getMOR(), host=host, featureKey=featureKey)

	def enableFeature(self, host, featureKey):
		self.getVimService().EnableFeature(self.getMOR(), host=host, featureKey=featureKey)

	def queryLicenseSourceAvailability(self, host=None):
		return self.getVimService().QueryLicenseSourceAvailability(self.getMOR(), host=host)

	def queryLicenseUsage(self, host=None):
		return self.getVimService().QueryLicenseUsage(self.getMOR(), host=host)

	def querySupportedFeatures(self, host=None):
		return self.getVimService().QuerySupportedFeatures(self.getMOR(), host=host)

	def removeLicense(self, licenseKey):
		self.getVimService().RemoveLicense(self.getMOR(), licenseKey=licenseKey)

	def removeLicenseLabel(self, licenseKey, labelKey):
		self.getVimService().RemoveLicenseLabel(self.getMOR(), licenseKey=licenseKey, labelKey=labelKey)

	def updateLicense(self, licenseKey, labels=None):
		self.getVimService().UpdateLicense(self.getMOR(), licenseKey=licenseKey, labels=labels)

	def updateLicenseLabel(self, licenseKey, labelKey, labelValue):
		self.getVimService().UpdateLicenseLabel(self.getMOR(), licenseKey=licenseKey, labelKey=labelKey, labelValue=labelValue)

	def setLicenseEdition(self, host=None, featureKey=None):
		self.getVimService().SetLicenseEdition(self.getMOR(), host=host, featureKey=featureKey)

class LocalizationManager(ManagedObject):
	def __init__(self, sc, mor):
		super(LocalizationManager, self).__init__(sc, mor)

	def getCatalog(self):
		self.getCurrentProperty('catalog')

class OptionManager(ManagedObject):
	def __init__(self, sc, mor):
		super(OptionManager, self).__init__(sc, mor)

	def getSetting(self):
		return self.getCurrentProperty('setting')

	def getSupportedOption(self):
		return self.getCurrentProperty('supportedOption')

	def queryOptions(self, name=None):
		return self.getVimService().QueryOptions(self.getMOR(), name=name)

	def updateOptions(self, changedValue):
		self.getVimService().UpdateOptions(self.getMOR(), changedValue=changedValue)

class OvfManager(ManagedObject):
	def __init__(self, sc, mor):
		super(OvfManager, self).__init__(sc, mor)

	def createDescriptor(self, obj, cdp):
		return self.getVimService().CreateDescriptor(self.getMOR(), obj=obj, cdp=cdp)

	def createImportSpec(self, ovfDescriptor, resourcePool, datastore, cisp):
		return self.getVimService().CreateImportSpec(self.getMOR(), ovfDescriptor=ovfDescriptor, resourcePool=resourcePool, datastore=datastore, cisp=cisp)

	def parseDescriptor(self, ovfDescriptor, pdp):
		return self.getVimService().ParseDescriptor(self.getMOR(), ovfDescriptor=ovfDescriptor, pdp=pdp)

	def validateHost(self, ovfDescriptor, host, vhp):
		return self.getVimService().ValidateHost(self.getMOR(), ovfDescriptor=ovfDescriptor, host=host, vhp=vhp)

class PerformanceManager(ManagedObject):
	def __init__(self, sc, mor):
		super(PerformanceManager, self).__init__(sc, mor)

	def getDescription(self):
		return self.getCurrentProperty('description')

	def getHistoricalInterval(self):
		return self.getCurrentProperty('historicalInterval')

	def getPerfCounter(self):
		return self.getCurrentProperty('perfCounter')

	def createPerfInterval(self, intervalId):
		self.getVimService().CreatePerfInterval(self.getMOR(), intervalId=intervalId)

	def queryAvailablePerfMetric(self, entity, beginTime=None, endTime=None, intervalId=None):
		return self.getVimService().QueryAvailablePerfMetric(self.getMOR(), entity=entity, beginTime=beginTime, endTime=endTime, intervalId=intervalId)

	def queryPerf(self, querySpec):
		return self.getVimService().QueryPerf(self.getMOR(), querySpec=querySpec)

	def queryPerfComposite(self, querySpec):
		return self.getVimService().QueryPerfComposite(self.getMOR(), querySpec=querySpec)

	def queryPerfCounter(self, counterId):
		return self.getVimService().QueryPerfCounter(self.getMOR(), counterId=counterId)

	def queryPerfCounterByLevel(self, level):
		return self.getVimService().QueryPerfCounterByLevel(self.getMOR(), level=level)

	def queryPerfProviderSummary(self, entity):
		return self.getVimService().QueryPerfProviderSummary(self.getMOR(), entity=entity)

	def removePerfInterval(self, samplePeriod):
		self.getVimService().RemovePerfInterval(self.getMOR(), samplePeriod=samplePeriod)

	def updatePerfInterval(self, interval):
		self.getVimService().UpdatePerfInterval(self.getMOR(), interval=interval)


class ProfileComplianceManager(ManagedObject):
	def __init__(self, sc, mor):
		super(ProfileComplianceManager, self).__init__(sc, mor)

	def checkCompliance_Task(self, profile=None, entity=None):
		taskMor = self.getVimService().CheckCompliance_Task(self.getMOR(), profile=profile, entity=entity)
		return Task(self.getServerConnection(), taskMor)

	def clearComplianceStatus(self, profile=None, entity=None):
		self.getVimService().ClearComplianceStatus(self.getMOR(), profile=profile, entity=entity)


	def queryComplianceStatus(self, profile=None, entity=None):
		return self.getVimService().QueryComplianceStatus(self.getMOR(), profile=profile, entity=entity)

	def queryExpressionMetadata(self, expressionName=None, profile=None):
		return self.getVimService().QueryExpressionMetadata(self.getMOR(), expressionName=expressionName, profile=profile)
class PropertyCollector(ManagedObject):
	def __init__(self, sc, mor):
		super(PropertyCollector, self).__init__(sc, mor)

	def getFilters(self):
		return ManagedObject.getFilter('filter')

	def cancelRetrievePropertiesEx(self, token):
		self.getVimService().CancelRetrievePropertiesEx(self.getMOR(), token=token)

	def cancelWaitForUpdates(self):
		self.getVimService().CancelWaitForUpdates(self.getMOR())

	def continueRetrievePropertiesEx(self, token):
		return self.getVimService().ContinueRetrievePropertiesEx(self.getMOR(), token=token)

	def checkForUpdates(self, version=None):
		return self.getVimService().CheckForUpdates(self.getMOR(), version=version)

	def createFilter(self, spec, partialUpdates):
		mor = self.getVimService().CreateFilter(self.getMOR(), spec=spec, partialUpdates=partialUpdates)
		return PropertyFilter(self.getServerConnection(), mor)

	def createPropertyCollector(self):
		mor = self.getVimService().CreatePropertyCollector(self.getMOR())
		return PropertyCollector(self.getServerConnection(), mor)

	def destroyPropertyCollector(self):
		self.getVimService().DestroyPropertyCollector(self.getMOR())

	def retrieveProperties(self, specSet):
		return self.getVimService().RetrieveProperties(self.getMOR(), specSet=specSet)

	def retrievePropertiesEx(self, specSet, options):
		return self.getVimService().RetrievePropertiesEx(self.getMOR(), specSet=specSet, options=options)

	def waitForUpdates(self, version=None):
		return self.getVimService().WaitForUpdates(self.getMOR(), version=version)

	def waitForUpdatesEx(self, version=None, options=None):
		return self.getVimService().WaitForUpdatesEx(self.getMOR(), version=version, options=options)


class PropertyFilter(ManagedObject):
	def __init__(self, sc, mor):
		super(PropertyFilter, self).__init__(sc, mor)

	def getPartialUpdates(self):
		return self.getCurrentProperty('partialUpdates')

	def getSpec(self):
		return self.getCurrentProperty('spec')

	def destroyPropertyFilter(self):
		self.getVimService().DestroyPropertyFilter(self.getMOR())


class ResourcePlanningManager(Profile):
	def __init__(self, sc, mor):
		super(ResourcePlanningManager, self).__init__(sc, mor)

	def estimateDatabaseSize(self, dbSizeParam):
		return self.getVimService().EstimateDatabaseSize(self.getMOR(), dbSizeParam=dbSizeParam)


class ResourcePool(ManagedEntity):
	def __init__(self, sc, mor):
		super(ResourcePool, self).__init__(sc, mor)

	def getChildConfiguration(self):
		return self.getCurrentProperty('childConfiguration')

	def getConfig(self):
		return self.getCurrentProperty('config')

	def getOwner(self):
		return self.getManagedObject('owner')

	def getResourcePools(self):
		return ManagedEntity.getResourcePools('resourcePool')

	def getRuntime(self):
		return self.getCurrentProperty('runtime')

	def getSummary(self):
		return self.getCurrentProperty('summary')

	def getVMs(self): ManagedEntity.getVms('vm')

	def createChildVM_Task(self, config, host=None):
		taskMor = self.getVimService().CreateChildVM_Task(self.getMOR(), config=config, host=host)
		return Task(self.getServerConnection(), taskMor)

	def createVApp(self, name, resSpec, configSpec, vmFolder=None):
		vaMor = self.getVimService().CreateVApp(self.getMOR(), name=name, resSpec=resSpec, configSpec=configSpec, vmFolder=vmFolder)
		return VirtualApp(self.getServerConnection(), vaMor)

	def importVApp(self, spec, folder=None, host=None):
		mor = self.getVimService().ImportVApp(self.getMOR(), spec=spec, folder=folder, host=host)
		return HttpNfcLease(self.getServerConnection(), mor)

	def refreshRuntime(self):
		self.getVimService().RefreshRuntime(self.getMOR())

	def registerChildVM_Task(self, path, name=None, host=None):
		mor = self.getVimService().RegisterChildVM_Task(self.getMOR(), path=path, name=name, host=host)
		return Task(self.getServerConnection(), mor)

	def createResourcePool(self, name, spec):
		rpMor = self.getVimService().CreateResourcePool(self.getMOR(), name=name, spec=spec)
		return ResourcePool(self.getServerConnection(), rpMor)

	def destroyChildren(self):
		self.getVimService().DestroyChildren(self.getMOR())

	def moveIntoResourcePool(self, listObj):
		self.getVimService().MoveIntoResourcePool(self.getMOR(), list=listObj)

	def queryResourceConfigOption(self):
		return self.getVimService().QueryResourceConfigOption(self.getMOR())

	def updateChildResourceConfiguration(self, spec):
		self.getVimService().UpdateChildResourceConfiguration(self.getMOR(), spec=spec)

	def updateConfig(self, name=None, config=None):
		self.getVimService().UpdateConfig(self.getMOR(), name=name, config=config)


class ScheduledTask(ExtensibleManagedObject):
	def __init__(self, sc, mor):
		super(ScheduledTask, self).__init__(sc, mor)

	def getInfo(self):
		return self.getCurrentProperty('info')

	def getActiveTask(self):
		return self.getCurrentProperty('info.activeTask')

	def getAssociatedManagedEntity(self):
		return self.getCurrentProperty('info.entity')

	def reconfigureScheduledTask(self, spec):
		self.getVimService().ReconfigureScheduledTask(self.getMOR(), spec=spec)

	def removeScheduledTask(self):
		self.getVimService().RemoveScheduledTask(self.getMOR())

	def runScheduledTask(self):
		self.getVimService().RunScheduledTask(self.getMOR())

class ScheduledTaskManager(ManagedObject):
	def __init__(self, sc, mor):
		super(ScheduledTaskManager, self).__init__(sc, mor)

	def getDescriptioin(self):
		return self.getCurrentProperty('description')

	def getScheduledTasks(self):
		return self.getScheduledTasks('scheduledTask')

	def createScheduledTask(self, entity, spec):
		return ScheduledTask(self.getServerConnection(),
				self.getVimService().CreateScheduledTask(self.getMOR(), entity=entity, spec=spec))

	def createObjectScheduledTask(self, obj, spec):
		return ScheduledTask(self.getServerConnection(),
				self.getVimService().CreateObjectScheduledTask(self.getMOR(), obj=obj, spec=spec))

	def retrieveEntityScheduledTask(self, entity=None):
		mors = self.getVimService().RetrieveEntityScheduledTask(self.getMOR(), entity=entity)
		tasks = []

		for m in mors:
			tasks.append(ScheduledTask(self.getServerConnection(), m))

		return tasks;

	def retrieveObjectScheduledTask(self, obj=None):
		mors = self.getVimService().RetrieveObjectScheduledTask(self.getMOR(), obj=obj)

		tasks = []

		for m in mors:
			tasks.append(ScheduledTask(self.getServerConnection(), m))

		return tasks;


class SearchIndex(ManagedObject):
	def __init__(self, sc, mor):
		super(SearchIndex, self).__init__(sc, mor)

	def findByInventoryPath(self, inventoryPath):
		mor = self.getVimService().FindByInventoryPath(self.getMOR(), inventoryPath=inventoryPath)
		return self.serverConnection.getVimService().createExactManagedEntity(mor)

	def findByIp(self, datacenter, ip, vmSearch):
		mor = self.getVimService().FindByIp(self.getMOR(), datacenter=datacenter, ip=ip, vmSearch=vmSearch)
		return self.serverConnection.getVimService().createExactManagedEntity(mor)

	def findByDnsName(self, datacenter, dnsName, vmSearch):
		mor = self.getVimService().FindByDnsName(self.getMOR(), datacenter=datacenter, dnsName=dnsName, vmSearch=vmSearch)
		return self.serverConnection.getVimService().createExactManagedEntity(mor)

	def findAllByDnsName(self, datacenter, dnsName, vmSearch):
		mors = self.getVimService().FindAllByDnsName(self.getMOR(), datacenter=datacenter, dnsName=dnsName, vmSearch=vmSearch)
		return self.serverConnection.getVimService().createManagedEntities(self.getServerConnection(), mors)

	def findAllByIp(self, datacenter, ip, vmSearch):
		mors = self.getVimService().FindAllByIp(self.getMOR(), datacenter=datacenter, ip=ip, vmSearch=vmSearch)
		return self.serverConnection.getVimService().createManagedEntities(self.getServerConnection(), mors)

	def findAllByUuid(self, datacenter, uuid, vmSearch, instanceUuid=None):
		mors = self.getVimService().FindAllByUuid(self.getMOR(), datacenter=datacenter, uuid=uuid, vmSearch=vmSearch, instanceUuid=instanceUuid)
		return self.serverConnection.getVimService().createManagedEntities(self.getServerConnection(), mors)

	def findByDatastorePath(self, datacenter, path):
		mor = self.getVimService().FindByDatastorePath(self.getMOR(), datacenter=datacenter, path=path)
		return self.serverConnection.getVimService().createExactManagedEntity(mor)

	def findByUuid(self, datacenter, uuid, vmSearch, instanceUuid=None):
		mor = self.getVimService().FindByUuid(self.getMOR(), datacenter=datacenter, uuid=uuid, vmSearch=vmSearch, instanceUuid=instanceUuid)
		return self.serverConnection.getVimService().createExactManagedEntity(mor)

	def findChild(self, entity, name):
		mor = self.getVimService().FindChild(self.getMOR(), entity=entity, name=name)
		return self.serverConnection.getVimService().createExactManagedEntity(mor)

class ManagedObjectReference(suds.sudsobject.Property):
	def __init__(self, _type, value):
		suds.sudsobject.Property.__init__(self, value)
		self._type = _type


class ServiceInstance(ManagedObject):
	def __init__(self, vimService, url, username=None, password=None, sessioncookie=None):
		# vimService is a reference to Vim25Client 
		self.SERVICE_INSTANCE_MOR = vimService.new('_this', _type='ServiceInstance', value='ServiceInstance')
		self.setMOR(self.SERVICE_INSTANCE_MOR)
		self.serviceContent = None # cached on first invocation of getServiceContent()
		sc = ServerConnection(url, vimService, self)
		self.setServerConnection(sc)
		vimService.setServerConnection(sc)

		if username and password:
			self.userSession = self.getSessionManager().login(username, password)
			self.getServerConnection().setUserSession(self.userSession)
		elif sessioncookie:
			self.getServerConnection().setSessionCookie(sessioncookie)
			#HIGH FIVE FOR JUST COMMENTING OUT LINES THAT BREAK!
#			self.userSession = self.getSessionManager().getCurrentSession()
#			self.getServerConnection().setUserSession(self.userSession)
						
	def setServiceContent(self, content):
		self.serviceContent = content

	def getServerClock(self):
		return self.getCurrentProperty('serverClock')

	def getCapability(self):
		return self.getCurrentProperty('capability')

	def getClusterProfileManager(self):
		return self._createMO(self.getServiceContent().getClusterProfileManager())

	def currentTime(self):
		return self.getVimService().CurrentTime(self.getMOR())

	def getRootFolder(self):
		return Folder(self.getServerConnection(), self.getServiceContent().rootFolder)

	def queryVMotionCompatibility(self, vm, host, compatibility=None):
		return self.getVimService().QueryVMotionCompatibility(self.getMOR(), vm=vm, host=host, compatibility=compatibility)

	def retrieveProductComponents(self):
		return self.getVimService().RetrieveProductComponents(self.getMOR())

	def _retrieveServiceContent(self):
		return self.getVimService().RetrieveServiceContent(self.getMOR())

	def validateMigration(self, vm, state=None, testType=None, pool=None, host=None):
		return self.getVimService().ValidateMigration(self.getMOR(), vm=vm, state=state, testType=testType, pool=pool, host=host)

	def getServiceContent(self):
		if self.serviceContent == None:
			self.serviceContent = self._retrieveServiceContent()
		return self.serviceContent

	def getAboutInfo(self):
		return self.getServiceContent().about

	def getAlarmManager(self):
		return self._createMO(self.getServiceContent().alarmManager)

	def getAuthorizationManager(self):
		return self._createMO(self.getServiceContent().authorizationManager)

	def getCustomFieldsManager(self):
		return self._createMO(self.getServiceContent().customFieldsManager)

	def getCustomizationSpecManager(self):
		return self._createMO(self.getServiceContent().customizationSpecManager)

	def getEventManager(self):
		return self._createMO(self.getServiceContent().eventManager)

	def getDiagnosticManager(self):
		return self._createMO(self.getServiceContent().diagnosticManager)

	def getDistributedVirtualSwitchManager(self):
		return self._createMO(self.getServiceContent().getDvSwitchManager())

	def getExtensionManager(self):
		return self._createMO(self.getServiceContent().getExtensionManager())

	def getFileManager(self):
		return self._createMO(self.getServiceContent().getFileManager())

	def getGuestOperationsManager(self):
		return self._createMO(self.getServiceContent().guestOperationsManager)

	def getAccountManager(self):
		return self._createMO(self.getServiceContent().accountManager)

	def getLicenseManager(self):
		return self._createMO(self.getServiceContent().licenseManager)

	def getLocalizationManager(self):
		return self._createMO(self.getServiceContent().localizationManager)

	def getPerformanceManager(self):
		return self._createMO(self.getServiceContent().perfManager)

	def getProfileComplianceManager(self):
		return self._createMO(self.getServiceContent().complianceManager)

	def getPropertyCollector(self):
		return self._createMO(self.getServiceContent().propertyCollector)

	def getScheduledTaskManager(self):
		return self._createMO(self.getServiceContent().scheduledTaskManager)

	def getSearchIndex(self):
		return self._createMO(self.getServiceContent().searchIndex)

	def getSessionManager(self):
		return self._createMO(self.getServiceContent().sessionManager)

	def getHostSnmpSystem(self):
		return self._createMO(self.getServiceContent().snmpSystem)

	def getHostProfileManager(self):
		return self._createMO(self.getServiceContent().hostProfileManager)

	def getIpPoolManager(self):
		return self._createMO(self.getServiceContent().ipPoolManager)

	def getVirtualMachineProvisioningChecker(self):
		return self._createMO(self.getServiceContent().vmProvisioningChecker)

	def getVirtualMachineCompatibilityChecker(self):
		return self._createMO(self.getServiceContent().vmCompatibilityChecker)

	def getTaskManager(self):
		return self._createMO(self.getServiceContent().taskManager)

	def getUserDirectory(self):
		return self._createMO(self.getServiceContent().userDirectory)

	def getViewManager(self):
		return self._createMO(self.getServiceContent().viewManager)

	def getVirtualDiskManager(self):
		return self._createMO(self.getServiceContent().virtualDiskManager)

	def getOptionManager(self):
		return self._createMO(self.getServiceContent().setting)

	def getOvfManager(self):
		return self._createMO(self.getServiceContent().ovfManager)

	def _createMO(self, mor):
		return None if not mor else self.serverConnection.getVimService().createExactManagedObject(mor)

class SessionManager(ManagedObject):
	def __init__(self, sc, mor):
		super(SessionManager, self).__init__(sc, mor)

	def getCurrentSession(self):
		return self.getCurrentProperty('currentSession')

	def getDefaultLocale(self):
		return self.getCurrentProperty('defaultLocale')

	def getMessage(self):
		return self.getCurrentProperty('message')

	def getMessageLocaleList(self):
		return self.getCurrentProperty('messageLocaleList')

	def getSessionList(self):
		return self.getCurrentProperty('sessionList')

	def getSupportedLocaleList(self):
		return self.getCurrentProperty('supportedLocaleList')

	def acquireLocalTicket(self, userName):
		return self.getVimService().AcquireLocalTicket(self.getMOR(), userName=userName)

	def acquireGenericServiceTicket(self, spec):
		return self.getVimService().AcquireGenericServiceTicket(self.getMOR(), spec=spec)

	def cloneSession(self, cloneTicket):
		return self.getVimService().CloneSession(self.getMOR(), cloneTicket=cloneTicket)


	def acquireCloneTicket(self):
		return self.getVimService().AcquireCloneTicket(self.getMOR())

	def loginExtensionBySubjectName(self, extensionKey, locale=None):
		return self.getVimService().LoginExtensionBySubjectName(self.getMOR(), extensionKey=extensionKey, locale=locale)

	def impersonateUser(self, userName, locale=None):
		return self.getVimService().ImpersonateUser(self.getMOR(), userName=userName, locale=locale)

	def login(self, userName, password, locale=None):
		return self.getVimService().Login(self.getMOR(), userName=userName, password=password, locale=locale)

	def loginBySSPI(self, base64Token, locale=None):
		return self.getVimService().LoginBySSPI(self.getMOR(), base64Token=base64Token, locale=locale)

	def logout(self):
		self.getVimService().Logout(self.getMOR())

	def sessionIsActive(self, sessionID, userName):
		return self.getVimService().SessionIsActive(self.getMOR(), sessionID=sessionID, userName=userName)

	def setLocale(self, locale):
		self.getVimService().SetLocale(self.getMOR(), locale=locale)

	def terminateSession(self, sessionId):
		self.getVimService().TerminateSession(self.getMOR(), sessionId=sessionId)

	def updateServiceMessage(self, message):
		self.getVimService().UpdateServiceMessage(self.getMOR(), message=message)


class StoragePod(Folder):
	def __init__(self, sc, mor):
		super(StoragePod, self).__init__(sc, mor)

	def getPodStorageDrsEntry(self):
		return self.getCurrentProperty('podStorageDrsEntry')

	def getSummary(self):
		return self.getCurrentProperty('summary')

class StorageResourceManager(ManagedObject):
	def __init__(self, sc, mor):
		super(StorageResourceManager, self).__init__(sc, mor)

	def applyStorageDrsRecommendation_Task(self, key):
		taskMor = self.getVimService().ApplyStorageDrsRecommendation_Task(self.getMOR(), key=key)
		return Task(self.getServerConnection(), taskMor)

	def applyStorageDrsRecommendationToPod_Task(self, pod, key):
		taskMor = self.getVimService().ApplyStorageDrsRecommendationToPod_Task(self.getMOR(), pod=pod, key=key)
		return Task(self.getServerConnection(), taskMor)

	def cancelStorageDrsRecommendation(self, key):
		self.getVimService().CancelStorageDrsRecommendation(self.getMOR(), key=key)

	def configureDatastoreIORM_Task(self, datastore, spec):
		mor = self.getVimService().ConfigureDatastoreIORM_Task(self.getMOR(), datastore=datastore, spec=spec)
		return Task(self.getServerConnection(), mor)

	def configureStorageDrsForPod_Task(self, pod, spec, modify):
		taskMor = self.getVimService().ConfigureStorageDrsForPod_Task(self.getMOR(), pod=pod, spec=spec, modify=modify)
		return Task(self.getServerConnection(), taskMor)

	def queryIORMConfigOption(self, host):
		return self.getVimService().QueryIORMConfigOption(self.getMOR(), host=host)

	def recommendDatastores(self, storageSpec):
		return self.getVimService().RecommendDatastores(self.getMOR(), storageSpec=storageSpec)

	def refreshStorageDrsRecommendation(self, pod):
		self.getVimService().RefreshStorageDrsRecommendation(self.getMOR(), pod=pod)

class Task(ExtensibleManagedObject):
	PROPNAME_INFO = 'info'
	SUCCESS = 'success'

	def __init__(self, sc, mor):
		super(Task, self).__init__(sc, mor)

	def getTaskInfo(self):
		return self.getCurrentProperty(self.PROPNAME_INFO)

	def getAssociatedManagedEntity(self):
		return self.getManagedObject('info.entity')

	def getLockedManagedEntities(self):
		return self.getManagedObjects('info.locked')

	def cancelTask(self):
		self.getVimService().CancelTask(self.getMOR())

	def setTaskState(self, state, result=None, fault=None):
		self.getVimService().SetTaskState(self.getMOR(), state=state, result=result, fault=fault)

	def updateProgress(self, percentDone):
		self.getVimService().UpdateProgress(self.getMOR(), percentDone=percentDone)

	def setTaskDescription(self, description):
		self.getVimService().SetTaskDescription(self.getMOR(), description=description)

	def waitForMe(self):
		TaskInfoState = self.serverConnection.getVimService().new('TaskInfoState')
		result = self.waitForValues(['info.state', 'info.error'],
									['state'], [TaskInfoState.success, TaskInfoState.error])

		if result[0] == TaskInfoState.success: return self.SUCCESS
		else:
			tinfo = self.getCurrentProperty(self.PROPNAME_INFO)
			fault = tinfo.getError()
			error = "Error Occured"

			return if_true(fault==None, error, fault.getFault())

	def waitForTask(self, runningDelayInMillSecond=500, queuedDelayInSecond=1):
		TaskInfoState = self.serverConnection.getVimService().new('TaskInfoState')
		tState = None
		tries = 0
		maxTries = 3
		getInfoException = None

		while tState in [None, TaskInfoState.running, TaskInfoState.queued]:
			tState = None
			getInfoException = None
			tries = 0
			while (tState==None):
				tries = tries + 1
				time.sleep(queuedDelayInSecond)
				# need to rewrite...
				tState = self.getTaskInfo().getState()

		return tState

class TaskHistoryCollector(HistoryCollector):
	def __init__(self, sc, mor):
		super(TaskHistoryCollector, self).__init__(sc, mor)

	def getFilter(self):
		return self.getCurrentProperty('filter')

	def getLatestPage(self):
		return self.getCurrentProperty('latestPage')

	def readNextTasks(self, maxCount):
		return self.getVimService().ReadNextTasks(self.getMOR(), maxCount=maxCount)

	def readPreviousTasks(self, maxCount):
		return self.getVimService().ReadPreviousTasks(self.getMOR(), maxCount=maxCount)

class TaskManager(ManagedObject):
	def __init__(self, sc, mor):
		super(TaskManager, self).__init__(sc, mor)

	def getDescription(self):
		return self.getCurrentProperty('description')

	def getMaxCollector(self):
		return self.getCurrentProperty('maxCollector')

	def getRecentTasks(self):
		return self.getTasks('recentTask')

	def createCollectorForTasks(self, targetfilter):
		return TaskHistoryCollector(self.getServerConnection(),
			   self.getVimService().CreateCollectorForTasks(self.getMOR(), filter=targetfilter))

	def createTask(self, obj, taskTypeId, initiatedBy, cancelable, parentTaskKey=None):
		return self.getVimService().CreateTask(self.getMOR(), obj=obj, taskTypeId=taskTypeId, initiatedBy=initiatedBy, cancelable=cancelable, parentTaskKey=parentTaskKey)


class UserDirectory(ManagedObject):
	def __init__(self, sc, mor):
		super(UserDirectory, self).__init__(sc, mor)

	def getDomainList(self):
		return self.getCurrentProperty('domainList')

	def retrieveUserGroups(self, domain, searchStr, belongsToGroup, belongsToUser, exactMatch, findUsers, findGroups):
		return self.getVimService().RetrieveUserGroups(self.getMOR(), domain=domain, searchStr=searchStr, belongsToGroup=belongsToGroup, belongsToUser=belongsToUser, exactMatch=exactMatch, findUsers=findUsers, findGroups=findGroups)

class VirtualApp(ResourcePool):
	def __init__(self, sc, mor):
		super(VirtualApp, self).__init__(sc, mor)

	def getChildLink(self):
		return self.getCurrentProperty('childLink')

	def getDatastore(self):
		return self.getDatastores('datastore')

	def getNetwork(self):
		return self.getNetworks('network')

	def getParentFolder(self):
		return Folder(self.getServerConnection(), self.getCurrentProperty('parentFolder'))

	def getParentVApp(self):
		return ManagedEntity(self.getServerConnection(), self.getCurrentProperty('parentVApp'))

	def getVAppConfig(self):
		return self.getCurrentProperty('vAppConfig')

	def cloneVApp_Task(self, name, target, spec):
		taskMor = self.getVimService().CloneVApp_Task(self.getMOR(), name=name, target=target, spec=spec)
		return Task(self.getServerConnection(), taskMor)

	def exportVApp(self):
		mor = self.getVimService().ExportVApp(self.getMOR())
		return HttpNfcLease(self.getServerConnection(), mor)

	def powerOffVApp_Task(self, force):
		taskMor = self.getVimService().PowerOffVApp_Task(self.getMOR(), force=force)
		return Task(self.getServerConnection(), taskMor)

	def suspendVApp_Task(self):
		taskMor = self.getVimService().SuspendVApp_Task(self.getMOR())
		return Task(self.getServerConnection(), taskMor)

	def powerOnVApp_Task(self):
		taskMor = self.getVimService().PowerOnVApp_Task(self.getMOR())
		return Task(self.getServerConnection(), taskMor)

	def unregisterVApp_Task(self):
		taskMor = self.getVimService().UnregisterVApp_Task(self.getMOR())
		return Task(self.getServerConnection(), taskMor)

	def updateLinkedChildren(self, addChangeSet=None, removeSet=None):
		self.getVimService().UpdateLinkedChildren(self.getMOR(), addChangeSet=addChangeSet, removeSet=removeSet)

	def updateVAppConfig(self, spec):
		self.getVimService().UpdateVAppConfig(self.getMOR(), spec=spec)

class VirtualDiskManager(ManagedObject):
	def __init__(self, sc, mor):
		super(VirtualDiskManager, self).__init__(sc, mor)


	def copyVirtualDisk_Task(self, sourceName, sourceDatacenter, destName, destDatacenter=None, destSpec=None, force=None):
		taskMor = self.getVimService().CopyVirtualDisk_Task(self.getMOR(), sourceName=sourceName, sourceDatacenter=sourceDatacenter, destName=destName, destDatacenter=destDatacenter, destSpec=destSpec, force=force)

		return Task(self.getServerConnection(), taskMor)

	def createVirtualDisk_Task(self, name, datacenter, spec):
		return Task(self.getServerConnection(),
				self.getVimService().CreateVirtualDisk_Task(self.getMOR(), name=name, datacenter=datacenter, spec=spec))

	def defragmentVirtualDisk_Task(self, name, datacenter=None):
		return Task(self.getServerConnection(),
				self.getVimService().DefragmentVirtualDisk_Task(self.getMOR(), name=name, datacenter=datacenter))

	def deleteVirtualDisk_Task(self, name, datacenter=None):
		return Task(self.getServerConnection(),
				self.getVimService().DeleteVirtualDisk_Task(self.getMOR(), name=name, datacenter=datacenter))

	def extendVirtualDisk_Task(self, name, datacenter, newCapacityKb, eagerZero=None):
		return Task(self.getServerConnection(),
				self.getVimService().ExtendVirtualDisk_Task(self.getMOR(), name=name, datacenter=datacenter, newCapacityKb=newCapacityKb, eagerZero=eagerZero))

	def eagerZeroVirtualDisk_Task(self, name, datacenter=None):
		return Task(self.getServerConnection(),
			self.getVimService().EagerZeroVirtualDisk_Task(self.getMOR(), name=name, datacenter=datacenter))


	def inflateVirtualDisk_Task(self, name, datacenter=None):
		return Task(self.getServerConnection(),
				self.getVimService().InflateVirtualDisk_Task(self.getMOR(), name=name, datacenter=datacenter))

	def moveVirtualDisk_Task(self, sourceName, sourceDatacenter, destName, destDatacenter=None, force=None):
		taskMor = self.getVimService().MoveVirtualDisk_Task(self.getMOR(), sourceName=sourceName, sourceDatacenter=sourceDatacenter, destName=destName, destDatacenter=destDatacenter, force=force)

		return Task(self.getServerConnection(), taskMor)

	def queryVirtualDiskFragmentation(self, name, datacenter=None):
		return self.getVimService().QueryVirtualDiskFragmentation(self.getMOR(), name=name, datacenter=datacenter)

	def queryVirtualDiskGeometry(self, name, datacenter=None):
		return self.getVimService().QueryVirtualDiskGeometry(self.getMOR(), name=name, datacenter=datacenter)

	def queryVirtualDiskUuid(self, name, datacenter=None):
		return self.getVimService().QueryVirtualDiskUuid(self.getMOR(), name=name, datacenter=datacenter)

	def setVirtualDiskUuid(self, name, datacenter, uuid):
		self.getVimService().SetVirtualDiskUuid(self.getMOR(), name=name, datacenter=datacenter, uuid=uuid)

	def shrinkVirtualDisk_Task(self, name, datacenter=None, copy=None):
		return Task(self.getServerConnection(),
				self.getVimService().ShrinkVirtualDisk_Task(self.getMOR(), name=name, datacenter=datacenter, copy=copy))

	def zeroFillVirtualDisk_Task(self, name, datacenter=None):
		return Task(self.getServerConnection(),
				self.getVimService().ZeroFillVirtualDisk_Task(self.getMOR(), name=name, datacenter=datacenter))

class VirtualMachine(ManagedEntity):
	def __init__(self, sc, mor):
		super(VirtualMachine, self).__init__(sc, mor)
		self.config = None

	def getCapability(self):
		return self.getCurrentProperty('capability')

	def getConfig(self):
		if self.config==None:
			self.config = self.getCurrentProperty('config')
		return self.config

	def getDatastores(self):
		return ManagedEntity.getDatastores(self, 'datastore')

	def getEnvironmentBrowser(self):
		return self.getManagedObject('environmentBrowser')

	def getGuest(self):
		return self.getCurrentProperty('guest')

	def getGuestHeartbeatStatus(self):
		return self.getCurrentProperty('guestHeartbeatStatus')

	def getLayout(self):
		return self.getCurrentProperty('layout')

	def getLayoutEx(self):
		return self.getCurrentProperty('layoutEx')

	def getStorage(self):
		return self.getCurrentProperty('storage')

	def getNetworks(self, nw = 'network'):
		return self.getNetworks(nw)

	def getParentVApp(self):
		mor = self.getCurrentProperty('parentVApp')
		return ManagedEntity(self.getServerConnection(), mor)

	def getResourceConfig(self):
		return self.getCurrentProperty('resourceConfig')

	def getResourcePool(self):
		return self.getManagedObject('resourcePool')

	def getRootSnapshot(self):
		mors = self.getCurrentProperty('rootSnapshot')

		vmns = []
		for m in mors:
			vmns.append(VirtualMachineSnapshot(self.getServerConnection(), m))
		return vmns;

	def getRuntime(self):
		return self.getCurrentProperty('runtime')

	def getSnapshot(self):
		return self.getCurrentProperty('snapshot')

	def getCurrentSnapShot(self):
		return self.getManagedObject('snapshot.currentSnapshot')

	def getSummary(self):
		return self.getCurrentProperty('summary')

	def acquireTicket(self, ticketType):
		return self.getVimService().AcquireTicket(self.getMOR(), ticketType=ticketType)

	def answerVM(self, questionId, answerChoice):
		self.getVimService().AnswerVM(self.getMOR(), questionId=questionId, answerChoice=answerChoice)

	def checkCustomizationSpec(self, spec):
		self.getVimService().CheckCustomizationSpec(self.getMOR(), spec=spec)

	def cloneVM_Task(self, folder, name, spec):
		mor = self.getVimService().CloneVM_Task(self.getMOR(), folder=folder, name=name, spec=spec)
		return Task(self.getServerConnection(), mor)

	def consolidateVMDisks_Task(self):
		taskMor = self.getVimService().ConsolidateVMDisks_Task(self.getMOR())
		return Task(self.getServerConnection(), taskMor)

	def createScreenshot_Task(self):
		mor = self.getVimService().CreateScreenshot_Task(self.getMOR())
		return Task(self.getServerConnection(), mor)

	def createSnapshot_Task(self, name, description, memory, quiesce):
		mor = self.getVimService().CreateSnapshot_Task(self.getMOR(), name=name, description=description, memory=memory, quiesce=quiesce)
		return Task(self.getServerConnection(), mor);

	def createSecondaryVM_Task(self, host=None):
		mor = self.getVimService().CreateSecondaryVM_Task(self.getMOR(), host=host)
		return Task(self.getServerConnection(), mor)

	def disableSecondaryVM_Task(self, vm):
		mor = self.getVimService().DisableSecondaryVM_Task(self.getMOR(), vm=vm)

		return Task(self.getServerConnection(), mor)

	def enableSecondaryVM_Task(self, vm, host=None):
		mor = self.getVimService().EnableSecondaryVM_Task(self.getMOR(), vm=vm, host=host)
		return Task(self.getServerConnection(), mor)

	def estimateStorageForConsolidateSnapshots_Task(self):
		taskMor = self.getVimService().EstimateStorageForConsolidateSnapshots_Task(self.getMOR())
		return Task(self.getServerConnection(), taskMor)

	def exportVm(self):
		mor = self.getVimService().ExportVm(self.getMOR())
		return HttpNfcLease(self.getServerConnection(), mor)

	def extractOvfEnvironment(self):
		return self.getVimService().ExtractOvfEnvironment(self.getMOR())

	def makePrimaryVM_Task(self, vm):
		mor = self.getVimService().MakePrimaryVM_Task(self.getMOR(), vm=vm)
		return Task(self.getServerConnection(), mor)

	def customizeVM_Task(self, spec):
		mor = self.getVimService().CustomizeVM_Task(self.getMOR(), spec=spec)
		return Task(self.getServerConnection(), mor)

	def defragmentAllDisks(self):
		self.getVimService().DefragmentAllDisks(self.getMOR())

	def markAsTemplate(self):
		self.getVimService().MarkAsTemplate(self.getMOR())

	def markAsVirtualMachine(self, pool, host=None):
		self.getVimService().MarkAsVirtualMachine(self.getMOR(), pool=pool, host=host)

	def migrateVM_Task(self, pool, host, priority, state=None):
		mor = self.getVimService().MigrateVM_Task(self.getMOR(), pool=pool, host=host, priority=priority, state=state)
		return Task(self.getServerConnection(), mor)

	def mountToolsInstaller(self):
		self.getVimService().MountToolsInstaller(self.getMOR())

	def powerOffVM_Task(self):
		mor = self.getVimService().PowerOffVM_Task(self.getMOR())
		return Task(self.getServerConnection(), mor)

	def powerOnVM_Task(self, host=None):
		mor = self.getVimService().PowerOnVM_Task(self.getMOR(), host=host)
		return Task(self.getServerConnection(), mor)

	def promoteDisks_Task(self, unlink, disks=None):
		mor = self.getVimService().PromoteDisks_Task(self.getMOR(), unlink=unlink, disks=disks)
		return Task(self.getServerConnection(), mor)

	def queryChangedDiskAreas(self, snapshot, deviceKey, startOffset, changeId):
		return self.getVimService().QueryChangedDiskAreas(self.getMOR(), snapshot=snapshot, deviceKey=deviceKey, startOffset=startOffset, changeId=changeId)

	def queryFaultToleranceCompatibility(self):
		return self.getVimService().QueryFaultToleranceCompatibility(self.getMOR())

	def queryUnownedFiles(self):
		return self.getVimService().QueryUnownedFiles(self.getMOR())

	def rebootGuest(self):
		self.getVimService().RebootGuest(self.getMOR())

	def reconfigVM_Task(self, spec):
		mor = self.getVimService().ReconfigVM_Task(self.getMOR(), spec=spec)
		return Task(self.getServerConnection(), mor)

	def reloadVirtualMachineFromPath_Task(self, configurationPath):
		mor = self.getVimService().ReloadVirtualMachineFromPath_Task(self.getMOR(), configurationPath=configurationPath)
		return Task(self.getServerConnection(), mor)

	def refreshStorageInfo(self):
		self.getVimService().RefreshStorageInfo(self.getMOR())

	def relocateVM_Task(self, spec, priority=None):
		mor = self.getVimService().RelocateVM_Task(self.getMOR(), spec=spec, priority=priority)
		return Task(self.getServerConnection(), mor)

	def removeAllSnapshots_Task(self, consolidate=None):
		mor = self.getVimService().RemoveAllSnapshots_Task(self.getMOR(), consolidate=consolidate)
		return Task(self.getServerConnection(), mor)

	def resetGuestInformation(self):
		self.getVimService().ResetGuestInformation(self.getMOR())

	def resetVM_Task(self):
		mor = self.getVimService().ResetVM_Task(self.getMOR())
		return Task(self.getServerConnection(), mor)

	def revertToCurrentSnapshot_Task(self, host=None, suppressPowerOn=None):
		mor = self.getVimService().RevertToCurrentSnapshot_Task(self.getMOR(), host=host, suppressPowerOn=suppressPowerOn)
		return Task(self.getServerConnection(), mor)

	def setDisplayTopology(self, displays):
		self.getVimService().SetDisplayTopology(self.getMOR(), displays=displays)

	def setScreenResolution(self, width, height):
		self.getVimService().SetScreenResolution(self.getMOR(), width=width, height=height)

	def shutdownGuest(self):
		self.getVimService().ShutdownGuest(self.getMOR())

	def startRecording_Task(self, name, description=None):
		mor = self.getVimService().StartRecording_Task(self.getMOR(), name=name, description=description)
		return Task(self.getServerConnection(), mor)

	def stopRecording_Task(self):
		mor = self.getVimService().StopRecording_Task(self.getMOR())
		return Task(self.getServerConnection(), mor)

	def stopReplaying_Task(self):
		mor = self.getVimService().StopReplaying_Task(self.getMOR())
		return Task(self.getServerConnection(), mor)

	def startReplaying_Task(self, replaySnapshot):
		mor = self.getVimService().StartReplaying_Task(self.getMOR(), replaySnapshot=replaySnapshot)
		return Task(self.getServerConnection(), mor)

	def standbyGuest(self):
		self.getVimService().StandbyGuest(self.getMOR())

	def suspendVM_Task(self):
		mor = self.getVimService().SuspendVM_Task(self.getMOR())
		return Task(self.getServerConnection(), mor)

	def terminateFaultTolerantVM_Task(self, vm=None):
		mor = self.getVimService().TerminateFaultTolerantVM_Task(self.getMOR(), vm=vm)
		return Task(self.getServerConnection(), mor)

	def turnOffFaultToleranceForVM_Task(self):
		mor = self.getVimService().TurnOffFaultToleranceForVM_Task(self.getMOR())
		return Task(self.getServerConnection(), mor)

	def unmountToolsInstaller(self):
		self.getVimService().UnmountToolsInstaller(self.getMOR())

	def unregisterVM(self):
		self.getVimService().UnregisterVM(self.getMOR())

	def upgradeTools_Task(self, installerOptions=None):
		mor = self.getVimService().UpgradeTools_Task(self.getMOR(), installerOptions=installerOptions)
		return Task(self.getServerConnection(), mor)

	def upgradeVM_Task(self, version=None):
		mor = self.getVimService().UpgradeVM_Task(self.getMOR(), version=version)
		return Task(self.getServerConnection(), mor)

class VirtualMachineProvisioningChecker(ManagedObject):
	def __init__(self, sc, mor):
		super(VirtualMachineProvisioningChecker, self).__init__(sc, mor)

	def checkMigrate_Task(self, vm, host=None, pool=None, state=None, testType=None):
		taskMor = self.getVimService().CheckMigrate_Task(self.getMOR(), vm=vm, host=host, pool=pool, state=state, testType=testType)
		return Task(self.getServerConnection(), taskMor);

	def checkRelocate_Task(self, vm, spec, testType=None):
		taskMor = self.getVimService().CheckRelocate_Task(self.getMOR(), vm=vm, spec=spec, testType=testType)
		return Task(self.getServerConnection(), taskMor)

	def queryVMotionCompatibilityEx_Task(self, vm, host):
		taskMor = self.getVimService().QueryVMotionCompatibilityEx_Task(self.getMOR(), vm=vm, host=host)

		return Task(self.getServerConnection(), taskMor)

class VirtualMachineCompatibilityChecker(ManagedObject):
	def __init__(self, sc, mor):
		super(VirtualMachineCompatibilityChecker, self).__init__(sc, mor)

	def checkCompatibility_Task(self, hostContainer, dvsProductSpec=None, hostFilterSpec=None):
		taskMor = self.getVimService().CheckCompatibility_Task(self.getMOR(), hostContainer=hostContainer, dvsProductSpec=dvsProductSpec, hostFilterSpec=hostFilterSpec)

		return Task(self.getServerConnection(), taskMor)


class VirtualMachineSnapshot(ManagedObject):
	def __init__(self, sc, mor):
		super(VirtualMachineSnapshot, self).__init__(sc, mor)

	def getChildSnapshot(self):
		mors = self.getCurrentProperty('childSnapshot')
		vmns = []
		for m in mors:
			vmns.append(VirtualMachineSnapshot(self.getServerConnection(), m))
		return vmns;

	def getConfig(self):
		return self.getCurrentProperty('config')

	def removeSnapshot_Task(self, removeChildren, consolidate=None):
		return Task( self.getServerConnection(),
					 self.getVimService().RemoveSnapshot_Task(self.getMOR(), removeChildren=removeChildren, consolidate=consolidate))

	def renameSnapshot(self, name=None, description=None):
		self.getVimService().RenameSnapshot(self.getMOR(), name=name, description=description)

	def revertToSnapshot_Task(self, host=None, suppressPowerOn=None):
		return Task(self.getServerConnection(),
				self.getVimService().RevertToSnapshot_Task(self.getMOR(), host=host, suppressPowerOn=suppressPowerOn))


class VmwareDistributedVirtualSwitch(DistributedVirtualSwitch):
	def __init__(self, sc, mor):
		super(VmwareDistributedVirtualSwitch, self).__init__(sc, mor)


