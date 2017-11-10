from vim25.connection import Connection
from vim25.mo import ManagedObjectReference
import re

class MetricsCache(object):
	def __init__(self, hostmoid, vmmoid, vmmwl="", vmmbl="", hostmwl="", hostmbl=""):
		"""This class will set "fullcounters" to an dictionary with keys structured like so:
		as a side note, this would be better stored as a set of listed objects for structure,
		but I don't want to test pickling in hydra incase we ever go cross os...  SO nested
		dicts it is!  This class also always assumes an active connection object.

		fullcounters = {"hostmetrics":fullhostcounters,"vmmetrics":fullvmcounters, "vmrefreshrate":self.vmrefreshrate, "hostrefreshrate":self.hostrefreshRate}
	
		Instantiated with kwargs:
			@hostmoid - moid of the host to store a metric cache for
			@vmmoid - moid of a vm currently residing on the host.  Used to query vm counters.  Should be a list at max 5 vms.
			@vmmwl - virtual machine metrics white list
			@vmmbl - virtual machine metrics white list
			@hostmwl - host system metrics white list
			@hostmbl - host system metrics black list
			@vmiwl - virtual machine instance white list
			@vmibl - virtual machine instance black list
			@hostiwl - host system instance white list
			@hostibl - host system instance black list
		"""
		self.perfManager = Connection.perfManager
		self.hostmoid=hostmoid
		self.vmmoid=vmmoid
		self.vmmwl = re.compile(vmmwl)
		self.vmmbl = re.compile(vmmbl)
		self.hostmwl = re.compile(hostmwl)
		self.hostmbl = re.compile(hostmbl)
		self.hostsystem = Connection.vim25client.createExactManagedObject(mor=ManagedObjectReference(value=self.hostmoid, _type="HostSystem"))
		self.vm = []
		self.vmrefreshrate=0
		count=0
		if vmmoid:
			for vm in vmmoid:
				if count<=5:
					currentvm = Connection.vim25client.createExactManagedObject(mor=ManagedObjectReference(value=vm, _type="VirtualMachine"))
					currentvmrefreshrate = self._queryRefreshRate(currentvm)
					if currentvmrefreshrate < self.vmrefreshrate or self.vmrefreshrate==0:
						self.vmrefreshrate = currentvmrefreshrate
					self.vm.append(currentvm)
					count=count+1
				else:
					break
			self.counterlistvm = self._queryVMCounters()
		else:
			self.vmrefreshrate=0
			self.counterlistvm = []
		self.hostrefreshRate = self._queryRefreshRate(self.hostsystem)
		self.counterlisthost = self._queryHostCounters()
		if self.counterlisthost:
			self.fullcounters = self._getCounterListsNames()
		else:
			self.fullcounters = None
			
	def _queryRefreshRate(self, entity):
		pps = self.perfManager.queryPerfProviderSummary(entity)
		return pps.refreshRate
		
	def _queryHostCounters(self):
		counterlisthost = set()
		for counter in self.perfManager.queryAvailablePerfMetric(self.hostsystem, intervalId=self.hostrefreshRate):
			counterlisthost.add(counter.counterId)
		return counterlisthost
		
	def _queryVMCounters(self):
		counterlistvm = set()
		for vm in self.vm:
			for counter in self.perfManager.queryAvailablePerfMetric(vm, intervalId=self.vmrefreshrate):
				counterlistvm.add(counter.counterId)
		return counterlistvm
	
	def _pruneWhiteBlacklists(self, listtoprune, whitelist, blacklist):
		'''
		Must be passed as regex compiled python objects.  re.compile("string").
		Will return a list with items pruned.  Items that match the whitelist AND are not
		in the blacklist will be returned.  A blank whitelist will assume that all entries are whitelisted.
		a blank blacklist will assume no entries are blacklisted.
		'''
		if bool(whitelist.pattern) and bool(blacklist.pattern):
			#There is a whitelist pattern specified and a blacklist pattern
			return [x for x in listtoprune if (whitelist.match(x['name']) and not blacklist.match(x['name']))]
		elif bool(whitelist.pattern) and not bool(blacklist.pattern):
			#There is a white list and no blacklist
			return [x for x in listtoprune if whitelist.match(x['name'])]
		elif not bool(whitelist.pattern) and bool(blacklist.pattern):
			#There is no whitelist and there is a blacklist
			return [x for x in listtoprune if not blacklist.match(x['name'])]
		else:
			#There is no white list or blacklist
			return listtoprune
	
	def _getCounterListsNames(self):
		if self.counterlistvm:
			counterlistvmnames=self.perfManager.queryPerfCounter(counterId=list(self.counterlistvm))
			fullvmcounters = []
			for counter in counterlistvmnames:
				fullvmcounters.append({"id":counter.key, "name":"_".join(['p', counter.rollupType, counter.groupInfo.key, counter.nameInfo.key, counter.unitInfo.key]), "group":str(counter.groupInfo.key)})
			fullvmcounters = self._pruneWhiteBlacklists(fullvmcounters, self.vmmwl, self.vmmbl)
		else:
			fullvmcounters = []
		counterlisthostnames=self.perfManager.queryPerfCounter(counterId=list(self.counterlisthost))
		fullhostcounters = []
		for counter in counterlisthostnames:
			fullhostcounters.append({"id":counter.key, "name":"_".join(['p', counter.rollupType, counter.groupInfo.key, counter.nameInfo.key, counter.unitInfo.key]), "group":str(counter.groupInfo.key)})
		fullhostcounters = self._pruneWhiteBlacklists(fullhostcounters, self.hostmwl, self.hostmbl)
		return {"hostmetrics":fullhostcounters,"vmmetrics":fullvmcounters, "vmrefreshrate":self.vmrefreshrate, "hostrefreshrate":self.hostrefreshRate}
