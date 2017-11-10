# Copyright (C) 2005-2017 Splunk Inc. All Rights Reserved. 

#Core Python Imports
import sys
import datetime
import json
import random

from splunk import util

# Append SA-Hydra/bin/pacakges to the Python path

from splunk.appserver.mrsparkle.lib.util import make_splunkhome_path
sys.path.append(make_splunkhome_path(['etc', 'apps', 'SA-Hydra', 'bin', 'packages']))

# Import TA-VMware collection code

import vim25.inventory as inventory
from vim25.connection import Connection
from ta_vmware.models import TAVMwareCacheStanza
from vim25.mo import ManagedObjectReference
from vim25.mo import ManagedObject


# Import from SA-Hydra
import hydra

import os

class BaseInventoryHandler(hydra.HydraHandler):
	"""
	Things all inv handlers need
	"""
	cache_model = TAVMwareCacheStanza
	def get_inv_cache(self, vc, target_config_object):
		for retry in range(4):
			locked_cache, status = self.getCacheAndLock(vc+":"+ target_config_object)
			if status:
				inv_data = locked_cache.get("inv_data", False)
				if inv_data:
					return inv_data.get("last_mor", None), inv_data.get("last_version", None), inv_data.get("last_session", None), locked_cache.get("inv_time", None)
		return None, None, None, None

	def set_inv_cache(self, vc, target_config_object, last_mor, last_version, last_session, last_dump_time):
		inv_data = {"last_mor" : last_mor, "last_version" : last_version, "last_session" : last_session}
		inv_time = last_dump_time
		for retry in range(4):
			locked_cache, status = self.getCacheAndLock(vc+":"+ target_config_object)
			if status:
				locked_cache["inv_data"] = inv_data
				locked_cache["inv_time"] = inv_time
				return self.setCache(vc+":"+ target_config_object, locked_cache)
		return False
		
	def destroy_inv_cache(self, target, target_config_object):
		return self.destroyCache(target + ":" + target_config_object)

    # Get Datastore details
	def get_datastore_details(self, datastore_mor):
		'''
			@param datastore_mor: managed object reference of datastore
		'''
		datastore_detail_list = []
		for mor in datastore_mor.ManagedObjectReference:
			# Create mo from mor
			mo = Connection.vim25client.createExactManagedObject(mor)
			objContent = mo.retrieveObjectProperties(["summary.accessible", "summary.name", "summary.url"])
			if objContent != None and objContent.propSet != None and len(objContent.propSet) > 0:
				datastore_detail_dict = {}
				for dynaprops in objContent.propSet:
					if dynaprops.name == "summary.accessible": datastore_detail_dict['accessible'] = dynaprops.val
					if dynaprops.name == "summary.name": datastore_detail_dict['name'] = dynaprops.val
					if dynaprops.name == "summary.url": datastore_detail_dict['url'] = dynaprops.val
				datastore_detail_list.append(datastore_detail_dict)
		return datastore_detail_list

	# Get mor of passing type
	def find_mor_by_type(self, host_mor,type):
		'''
			@param host_mor: managed object reference of hostsystem
			@param type: entity type ex.ClusterComputeResource
		'''
		parent_mor = host_mor
		while parent_mor._type != type:
			mo = Connection.vim25client.createExactManagedObject(parent_mor)
			parent_mor = mo.getCurrentProperty("parent")
			if parent_mor._type == "RootFolder":
				return None, None
		parent_mo = Connection.vim25client.createExactManagedObject(parent_mor)
		parent_name = parent_mo.getCurrentProperty("name")
		return parent_mor, parent_name

	# Get current properties into dictionary
	def get_current_properties_into_dict(self, mor, path_dict, entity_dict):
		mo = Connection.vim25client.createExactManagedObject(mor)
		objContent = mo.retrieveObjectProperties(path_dict.keys())
		if objContent != None and objContent.propSet != None and len(objContent.propSet) > 0:
			for dynaprops in objContent.propSet:
				if dynaprops.name == "datastore":
					entity_dict['datastores'] = self.get_datastore_details(dynaprops.val)
				elif dynaprops.name == "config.network.vnic":
					entity_dict['ip'] = ','.join(str(i['spec']['ip']['ipAddress']) for i in dynaprops.val.HostVirtualNic)
				elif dynaprops.name in path_dict.keys(): exec(path_dict[dynaprops.name] + " = dynaprops.val") in locals()

	# Send inventory data to splunk in chunks
	def send_inv_data(self, hierarchyCollector, last_version, host, sourcetype, sourcename, time, dest_index, config, target_config_object=None):
		'''
			A common function which is used to send data hierarchical data to splunk for all inventory handlers
			@param hierarchyCollector: Property collector object to get inventory data
			@param last_version : version
			@param host: host name to send the data for that host
			@param sourcetype: sourcetype name
			@param sourcename: source value
			@param time : time to index the data
			@param dest_index : splunk index value
			
			@return last_version: final version of hierarchy data
		'''
		is_first_version_seen = False
		if hierarchyCollector is None:
			self.logger.error("[Inventory Handler] Property collector to get hierarchy is not defined")
			return last_version, is_first_version_seen
		maxObjUpdates = config.get('inv_maxObjUpdates', None)
		gen_check_for_updates = hierarchyCollector.checkForUpdates(ver=last_version, maxObjUpdatesWaitOp=maxObjUpdates)
		# data_set is only used only for datagen, not in production
		data_set = []
		for last_version, data in gen_check_for_updates:
			if data is None:
				self.logger.warn("Failed to get data for sourcetype=%s, version=%s", sourcename, last_version)
				return last_version, is_first_version_seen
			self.logger.info("[Inventory Handler] Creating a flattened json object")
			flattenCombineDataGen = inventory.FlattenCombinedData(data, last_version)
			for data in flattenCombineDataGen:
				if target_config_object == "VirtualMachine":
					vm_dict = json.loads(data) if data else {}
					vm_moid = vm_dict.get('moid', None)
					if vm_moid is not None:
						try:
							vm_mor = ManagedObjectReference(value=vm_moid, _type="VirtualMachine")
							path_dict={"config.instanceUuid": "entity_dict['vm_id']",
										"config.name": "entity_dict['vm_name']",
										"datastore":""}
							self.get_current_properties_into_dict(vm_mor, path_dict, vm_dict)
						except Exception as e:
							self.logger.warn("Configuration of virtual machine: {0} is not available, Error: {1}.".format(vm_moid, e))
					runtime_dict = vm_dict.get('changeSet', {}).get('summary', {}).get('runtime', {})
					host_moid = runtime_dict.get('host', {}).get('moid', None) if isinstance(runtime_dict, dict) else None
					if host_moid is not None:
						try:
							host_mor = ManagedObjectReference(value=host_moid, _type="HostSystem")
							path_dict={"config.product.version": "entity_dict['hypervisor_os_version']",
										"hardware.systemInfo.uuid": "entity_dict['changeSet']['summary']['runtime']['host']['uuid']",
										"summary.config.name": "entity_dict['changeSet']['summary']['runtime']['host']['name']"}
							self.get_current_properties_into_dict(host_mor, path_dict, vm_dict)
						except Exception as e:
							self.logger.warn("Hardware info is not available for parent host: {0}, Error: {1}.".format(host_moid, e))
						try:
							cluster_mor, cluster_name = self.find_mor_by_type(host_mor, "ClusterComputeResource")
							if cluster_mor is not None:
								vm_dict['cluster'] = {"moid": cluster_mor.value, "type": cluster_mor._type, "name": str(cluster_name)}
						except:
							self.logger.warn("Looks like host is not part of cluster, Cound not find ClusterComputeResource for Virtual Machine.")
					data= json.dumps(vm_dict)
				if target_config_object == "HostSystem":
					host_dict = json.loads(data) if data else {}
					host_moid = host_dict.get('moid', None)
					if host_moid is not None:
						try:
							host_mor = ManagedObjectReference(value=host_moid, _type="HostSystem")
							path_dict={"summary.config.name": "entity_dict['hypervisor_name']",
										"summary.hardware.uuid": "entity_dict['hypervisor_id']",
										"datastore": "",
										"config.network.vnic": ""}
							self.get_current_properties_into_dict(host_mor, path_dict, host_dict)
							datcenter_mor, datcenter_name = self.find_mor_by_type(host_mor, "Datacenter")
							if datcenter_mor is not None:
								host_dict['datacenter'] = {"moid": datcenter_mor.value, "type": datcenter_mor._type, "name": str(datcenter_name)}
						except Exception as e:
							self.logger.warn("Configuration of hostsystem: {0} is not available, Error: {1}".format(host_moid, e))
						try:
							cluster_mor, cluster_name = self.find_mor_by_type(host_mor, "ClusterComputeResource")
							if cluster_mor is not None:
								host_dict['cluster'] = {"moid": cluster_mor.value, "type": cluster_mor._type, "name": str(cluster_name)}
						except:
							self.logger.warn("Looks like host is not part of cluster, Cound not find ClusterComputeResource for host.")
					data= json.dumps(host_dict)
				if target_config_object == "Datastore":
					datastore_dict = json.loads(data) if data else {}
					datastore_moid = datastore_dict.get('moid', None)
					if datastore_moid is not None:
						datastore_mor = ManagedObjectReference(value=datastore_moid, _type="Datastore")
						path_dict={"summary.name": "entity_dict['datastore_name']",
									"summary.url": "entity_dict['datastore_url']"}
						self.get_current_properties_into_dict(datastore_mor, path_dict, datastore_dict)
					data = json.dumps(datastore_dict)
				self.logger.info("[Inventory Handler] Finished creating a json object, processing XML output")
				self.output.sendData(data, host=host, sourcetype=sourcetype, source=sourcename, time=time, index=dest_index)
				if config.get('autoeventgen', None) and util.normalizeBoolean(config['autoeventgen']):
					if target_config_object == 'HostSystem' or target_config_object == 'Hierarchy' or target_config_object == 'VirtualMachine' or target_config_object == 'ClusterComputeResource':
						data_set.append(data)
			del flattenCombineDataGen
			if float(str(last_version)) == 1:
				is_first_version_seen = True
		if is_first_version_seen and config.get('autoeventgen', None) and util.normalizeBoolean(config['autoeventgen']):
			if target_config_object == 'HostSystem' or target_config_object == 'Hierarchy' or target_config_object == 'VirtualMachine' or target_config_object == 'ClusterComputeResource':
				if config.get('autoeventgen_poweroff_vmcount', None):
					poweroff_vm_count = config['autoeventgen_poweroff_vmcount']
				else:
					poweroff_vm_count = 0
				self.auto_gen_data(data_set, host, sourcetype, sourcename, time, dest_index, target_config_object, config["target"][0], poweroff_vm_count)
		del data_set
		return last_version, is_first_version_seen

	def auto_gen_data(self, data_set, host, sourcetype, source, time, dest_index, target_config_object, vc, poweroff_vm_count=0):
		'''
			Generate fake event based upon existig one and modify moid, parent etc
		'''
		# Get list of
		host_data = []
		vm_data = []
		cluster_data = []
		if target_config_object == "Hierarchy":
			# Get only data belong to hostSystem
			for data in data_set:
				jsonifydata = json.loads(data)
				if jsonifydata['type'] == 'HostSystem':
					host_data.append(json.dumps(jsonifydata))
				elif jsonifydata['type'] == 'VirtualMachine':
					vm_data.append(json.dumps(jsonifydata))
				elif jsonifydata['type'] == 'ClusterComputeResource':
					cluster_data.append(json.dumps(jsonifydata))

		auto_generatedids = self.gateway_adapter.get_cache("autogenertedid:"+vc)
		if auto_generatedids is None:
			self.logger.error("Could not find out generated moid in gateway cache.")
			return
		else:
			for cluster in auto_generatedids['clusters']:
				if target_config_object == 'ClusterComputeResource' or target_config_object == "Hierarchy":
					if target_config_object == "Hierarchy" and len(cluster_data) > 0:
						json_data = json.loads(cluster_data[random.randint(0, len(cluster_data)-1)])
					else:
						json_data = json.loads(data_set[random.randint(0, len(data_set)-1)])
					json_data['moid'] = cluster['moid']
					json_data['changeSet']['name'] = cluster['name']
					self.logger.info("[%s] added auto generated cluster moid:%s, name:%s", target_config_object, json_data['moid'], json_data['changeSet']['name'])
					self.output.sendData(json.dumps(json_data), host=host, sourcetype=sourcetype, source=source, time=time, index=dest_index)
					if target_config_object == 'ClusterComputeResource':
						continue
				if target_config_object == "Hierarchy" or target_config_object == 'HostSystem' or target_config_object == "VirtualMachine":
					for autogen_host in cluster['hosts']:
						if target_config_object == "Hierarchy" or target_config_object == 'HostSystem':
							if target_config_object == "Hierarchy":
								json_data = json.loads(host_data[random.randint(0, len(host_data)-1)])
							else:
								json_data = json.loads(data_set[random.randint(0, len(data_set)-1)])
							json_data['moid'] = autogen_host['moid']
							json_data['changeSet']['name'] = autogen_host['name']
							json_data['changeSet']['moid'] = autogen_host['moid']
							json_data['changeSet']['parent']['moid'] = cluster['moid']
							json_data['changeSet']['parent']['type'] = "ClusterComputeResource"
							self.logger.info("[%s] added auto generated host moid:%s, name:%s", target_config_object, json_data['moid'], json_data['changeSet']['name'])
							self.output.sendData(json.dumps(json_data), host=host, sourcetype=sourcetype, source=source, time=time, index=dest_index)
							if target_config_object == 'HostSystem':
								continue
						if target_config_object == "Hierarchy" or target_config_object == "VirtualMachine":
							for vm in autogen_host['vms']:
								if target_config_object == "Hierarchy":
									json_data = json.loads(vm_data[random.randint(0, len(vm_data)-1)])
								else:
									json_data = json.loads(data_set[random.randint(0, len(data_set)-1)])
								json_data['moid'] = vm['moid']
								json_data['changeSet']['name'] = vm['name']
								json_data['changeSet']['parent']['moid'] = autogen_host['moid']
								json_data['changeSet']['parent']['type'] = "HostSystem"
								if target_config_object == "Hierarchy":
									json_data['changeSet']['runtime']['host']['moid'] = autogen_host['moid']
									json_data['changeSet']['runtime']['host']['type'] = "HostSystem"
									if json_data['changeSet'].get('resourcePool', None) is not None:
										json_data['changeSet']['resourcePool']['moid'] = "autogen-resourcepool-1"
								# Applicable for VirtualMachine only
								if target_config_object == "VirtualMachine":
									json_data['changeSet']['config']['name'] = vm['name']
									json_data['changeSet']['summary']['config']['name'] = vm['name']
									json_data['changeSet']['summary']['vm']['moid'] = vm['moid']
									json_data['changeSet']['summary']['runtime']['host']['moid'] = autogen_host['moid']
									json_data['changeSet']['summary']['runtime']['host']['type'] = "HostSystem"
									if poweroff_vm_count > 0:
										json_data['changeSet']['summary']['runtime']['powerState'] = "poweredOff"
										poweroff_vm_count = poweroff_vm_count - 1
								self.logger.info("[%s] Added auto generated vm moid:%s, name:%s", target_config_object, json_data['moid'], json_data['changeSet']['name'])
								self.output.sendData(json.dumps(json_data), host=host, sourcetype=sourcetype, source=source, time=time, index=dest_index)
		del data_set

class HierarchyInventoryHandler(BaseInventoryHandler):
	"""
	Handler for running the inventory collection for targetConfig
	of Hierarchy
	"""
	def run(self, session, config, create_time, last_time):
		"""
		This is the method you must implement to perform your atomic task
		args:
			session - the session object return by the loginToTarget method
			config - the dictionary of all the config keys from your stanza in the collection.conf
			create_time - the time this task was created/scheduled to run (datetime object)
			last_time - the last time this task was created/scheduler to run (datetime object)
		
		RETURNS True if successful, False otherwise
		"""
		try:
			#Handle the destination index for the data, note that we must handle empty strings and change them to None
			dest_index = config.get("inv_index", False)
			if not dest_index:
				dest_index = None
			
			self.logger.info("[Inventory Handler] Starting Hierarchy Collection: create_time={0}, last_time={1}".format(create_time, last_time))
			self.logger.info("[Inventory Handler] Starting Cache Inspection")
			last_mor, last_version, last_session, last_dump_time = self.get_inv_cache(session[0], "Hierarchy")
			self.logger.info("[Inventory Handler] Finished Cache Inspection")
			self.logger.debug("[Inventory Handler] Cached Collection Values: last_mor:"+str(last_mor)+"|last_version:"+str(last_version)+"|last_session:"+str(last_session)+"|last_dumptime:"+str(last_dump_time))
			if last_session != session[1]:
				updatedump = True
				self.logger.info("[Inventory Handler] Found a changed session, recreating collector.")
				last_version, hierarchyCollector, target_config_object, mor = inventory.CreateHierarchyCollector(targetConfigObject="Hierarchy")
			elif (create_time-last_dump_time)>datetime.timedelta(hours=4) or (last_version != None and float(str(last_version)) >= 20):
				updatedump = True
				self.logger.info("[Inventory Handler] Found session too old or version is greater then 20, recreating collector")
				self.logger.debug("[Inventory Handler] Calling CreateHierarchyCollector: MOR:"+str(last_mor)+"| Version:"+str(last_version))
				last_version, hierarchyCollector, target_config_object, mor = inventory.CreateHierarchyCollector(managedObjectReference=last_mor, version=last_version, updateType="recycle", targetConfigObject="Hierarchy")
			else:
				updatedump = False
				self.logger.info("[Inventory Handler] Checking for updates on existing collector")
				self.logger.debug("[Inventory Handler] Calling CreateHierarchyCollector: MOR:"+str(last_mor)+"| Version:"+str(last_version))
				last_version, hierarchyCollector, target_config_object, mor = inventory.CreateHierarchyCollector(managedObjectReference=last_mor, version=last_version, targetConfigObject="Hierarchy")
			tempus = str(Connection.svcInstance.currentTime())
			sourcename = "VMInv:" + target_config_object
			last_version, is_first_version_seen = self.send_inv_data(hierarchyCollector, last_version, session[0], "vmware:inv:hierarchy", sourcename, tempus, dest_index, config, target_config_object)
			if is_first_version_seen and updatedump:
				self.set_inv_cache(session[0], "Hierarchy", mor, last_version, session[1], create_time)
				addRootNode = True
			else:
				self.set_inv_cache(session[0], "Hierarchy", mor, last_version, session[1], last_dump_time)
				addRootNode = False
			if addRootNode:
				rootNode={ "moid":Connection.rootFolder.getMOR().value, "type":"RootFolder", "changeSet":{"name":Connection.domain, "parent":{"moid":"N/A", "type":"N/A"}}}
				self.output.sendData(inventory.Jsonify(rootNode), host=session[0], sourcetype="vmware:inv:hierarchy", source=sourcename, time=tempus, index=dest_index)
			self.logger.info("[Inventory Handler] Finished collecting "+target_config_object+", stored these values: mor:"+str(mor)+" | last_version:"+str(last_version)+" | session:"+str(session[1])+" | last_dump_time:"+str(last_dump_time) )
			del last_version, mor, addRootNode, target_config_object
			return True
		except Exception as e:
			self.logger.exception(e)
			return False

class VirtualMachineInventoryHandler(BaseInventoryHandler):
	"""
	Handler for running the inventory collection for targetConfig
	of VirtualMachine
	"""
	def run(self, session, config, create_time, last_time):
		
		"""
		This is the method you must implement to perform your atomic task
		args:
			session - the session object return by the loginToTarget method
			config - the dictionary of all the config keys from your stanza in the collection.conf
			create_time - the time this task was created/scheduled to run (datetime object)
			last_time - the last time this task was created/scheduler to run (datetime object)
		
		RETURNS True if successful, False otherwise
		"""
		try:
			#Handle the destination index for the data, note that we must handle empty strings and change them to None
			dest_index = config.get("inv_index", False)
			if not dest_index:
				dest_index = None
			self.logger.info("[Inventory Handler] Starting VirtualMachine Collection: create_time={0}, last_time={1}".format(create_time, last_time))
			self.logger.info("[Inventory Handler] Starting Cache Inspection")
			last_mor, last_version, last_session, last_dump_time = self.get_inv_cache(session[0], "VirtualMachine")
			self.logger.info("[Inventory Handler] Finished Cache Inspection")
			self.logger.debug("[Inventory Handler] Cached Collection Values: last_mor:"+str(last_mor)+"|last_version:"+str(last_version)+"|last_session:"+str(last_session)+"|last_dumptime:"+str(last_dump_time))
			if last_session != session[1]:
				updatedump = True
				self.logger.info("[Inventory Handler] Found a changed session, recreating collector.")
				last_version, hierarchyCollector, target_config_object, mor = inventory.CreateHierarchyCollector(targetConfigObject="VirtualMachine")
			elif (create_time-last_dump_time)>datetime.timedelta(hours=4) or (last_version != None and float(str(last_version)) >= 20):
				updatedump = True
				self.logger.info("[Inventory Handler] Found session too old or version is greater then 20, recreating collector")
				self.logger.debug("[Inventory Handler] Calling CreateHierarchyCollector: MOR:"+str(last_mor)+"| Version:"+str(last_version))
				last_version, hierarchyCollector, target_config_object, mor = inventory.CreateHierarchyCollector(managedObjectReference=last_mor, version=last_version, updateType="recycle", targetConfigObject="VirtualMachine")
			else:
				updatedump = False
				self.logger.info("[Inventory Handler] Checking for updates on existing collector")
				self.logger.debug("[Inventory Handler] Calling CreateHierarchyCollector: MOR:"+str(last_mor)+"| Version:"+str(last_version))
				last_version, hierarchyCollector, target_config_object, mor = inventory.CreateHierarchyCollector(managedObjectReference=last_mor, version=last_version, targetConfigObject="VirtualMachine")
			tempus = str(Connection.svcInstance.currentTime())
			sourcename = "VMInv:" + target_config_object
			last_version, is_first_version_seen = self.send_inv_data(hierarchyCollector, last_version, session[0], "vmware:inv:vm", sourcename, tempus, dest_index, config, target_config_object)
			if is_first_version_seen and updatedump:
				self.set_inv_cache(session[0], "VirtualMachine", mor, last_version, session[1], create_time)
			else:
				self.set_inv_cache(session[0], "VirtualMachine", mor, last_version, session[1], last_dump_time)
			self.logger.info("[Inventory Handler] Finished collecting "+target_config_object+", stored these values: mor:"+str(mor)+" | last_version:"+str(last_version)+" | session:"+str(session[1])+" | last_dump_time:"+str(last_dump_time) )
			del last_version, mor, target_config_object
			return True
		except Exception as e:
			self.logger.exception(e)
			return False

class HostSystemInventoryHandler(BaseInventoryHandler):
	"""
	Handler for running the inventory collection for targetConfig
	of HostSystem
	"""
	def run(self, session, config, create_time, last_time):
		"""
		This is the method you must implement to perform your atomic task
		args:
			session - the session object return by the loginToTarget method
			config - the dictionary of all the config keys from your stanza in the collection.conf
			create_time - the time this task was created/scheduled to run (datetime object)
			last_time - the last time this task was created/scheduler to run (datetime object)
		
		RETURNS True if successful, False otherwise
		"""
		try:
			#Handle the destination index for the data, note that we must handle empty strings and change them to None
			dest_index = config.get("inv_index", False)
			if not dest_index:
				dest_index = None

			#Build a list of any addl. properties that need to be collected as specified in conf file
			host_config_prop_list = []
			host_config_prop_list = config.get("hostsystem_inv_config")
			
			self.logger.info("[Inventory Handler] Starting HostSystem Collection: create_time={0}, last_time={1}".format(create_time, last_time))
			self.logger.info("[Inventory Handler] Starting Cache Inspection")
			last_mor, last_version, last_session, last_dump_time = self.get_inv_cache(session[0], "HostSystem")
			self.logger.info("[Inventory Handler] Finished Cache Inspection")
			self.logger.debug("[Inventory Handler] Cached Collection Values: last_mor:"+str(last_mor)+"|last_version:"+str(last_version)+"|last_session:"+str(last_session)+"|last_dumptime:"+str(last_dump_time))
			if last_session != session[1]:
				updatedump = True
				self.logger.info("[Inventory Handler] Found a changed session, recreating collector.")
				last_version, hierarchyCollector, target_config_object, mor = inventory.CreateHierarchyCollector(targetConfigObject="HostSystem", addlTargetConfig=host_config_prop_list)
			elif (create_time-last_dump_time)>datetime.timedelta(hours=4) or (last_version != None and float(str(last_version)) >= 20):
				updatedump = True
				self.logger.info("[Inventory Handler] Found session too old or version is greater then 20, recreating collector")
				self.logger.debug("[Inventory Handler] Calling CreateHierarchyCollector: MOR:"+str(last_mor)+"| Version:"+str(last_version))
				last_version, hierarchyCollector, target_config_object, mor = inventory.CreateHierarchyCollector(managedObjectReference=last_mor, version=last_version, updateType="recycle", targetConfigObject="HostSystem",  addlTargetConfig=host_config_prop_list)
			else:
				updatedump = False
				self.logger.info("[Inventory Handler] Checking for updates on existing collector")
				self.logger.debug("[Inventory Handler] Calling CreateHierarchyCollector: MOR:"+str(last_mor)+"| Version:"+str(last_version))
				last_version, hierarchyCollector, target_config_object, mor = inventory.CreateHierarchyCollector(managedObjectReference=last_mor, version=last_version, targetConfigObject="HostSystem", addlTargetConfig=host_config_prop_list)
			tempus = str(Connection.svcInstance.currentTime())
			sourcename = "VMInv:" + target_config_object
			last_version, is_first_version_seen = self.send_inv_data(hierarchyCollector, last_version, session[0], "vmware:inv:hostsystem", sourcename, tempus, dest_index, config, target_config_object)
			if is_first_version_seen and updatedump:
				self.set_inv_cache(session[0], "HostSystem", mor, last_version, session[1], create_time)
			else:
				self.set_inv_cache(session[0], "HostSystem", mor, last_version, session[1], last_dump_time)
			self.logger.info("[Inventory Handler] Finished collecting "+target_config_object+", stored these values: mor:"+str(mor)+" | last_version:"+str(last_version)+" | session:"+str(session[1])+" | last_dump_time:"+str(last_dump_time) )
			del last_version, mor, target_config_object
			return True
		except Exception as e:
			self.logger.exception(e)
			return False

class ResourcePoolInventoryHandler(BaseInventoryHandler):
	"""
	Handler for running the inventory collection for targetConfig
	of ResourcePool
	"""
	def run(self, session, config, create_time, last_time):
		"""
		This is the method you must implement to perform your atomic task
		args:
			session - the session object return by the loginToTarget method
			config - the dictionary of all the config keys from your stanza in the collection.conf
			create_time - the time this task was created/scheduled to run (datetime object)
			last_time - the last time this task was created/scheduler to run (datetime object)
		
		RETURNS True if successful, False otherwise
		"""
		try:
			#Handle the destination index for the data, note that we must handle empty strings and change them to None
			dest_index = config.get("inv_index", False)
			if not dest_index:
				dest_index = None
			
			self.logger.info("[Inventory Handler] Starting ResourcePool Collection: create_time={0}, last_time={1}".format(create_time, last_time))
			self.logger.info("[Inventory Handler] Starting Cache Inspection")
			last_mor, last_version, last_session, last_dump_time = self.get_inv_cache(session[0], "ResourcePool")
			self.logger.info("[Inventory Handler] Finished Cache Inspection")
			self.logger.debug("[Inventory Handler] Cached Collection Values: last_mor:"+str(last_mor)+"|last_version:"+str(last_version)+"|last_session:"+str(last_session)+"|last_dumptime:"+str(last_dump_time))
			if last_session != session[1]:
				updatedump = True
				self.logger.info("[Inventory Handler] Found a changed session, recreating collector.")
				last_version, hierarchyCollector, target_config_object, mor = inventory.CreateHierarchyCollector(targetConfigObject="ResourcePool")
			elif (create_time-last_dump_time)>datetime.timedelta(hours=4) or (last_version != None and float(str(last_version)) >= 20):
				updatedump = True
				self.logger.info("[Inventory Handler] Found session too old or version is greater then 20, recreating collector")
				self.logger.debug("[Inventory Handler] Calling CreateHierarchyCollector: MOR:"+str(last_mor)+"| Version:"+str(last_version))
				last_version, hierarchyCollector, target_config_object, mor = inventory.CreateHierarchyCollector(managedObjectReference=last_mor, version=last_version, updateType="recycle", targetConfigObject="ResourcePool")
			else:
				updatedump = False
				self.logger.info("[Inventory Handler] Checking for updates on existing collector")
				self.logger.debug("[Inventory Handler] Calling CreateHierarchyCollector: MOR:"+str(last_mor)+"| Version:"+str(last_version))
				last_version, hierarchyCollector, target_config_object, mor = inventory.CreateHierarchyCollector(managedObjectReference=last_mor, version=last_version, targetConfigObject="ResourcePool")
			tempus = str(Connection.svcInstance.currentTime())
			sourcename = "VMInv:" + target_config_object
			last_version, is_first_version_seen = self.send_inv_data(hierarchyCollector, last_version, session[0], "vmware:inv:resourcepool", sourcename, tempus, dest_index, config, target_config_object)
			if is_first_version_seen and updatedump:
				self.set_inv_cache(session[0], "ResourcePool", mor, last_version, session[1], create_time)
			else:
				self.set_inv_cache(session[0], "ResourcePool", mor, last_version, session[1], last_dump_time)
			self.logger.info("[Inventory Handler] Finished collecting "+target_config_object+", stored these values: mor:"+str(mor)+" | last_version:"+str(last_version)+" | session:"+str(session[1])+" | last_dump_time:"+str(last_dump_time) )
			del last_version, mor, target_config_object
			return True
		except Exception as e:
			self.logger.exception(e)
			return False
			
class ClusterComputeResourceInventoryHandler(BaseInventoryHandler):
	"""
	Handler for running the inventory collection for targetConfig
	of ClusterComputeResource
	"""
	def run(self, session, config, create_time, last_time):
		"""
		This is the method you must implement to perform your atomic task
		args:
			session - the session object return by the loginToTarget method
			config - the dictionary of all the config keys from your stanza in the collection.conf
			create_time - the time this task was created/scheduled to run (datetime object)
			last_time - the last time this task was created/scheduler to run (datetime object)
		
		RETURNS True if successful, False otherwise
		"""
		try:
			#Handle the destination index for the data, note that we must handle empty strings and change them to None
			dest_index = config.get("inv_index", False)
			if not dest_index:
				dest_index = None
			
			self.logger.info("[Inventory Handler] Starting ClusterComputeResource Collection: create_time={0}, last_time={1}".format(create_time, last_time))
			self.logger.info("[Inventory Handler] Starting Cache Inspection")
			last_mor, last_version, last_session, last_dump_time = self.get_inv_cache(session[0], "ClusterComputeResource")
			self.logger.info("[Inventory Handler] Finished Cache Inspection")
			self.logger.debug("[Inventory Handler] Cached Collection Values: last_mor:"+str(last_mor)+"|last_version:"+str(last_version)+"|last_session:"+str(last_session)+"|last_dumptime:"+str(last_dump_time))
			if last_session != session[1]:
				updatedump = True
				self.logger.info("[Inventory Handler] Found a changed session, recreating collector.")
				last_version, hierarchyCollector, target_config_object, mor = inventory.CreateHierarchyCollector(targetConfigObject="ClusterComputeResource")
			elif (create_time-last_dump_time)>datetime.timedelta(hours=4) or (last_version != None and float(str(last_version)) >= 20):
				updatedump = True
				self.logger.info("[Inventory Handler] Found session too old or version is greater then 20, recreating collector")
				self.logger.debug("[Inventory Handler] Calling CreateHierarchyCollector: MOR:"+str(last_mor)+"| Version:"+str(last_version))
				last_version, hierarchyCollector, target_config_object, mor = inventory.CreateHierarchyCollector(managedObjectReference=last_mor, version=last_version, updateType="recycle", targetConfigObject="ClusterComputeResource")
			else:
				updatedump = False
				self.logger.info("[Inventory Handler] Checking for updates on existing collector")
				self.logger.debug("[Inventory Handler] Calling CreateHierarchyCollector: MOR:"+str(last_mor)+"| Version:"+str(last_version))
				last_version, hierarchyCollector, target_config_object, mor = inventory.CreateHierarchyCollector(managedObjectReference=last_mor, version=last_version, targetConfigObject="ClusterComputeResource")
			tempus = str(Connection.svcInstance.currentTime())
			sourcename = "VMInv:" + target_config_object
			last_version, is_first_version_seen = self.send_inv_data(hierarchyCollector, last_version, session[0], "vmware:inv:clustercomputeresource", sourcename, tempus, dest_index, config, target_config_object)
			if is_first_version_seen and updatedump:
				self.set_inv_cache(session[0], "ClusterComputeResource", mor, last_version, session[1], create_time)
			else:
				self.set_inv_cache(session[0], "ClusterComputeResource", mor, last_version, session[1], last_dump_time)
			self.logger.info("[Inventory Handler] Finished collecting "+target_config_object+", stored these values: mor:"+str(mor)+" | last_version:"+str(last_version)+" | session:"+str(session[1])+" | last_dump_time:"+str(last_dump_time) )
			del last_version, mor, target_config_object
			return True
		except Exception as e:
			self.logger.exception(e)
			return False

class DatastoreInventoryHandler(BaseInventoryHandler):
	"""
	Handler for running the inventory collection for targetConfig
	of Datastore
	"""
	def run(self, session, config, create_time, last_time):
		"""
		This is the method you must implement to perform your atomic task
		args:
			session - the session object return by the loginToTarget method
			config - the dictionary of all the config keys from your stanza in the collection.conf
			create_time - the time this task was created/scheduled to run (datetime object)
			last_time - the last time this task was created/scheduler to run (datetime object)
		
		RETURNS True if successful, False otherwise
		"""
		try:
			#Handle the destination index for the data, note that we must handle empty strings and change them to None
			dest_index = config.get("inv_index", False)
			if not dest_index:
				dest_index = None
			
			self.logger.info("[Inventory Handler] Starting Datastore Collection: create_time={0}, last_time={1}".format(create_time, last_time))
			self.logger.info("[Inventory Handler] Starting Cache Inspection")
			last_mor, last_version, last_session, last_dump_time = self.get_inv_cache(session[0], "Datastore")
			self.logger.info("[Inventory Handler] Finished Cache Inspection")
			self.logger.debug("[Inventory Handler] Cached Collection Values: last_mor:"+str(last_mor)+"|last_version:"+str(last_version)+"|last_session:"+str(last_session)+"|last_dumptime:"+str(last_dump_time))
			if last_session != session[1]:
				updatedump = True
				self.logger.info("[Inventory Handler] Found a changed session, recreating collector.")
				last_version, hierarchyCollector, target_config_object, mor = inventory.CreateHierarchyCollector(targetConfigObject="Datastore")
			elif (create_time-last_dump_time)>datetime.timedelta(hours=4) or (last_version != None and float(str(last_version)) >= 20):
				updatedump = True
				self.logger.info("[Inventory Handler] Found session too old or version is greater then 20, recreating collector")
				self.logger.debug("[Inventory Handler] Calling CreateHierarchyCollector: MOR:"+str(last_mor)+"| Version:"+str(last_version))
				last_version, hierarchyCollector, target_config_object, mor = inventory.CreateHierarchyCollector(managedObjectReference=last_mor, version=last_version, updateType="recycle", targetConfigObject="Datastore")
			else:
				updatedump = False
				self.logger.info("[Inventory Handler] Checking for updates on existing collector")
				self.logger.debug("[Inventory Handler] Calling CreateHierarchyCollector: MOR:"+str(last_mor)+"| Version:"+str(last_version))
				last_version, hierarchyCollector, target_config_object, mor = inventory.CreateHierarchyCollector(managedObjectReference=last_mor, version=last_version, targetConfigObject="Datastore")
			tempus = str(Connection.svcInstance.currentTime())
			sourcename = "VMInv:" + target_config_object
			last_version, is_first_version_seen = self.send_inv_data(hierarchyCollector, last_version, session[0], "vmware:inv:datastore", sourcename, tempus, dest_index, config, target_config_object)
			if is_first_version_seen and updatedump:
				self.set_inv_cache(session[0], "Datastore", mor, last_version, session[1], create_time)
			else:
				self.set_inv_cache(session[0], "Datastore", mor, last_version, session[1], last_dump_time)
			self.logger.info("[Inventory Handler] Finished collecting "+target_config_object+", stored these values: mor:"+str(mor)+" | last_version:"+str(last_version)+" | session:"+str(session[1])+" | last_dump_time:"+str(last_dump_time) )
			del last_version, mor, target_config_object
			return True
		except Exception as e:
			self.logger.exception(e)
			return False
