# -*-  indent-tabs-mode:nil;  -*- 
# Copyright (C) 2005-2016 Splunk Inc. All Rights Reserved. 
# Core Python Imports
import sys
import datetime
import math
import re
import random

from splunk import util

# Append SA-Hydra/bin/pacakges to the Python path

from splunk.appserver.mrsparkle.lib.util import make_splunkhome_path
sys.path.append(make_splunkhome_path(['etc', 'apps', 'SA-Hydra', 'bin', 'packages']))

# Import TA-VMware collection code

from vim25.performance import PerfCollector
from vim25.connection import Connection
from vim25 import utils
from vim25 import hostvm_metrics
from vim25.mo import ManagedObjectReference
from vim25.mo import ManagedObject

import hydra

DBG_SUFFIX = ""
SEP = '\t'
HEADER_LIM = 100
NUM_VMS_SINGLE_COLLECTION = 80
datastore_details = {} # This dict will be used to keep mapping of datastore moid and its url, capacity & free space.

class BasePerfHandler(hydra.HydraHandler):
	def _prepare_timestamps(self, *args):
		"""
		Input: varargs list of datetime objects (assumed UTC).
		Output: UTC datetime(s) corresponding to the server clock that are guaranteed to have
				correct tzinfo field. Outputs single object for a single input argument, a list 
				for multiple input arguments.
		"""
		results = utils.AddUtcTzinfo(utils.ConvertToServerTime(args, Connection.svcInstance, zone="UTC")) 
		return results[0] if len(results) == 1 else results
		
	def _create_counter_from_id(self, metricid, instanced=False):
		'''
		Takes a single "id" and will return a PerfMetricId with instance set to * or ""
		
		@metricid = a number referring to the counter id on a vc
		@int
		@instanced = boolean based on if the metric is to be used in instanced level collection
		@bool
		'''
		if bool(instanced):
			return Connection.vim25client.new('PerfMetricId', counterId=metricid, instance="*")
		else:
			return Connection.vim25client.new('PerfMetricId', counterId=metricid, instance="")
	
	def _merged_host_vm_cache(self, metricscache):
		'''
		takes a metric cache with hostmetrics and vmmetrics set and will return 1 list of dicts with the unique
		counters in both
		'''
		mergedcache = metricscache['hostmetrics']
		for item in metricscache['vmmetrics']:
			if not item in mergedcache:
				mergedcache.append(item)
		return mergedcache
	
	def _check_format_type(self, format_type):
		'''
			Check if performance performance type, raise exception is not correct.
			@param format_type: specified peformance type in str format
			
			@return: Exception, if it is not supported format, otherwise None
		'''
		if not format_type in ['csv', 'normal']:
			self.logger.error("[Performance Handler] Specify performance format is incorrect. Specify format type either csv or normal.")
			raise Exception("[Performance Handler] Specify performance format is incorrect. Specify format type either csv or normal.")
		
	def _process_timestamps(self, perfdata, format):
		'''
			Get list of timestamps value in %Y-%m-%dT%H:%M:%SZ format of perfdata
			
			@return list of timestamps in %Y-%m-%dT%H:%M:%SZ format
		'''
		if format == 'csv':
			return perfdata.sampleInfoCSV.split(',')[1::2]
		else:
			timestamps = []
			for sampleInfo in perfdata.sampleInfo:
				# same time format as csv type
				timestamps.append(sampleInfo.timestamp.strftime('%Y-%m-%dT%H:%M:%SZ'))
			return timestamps

	def _process_perf_data(self, perfdata_array, format):
		"""Parses performance data and returns a nested dict which can be used
		for outputting data in table form.
		
		@param format: Define perfdata format type. Possible values for this: 'csv' or 'normal'
		
		Table keys are formed by the (timestamp, group, entity_type) tuples.
		For each table key, the entries include moid, counter instance, and a list of metrics;
		this information is stored in a nested dictionary.
		
		Expects that metric cache has been set on the handler.
		"""
		
		res = {}
		host_instance_blist = [re.compile(x) for x in self.config['host_instance_blacklist']]
		host_instance_wlist = [re.compile(x) for x in self.config['host_instance_whitelist']]
		vm_instance_blist = [re.compile(x) for x in self.config['vm_instance_blacklist']]
		vm_instance_wlist = [re.compile(x) for x in self.config['vm_instance_whitelist']]
		for perfdata in perfdata_array: # entities
			if (format == 'csv' and perfdata.sampleInfoCSV is None) or (format == 'normal' and perfdata.sampleInfo is None): 
				self.logger.debug("[Performance Handler] Missing sample info for entity=%s of type=%s, skipping record",
					perfdata.entity.value, perfdata.entity._type)
				continue
			mergedcache = self._merged_host_vm_cache(self.metricscache)
			timestamps = self._process_timestamps(perfdata, format)
			for pmser in perfdata.value: # counters (group, instance, name)
				processmetric=True
				if format == 'csv':
					data_values = pmser.value.split(',')
				else:
					# normal format type has value in array format
					# Converting long to str format same as csv format
					data_values = [str(x) for x in pmser.value]
				pc = pmser.id.counterId
				fqname, group = [(x['name'], x['group']) for x in mergedcache if x['id']==pc][0]
				#group = pc.groupInfo.key
				entity_name = perfdata.entity.value
				# instance value of None or "" means this is an aggregated metric
				inst = pmser.id.instance if pmser.id.instance else "aggregated"
				# need to add logic to process the instance whitelist / blist
				if entity_name.startswith("host"):
					# check if there is no whitelist but a blist, if so, process everything that's not on the blist
					if not host_instance_wlist and host_instance_blist:
						if [regexmatch for regexmatch in host_instance_blist if regexmatch.match(inst)]:
							processmetric=False
					# check if there is no blacklist but a wlist, if so, process everything that's only in the wlist
					elif host_instance_wlist and not host_instance_blist:
						processmetric=False
						if [regexmatch for regexmatch in host_instance_wlist if regexmatch.match(inst)]:
							processmetric=True
					# there is both a whitelist and blacklist, process the items only in the whitelist and exclude the ones in the blacklist
					elif host_instance_wlist and host_instance_blist:
						processmetric=False
						if [regexmatch for regexmatch in host_instance_wlist if regexmatch.match(inst)] and not [regexmatch for regexmatch in host_instance_blist if regexmatch.match(inst)]:
							processmetric=True
				elif entity_name.startswith("vm"):
					# check if there is no whitelist but a blist, if so, process everything that's not on the blist
					if not vm_instance_wlist and vm_instance_blist:
						if [regexmatch for regexmatch in vm_instance_blist if regexmatch.match(inst)]:
							processmetric=False
					# check if there is no blacklist but a wlist, if so, process everything that's only in the wlist
					elif vm_instance_wlist and not vm_instance_blist:
						processmetric=False
						if [regexmatch for regexmatch in vm_instance_wlist if regexmatch.match(inst)]:
							processmetric=True
					# there is both a whitelist and blacklist, process the items only in the whitelist and exclude the ones in the blacklist
					elif vm_instance_wlist and vm_instance_blist:
						processmetric=False
						if [regexmatch for regexmatch in vm_instance_wlist if regexmatch.match(inst)] and not [regexmatch for regexmatch in vm_instance_blist if regexmatch.match(inst)]:
							processmetric=True
				if processmetric:
					for tsi in range(len(timestamps)): # times
						# timestamps are returned as UTC: 2013-04-01T23:06:00Z
						ts = timestamps[tsi]
						key = (ts, group, perfdata.entity._type)
						# res[key] contains table data; 
						# res[key][0] is the table (stored as nested dict), res[key][1] holds a set() of headers
						if key not in res: res[key] = ({}, set())
						if fqname not in res[key][1]: res[key][1].add(fqname)
						if entity_name not in res[key][0]: res[key][0][entity_name] = {}
						if inst not in res[key][0][entity_name]: res[key][0][entity_name][inst] = {}
						res[key][0][entity_name][inst][fqname] = data_values[tsi]
				else:
					self.logger.debug("[Performance Handler] {task} Current instance ("+inst+") does not meet whitelist/blacklist and will be ignored.")
		return res

	# Set datastore Details
	def _set_datastore_detail(self, datastore_mor_list):
		"""
		Input: list of datastore mor.
		Updates datastore_details global dictionary.
		"""
		try:
			global datastore_details
			for mor in datastore_mor_list.ManagedObjectReference:
				ds_moid = mor.value
				if ds_moid not in datastore_details:
					mo = Connection.vim25client.createExactManagedObject(mor)
					datastore_url = str(mo.getCurrentProperty("summary.url"))
					datastore_capacity = str(mo.getCurrentProperty("summary.capacity"))
					datastore_freespace = str(mo.getCurrentProperty("summary.freeSpace"))
					datastore_details[ds_moid] = [datastore_url, datastore_capacity, datastore_freespace]
			return
		except Exception as e:
			self.logger.warn("[Performance Handler] Error While getting some property for datastore  : {0}, Error: {1}.".format(ds_moid, e))


	def _output_results(self, grouped_data, output=None, host=None):
		"""Takes the output of group_perf_data and an output handler and 
		creates data tables."""
		
		def build_header(headers_list):
			return "%s"*9 % ("moid", SEP, "uuid", SEP, "instance", SEP, "samp_int", SEP, SEP.join(headers_list))
				
		def build_line(entity, uuid,  inst, samp_int, data, headers_list):
			def retrieve(name):
				# values labeled percent are actually in units of % * 100, so must convert
				div_by_100_tostr = lambda x: str(float(x) / 100) if x else ""
				val = data.get(name, "")
				return div_by_100_tostr(val) if (re.search("percent$", name) is not None) else val
				
			return "%s"*9 % (entity, SEP, uuid, SEP, inst, SEP, samp_int, SEP,
								   SEP.join([retrieve(fqname) for fqname in headers_list]))

		def build_metadata(ts, host, group, entity_type):
			#Handle the destination index for the data, note that we must handle empty strings and change them to None
			dest_index = self.config.get("perf_index", False)
			if not dest_index:
				dest_index = None
			
			return {'sourcetype': 'vmware:perf:{group}'.format(group=group),
					'source': 'VMPerf:{entity_type}'.format(entity_type=entity_type),
					'host': '{host}'.format(host=host),
					'time': utils.ConvertIsoUtcDate(ts),
					'index': dest_index}
		if not output:
			output=self.output
		if not host:
			host=Connection.domain
		buf = []
		unbroken = False
		mi_metadata = {}
		host_uuid_map = {}  # This dictionary will keep mapping of host moid and uuid.
		vm_uuid_map = {}    # This dictionary will keep mapping of vm moid and uuid.
		host_vm_ds_map = {} # This dictionary will keep mapping of host/vm moid and their datastore moids.
		vm_storage_map = {} # This dictionary will keep mapping of vm moid and its committed & uncommitted space.
		global datastore_details
		host_mo = None
		vm_mo = None
		for key in grouped_data:
			ts, g, entity_type = key
			if entity_type == "HostSystem":
				samp_int = str(self.metricscache['hostrefreshrate']) # get sampling interval
			elif entity_type == "VirtualMachine":
				samp_int = str(self.metricscache['vmrefreshrate']) # get sampling interval
			mi_metadata = build_metadata(ts, host, g, entity_type)
			headers_list = list(grouped_data[key][1])
			if entity_type == "VirtualMachine" and g == "datastore":
				headers_list.extend(["storage_committed","storage_uncommitted"])
			if g == "datastore":
				headers_list.extend(["datastore_capacity","datastore_freespace"])
			cur_header = build_header(headers_list)
			buf = [ cur_header ]
			linecount = 0
			uuid = ""
			for entity in grouped_data[key][0]:
				if entity_type == "HostSystem":
					if entity not in host_uuid_map:
						host_mor = ManagedObjectReference(value=entity, _type="HostSystem")
						host_mo = Connection.vim25client.createExactManagedObject(host_mor)
						uuid = host_mo.getCurrentProperty("hardware.systemInfo.uuid")
						host_uuid_map[entity] = uuid
					else:
						uuid = host_uuid_map.get(entity, None)
					if entity not in host_vm_ds_map:
						if host_mo == None:
							host_mor = ManagedObjectReference(value=entity, _type="HostSystem")
							host_mo = Connection.vim25client.createExactManagedObject(host_mor)
						host_ds_moid_list = []
						datastore_mor_list = host_mo.getCurrentProperty("datastore")
						for datastore_mor in datastore_mor_list.ManagedObjectReference:
							host_ds_moid_list.append(datastore_mor.value)
						host_vm_ds_map[entity] = host_ds_moid_list
						self._set_datastore_detail(datastore_mor_list)
				elif entity_type == "VirtualMachine":
					if entity not in vm_uuid_map:
						vm_mor = ManagedObjectReference(value=entity, _type="VirtualMachine")
						vm_mo = Connection.vim25client.createExactManagedObject(vm_mor)
						uuid = vm_mo.getCurrentProperty("config.instanceUuid")
						vm_uuid_map[entity] = uuid
					else:
						uuid = vm_uuid_map.get(entity, None)
					if entity not in host_vm_ds_map:
						if vm_mo == None:
							vm_mor = ManagedObjectReference(value=entity, _type="VirtualMachine")
							vm_mo = Connection.vim25client.createExactManagedObject(vm_mor)
						vm_ds_moid_list = []
						datastore_mor_list = vm_mo.getCurrentProperty("datastore")
						for datastore_mor in datastore_mor_list.ManagedObjectReference:
							vm_ds_moid_list.append(datastore_mor.value)
						host_vm_ds_map[entity] = vm_ds_moid_list
						self._set_datastore_detail(datastore_mor_list)
					if entity not in vm_storage_map:
						if vm_mo == None:
							vm_mor = ManagedObjectReference(value=entity, _type="VirtualMachine")
							vm_mo = Connection.vim25client.createExactManagedObject(vm_mor)
						committed= vm_mo.getCurrentProperty("summary.storage.committed")
						uncommitted = vm_mo.getCurrentProperty("summary.storage.uncommitted")
						vm_storage_map[entity] = [committed, uncommitted]
				for inst in grouped_data[key][0][entity]:
					if (entity_type == "HostSystem" or entity_type == "VirtualMachine") and g == "datastore":
						if entity_type == "VirtualMachine":
							grouped_data[key][0][entity][inst]['storage_committed'] = str(vm_storage_map[entity][0])
							grouped_data[key][0][entity][inst]['storage_uncommitted'] = str(vm_storage_map[entity][1])
						if inst != 'aggregated':
							ds_moid_list = host_vm_ds_map[entity]
							for moid in ds_moid_list:
							# Check if datastore current inst matches with the datastore url
								if inst in datastore_details[moid][0]:
									grouped_data[key][0][entity][inst]['datastore_capacity'] = datastore_details[moid][1]
									grouped_data[key][0][entity][inst]['datastore_freespace'] = datastore_details[moid][2]
					buf.append(build_line(entity, uuid, inst, samp_int, grouped_data[key][0][entity][inst], headers_list))
					linecount += 1
					if linecount > HEADER_LIM:
						output.sendData('\n'.join(buf), unbroken=unbroken, **mi_metadata)
						if unbroken: output.sendDoneKey(**mi_metadata)
						buf = [ cur_header ]
						linecount = 0
			output.sendData('\n'.join(buf), unbroken=unbroken, **mi_metadata)
			if unbroken: output.sendDoneKey(**mi_metadata)
			# Send dummy data only if dummy data is being configured (large scale testing purpose only)
			if self.config.get('autoeventgen', None) and self.config['autoeventgen']:
				# Get cache
				auto_generatedids = self.gateway_adapter.get_cache("autogenertedid:"+self.config["target"][0])
				if auto_generatedids is None:
					self.logger.error("Could not find out generated ids in the gateway cache")
				else:
					clusters_moids = []
					hosts_moids = []
					vms_moids = []
					for cluster in auto_generatedids['clusters']:
						clusters_moids.append(cluster['moid'])
						for autogen_host in cluster['hosts']:
							hosts_moids.append(autogen_host['moid'])
							for vm in autogen_host['vms']:
								vms_moids.append(vm['moid'])
					if entity_type == "HostSystem":
						obj_list = hosts_moids
						mapping_count = math.floor(len(obj_list)/auto_generatedids['existing_hosts_count'])
					elif entity_type == "VirtualMachine":
						obj_list = vms_moids
						mapping_count = math.floor(len(obj_list)/auto_generatedids['existing_vms_count'])
					elif entity_type == "ClusterComputeResource":
						obj_list = clusters_moids
						mapping_count = len(obj_list)
					else:
						# Future if dummy performance data is generated
						pass
					dummy_buf = [ cur_header ]
					dummy_linecount = 0
					for entity in grouped_data[key][0]:
						for inst in grouped_data[key][0][entity]:
							for index in range(int(mapping_count)):
								obj_moid = obj_list[random.randint(0, len(obj_list)-1)]
								dummy_buf.append(build_line(obj_moid, inst, samp_int, grouped_data[key][0][entity][inst], headers_list))
								dummy_linecount += 1
								if dummy_linecount > HEADER_LIM:
									output.sendData('\n'.join(dummy_buf), unbroken=unbroken, **mi_metadata)
									if unbroken: output.sendDoneKey(**mi_metadata)
									dummy_buf = [ cur_header ]
									dummy_linecount = 0
					output.sendData('\n'.join(dummy_buf), unbroken=unbroken, **mi_metadata)
					if unbroken: output.sendDoneKey(**mi_metadata)

class HostVMPerfHandler(BasePerfHandler):
	"""
	Handler for running host/vm perf collection
	Quasi-real-time, 20-second performance samples are collected from host systems and VMs;
	"""
	# all functionality currently captured by the base handler 
	def run(self, session, config, create_time, last_time):
		"""
		create_time - the time this task was created/scheduled to run (datetime object)
		last_time - the last time this task was created/scheduler to run (datetime object)
		RETURNS True if successful, False otherwise
		"""

		try:
			#Handle the destination index for the data, note that we must handle empty strings and change them to None
			if not hasattr(self, 'pc') or not hasattr(self, 'config'):
				self.config = config
				self.logger.debug("[Performance Handler] {task} Instantiating PerfCollector for ...".format(task=config['perf_collection_type']))
				self.pc = PerfCollector(config, self.logger)
			self.pc.update_config(config)
			dest_index = config.get("perf_index", False)
			# grab an existing cache if it already exists
			self.metricscache = self.gateway_adapter.get_cache(Connection.domain+':hostvmperf:metrics')
			# grab the hierarchy from the gateway
			target_host_cache = "perfhierarchy:"+Connection.domain+":"+config['perf_target_hosts'][0]
			self.vms_on_host = self.gateway_adapter.get_cache(target_host_cache)
			if not self.vms_on_host:
					self.logger.info("[Performance Handler] {task} No hierarchy with vm's in hierarchy cache. Cache Target: {target}".format(task=config['perf_collection_type'], target=target_host_cache))
					self.logger.info("[Performance Handler] {task} Running collection on host only.".format(task=config['perf_collection_type']))
			# check if cache was returned valid
			if not self.metricscache:
				# Couldn't find metrics, need to populate the cache
				if not self.vms_on_host:
					self.logger.info("[Performance Handler] {task} Running metrics cache creation without vms.  This will need to be updated once a host is processed with vms.".format(task=config['perf_collection_type']))
					self.metricscache = hostvm_metrics.MetricsCache(hostmoid=config["perf_target_hosts"][0], vmmoid=[]).fullcounters
				else:
					self.metricscache = hostvm_metrics.MetricsCache(hostmoid=config["perf_target_hosts"][0], vmmoid=self.vms_on_host[config["perf_target_hosts"][0]]).fullcounters
				if self.metricscache:
					set_cache_returncode = self.gateway_adapter.set_cache(name=Connection.domain+':hostvmperf:metrics', value=self.metricscache, expiration=172800)
					if set_cache_returncode != 200:
						self.logger.error("[Performance Handler] {task} Failed updating metrics cache raising an exception.")
						return False
				else:
					self.logger.error("[Performance Handler] {task} There was an error returning metrics from the vc for the selected host ( vc={vc} target_host={host} ).".format(task=config['perf_collection_type'], vc=Connection.domain, host=config["perf_target_hosts"][0]))
					return False
			if not self.metricscache['vmmetrics'] and self.vms_on_host:
				self.logger.error("[Performance Handler] {task} Metrics cache is missing vmmetrics and this host has active vms.  Updating cache.".format(task=config['perf_collection_type']))
				self.metricscache = hostvm_metrics.MetricsCache(hostmoid=config["perf_target_hosts"][0], vmmoid=self.vms_on_host[config["perf_target_hosts"][0]]).fullcounters
				if self.metricscache:
					set_cache_returncode = self.gateway_adapter.set_cache(name=Connection.domain+':hostvmperf:metrics', value=self.metricscache, expiration=172800)
					if set_cache_returncode != 200:
						self.logger.error("[Performance Handler] {task} Failed updating metrics cache raising an exception.")
						return False
				else:
					self.logger.error("[Performance Handler] {task} There was an error returning metrics from the vc for the selected host ( vc={vc} target_host={host} ).".format(task=config['perf_collection_type'], vc=Connection.domain, host=config["perf_target_hosts"][0]))
					return False
			# set the dest index for the mod input output 
			if not dest_index:
				dest_index = None
			# grab the real times for collection from the vc
			start_time, end_time = self._prepare_timestamps(last_time, create_time)
			self.logger.debug("[Performance Handler] {task} Converting (last_time, create_time) to server time; location=handler_args_server_clock start_time={s} end_time={e}".format(task=config['perf_collection_type'], s=start_time, e=end_time))
			# setup different collection time checks in-case 0 second span passed for first run.
			if end_time - start_time < datetime.timedelta(seconds=1):
				start_time = end_time - datetime.timedelta(seconds=1)
			perf_data = []
			entities = []
			# get format type (default 'csv')
			format_type = self.config.get('perf_format_type', 'csv')
			self._check_format_type(format_type)
			#Create MOR for the host
			#Check if host systems are blisted, if not, add them to the collection.  
			#This next part is going to look like a rip off of _query_perf, but it should exist in the handler
			for host_moid in config['perf_target_hosts']:
				if not self.pc._is_entity_blacklisted('HostSystem'):
					#runs through the metric cache and builds metric objects based on the correct instance.
					metrics=[]
					if config["host_instance_whitelist"] or config["host_instance_blacklist"]:
						metrics=[self._create_counter_from_id(metric['id'], instanced=True) for metric in self.metricscache['hostmetrics']]
					else:
						metrics=[self._create_counter_from_id(metric['id']) for metric in self.metricscache['hostmetrics']]
					host_mor = ManagedObjectReference(value=host_moid, _type="HostSystem")
					queryspec = Connection.vim25client.new('PerfQuerySpec', entity=host_mor, metricId=metrics, format=format_type, intervalId=self.metricscache['hostrefreshrate'], startTime=start_time, endTime=end_time)
					#queryspec built for the current host, adding it to the collection cycle
					entities.append(queryspec)
				#Now find the vm's 
				if self.vms_on_host:
					for vm_moid in self.vms_on_host[host_moid]:
						if not self.pc._is_entity_blacklisted('VirtualMachine'):
							#runs through the metric cache and builds metric objects based on the correct instance.
							metrics=[]
							if config["vm_instance_whitelist"] or config["vm_instance_blacklist"]:
								metrics=[self._create_counter_from_id(metric['id'], instanced=True) for metric in self.metricscache['vmmetrics']]
							else:
								metrics=[self._create_counter_from_id(metric['id']) for metric in self.metricscache['vmmetrics']]
							vm_mor = ManagedObjectReference(value=vm_moid, _type="VirtualMachine")
							queryspec = Connection.vim25client.new('PerfQuerySpec', entity=vm_mor, metricId=metrics, format=format_type, intervalId=self.metricscache['vmrefreshrate'], startTime=start_time, endTime=end_time)
							entities.append(queryspec)
				#All eligible vm's and hosts should have been added to the entities dict.  Time to get perf.
				if len(entities) > 0:
					num_collections = math.ceil(len(entities) / float(NUM_VMS_SINGLE_COLLECTION))
					chunk_size = int(math.ceil(len(entities) / num_collections))
					assert chunk_size >= 0 and chunk_size <= len(entities)
					for i in range(int(num_collections)):
						#python is OK with slice indexes being longer than max list index
						chunk = entities[i * chunk_size : (i + 1) * chunk_size]
						perfdata = Connection.perfManager.queryPerf(chunk)
						parse = self._process_perf_data(perfdata, format_type)
						self._output_results(parse)
					entities = []
			# Clean the global dictionary at the end of task.
			global datastore_details
			datastore_details = {}
			self.logger.info("[Performance Handler] {task} finished collecting perf".format(task=config['perf_collection_type']))
			return True
		except Exception as e:
			self.logger.exception(e) 
			return False


class OtherPerfHandler(BasePerfHandler):
	"""
	Handler for running Cluster/RP perf collection
	5-minute aggregate stastistics is gathered from clusters and resource pools.
	"""
	def run(self, session, config, create_time, last_time):
		"""
		create_time - the time this task was created/scheduled to run (datetime object)
		last_time - the last time this task was created/scheduler to run (datetime object)
		RETURNS True if successful, False otherwise
		"""
		try:
			#Handle the destination index for the data, note that we must handle empty strings and change them to None
			dest_index = config.get("perf_index", False)
			if not dest_index:
				dest_index = None
			start_time, end_time = self._prepare_timestamps(last_time, create_time)
			self.logger.debug("[Performance Handler] {task} Converting (last_time, create_time) to server time; location=handler_args_server_clock start_time={s} end_time={e}".format(task=config['perf_collection_type'], s=start_time, e=end_time))

			if not hasattr(self, 'pc') or not hasattr(self, 'config'):
				self.config = config
				self.logger.debug("[Performance Handler] {task} Instantiating PerfCollector...".format(task=config['perf_collection_type']))
				self.pc = PerfCollector(config, self.logger)
			self.pc.update_config(config)
			self.pc.collect_performance(start_time, end_time, self.output, host=session[0]+DBG_SUFFIX)
			return True
		except Exception as e:
			self.logger.exception(e) 
			return False
	
