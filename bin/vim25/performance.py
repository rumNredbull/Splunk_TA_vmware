# -*-  indent-tabs-mode:nil;  -*- 
# Copyright (C) 2005-2017 Splunk Inc. All Rights Reserved. 

import datetime
import random

from vim25.mo import ManagedObjectReference
from vim25 import utils
from vim25.connection import Connection

import vim25.inventory as inventory
from vim25.metrics_list_matcher import MetricsListMatcher
from vim25.metrics_cache import MetricsCache

from collections import defaultdict
import math
import re

SEP = '\t'
HEADER_LIM = 100
ENTITY_ABBREV = {'HostSystem': 'host', 'VirtualMachine': 'vm', 
				 'ResourcePool': 'rp', 'ClusterComputeResource': 'cluster'}
# available performance metrics will be queried from every entity in this group
ALL_METRICS_FROM_ALL_ENTITIES_TYPES = ["ClusterComputeResource", "ResourcePool"]

class PerfCollector(Connection):
	"""Class responsible for retrieval and output of performance metrics.

	Instantiated with:
	  config - dict of collection parameters
	  logger - logger instance

	Caches: 
	  performance metrics (from queryAvailablePerfMetrics)
	  performance counters (from PerfCounterInfo)
	
	The caches are typically multi-level dictionaries, with the VCs at the root level.
	"""
	def __init__(self, config, logger):
		self.config = config
		self.dbg_info = "[Performance Handler: {task}] [PerfCollector] ".format(task=config['perf_collection_type'])
		self.logger = logger
		self.logger.debug(self.dbg_info + "Instantiating perf collection class for %s (%s)" % (config['perf_collection_type'], str(config['perf_target_hosts'])))
		self._ref_rate_cache = {}
		self._counters_cache = {} # format: {self.domain: {'pcs_by_key': {}, 'pcs_fqname_by_key': {}}}
		self._metrics_cache = {}  # format: {self.domain: MetricsCache(200, 50)}
		self._vc_saved_id = None
		# self.logger.debug(self.dbg_info + "Done initializing perf collector")
		# self._update_counters_cache()
		# self.logger.debug(self.dbg_info + "Done updating perf counter caches")


	def update_config(self, newconfig):
		"""
		Updates the config member variable.  Note that target-specific keys
		in the config are expected to be different, so they are is excluded from
		comparison.
		"""
		def config_same(c1, c2):
			exclude_keys = ['perf_target_hosts', 'username', 'target', 'target_type']
			for k in c1:
				if k in exclude_keys: continue
				if c1[k] != c2[k]: return False
			return True
		# If config is different, blow away the caches
		if not config_same(self.config, newconfig):
			self.logger.debug(self.dbg_info + "Found different config, blowing away caches")
			self._counters_cache = {} 
			self._metrics_cache = {} 
		self.config = newconfig
		


	def _update_counters_cache(self):
		"""Checks the current vc ID agains the saved vc_id and if we have changed vcs (or we
		haven't talked to one before) create (or re-create) dictionaries of performance counters 
		keyed by ID.  Returns the vcenter UUID."""
		def populate_counter_dicts():
			pcis = self.perfManager.getPerfCounter().PerfCounterInfo
			pcs_by_key = {}
			pcs_fqname_by_key = {}
			for pc in pcis:
				pcs_by_key[pc.key] = pc
				pcs_fqname_by_key[pc.key] = self._get_fqname(pc)
			return {'pcs_by_key': pcs_by_key, 'pcs_fqname_by_key': pcs_fqname_by_key}
			
		if self.domain != self._vc_saved_id:
			self._vc_saved_id = self.domain
			if self.domain not in self._counters_cache:
				self._counters_cache[self.domain] = populate_counter_dicts()
				self.logger.debug(self.dbg_info + "Populated counters cache for domain %s", self.domain)
			self.pcs_by_key = self._counters_cache[self.domain]['pcs_by_key']
			self.pcs_fqname_by_key = self._counters_cache[self.domain]['pcs_fqname_by_key']
		return self._vc_saved_id

		
	def _update_entity_lists(self):
		"""Generates up-to-date entity lists by querying inventory.
		vc_id: Virtual center's UUID, needed as part of the inventory hash

		Returns: dict of entities keyed by entity_type (e.g.
				 'HostSystem'/'VirtualMachine' if this collector does host/vm perf, or 
				 'ResourcePool'/'ClusterComputeResource'

		Entities are represented via MORs; if a MOR is needed from MOID (e.g. 
		to construct a host MOR from the config parameter), one is obtained by
		instantiating vim25.mo.ManagedObjectReference(moid, type)"""
		def get_inventory_by_entity(e):
			if   e == 'HostSystem': return [host_mor] # defined later in the outer function
			elif e == 'VirtualMachine': return self._find_vms_for_host(host_moid)
			elif e == 'ResourcePool': return self._find_rps()
			elif e == 'ClusterComputeResource': return self._find_clusters()
			else: return []
		def update_entities_maybe(e):
			if not self._is_entity_blacklisted(e): 
				entities[e].extend(get_inventory_by_entity(e))
			else:
				self.logger.debug(self.dbg_info + "Entity %s blacklisted for collection" % e)
			
		entities = defaultdict(list)
		if self.config['perf_collection_type'] != "otherperf":
			for host_moid in self.config['perf_target_hosts']:
				host_mor = ManagedObjectReference(value=host_moid, _type="HostSystem")
				update_entities_maybe('HostSystem')
				update_entities_maybe('VirtualMachine')
			self.logger.debug(self.dbg_info + "Updated entity lists: number of hosts: " +
							  "%d; number of VMs: %d" % (len(entities['HostSystem']), len(entities['VirtualMachine'])))
		else:
			update_entities_maybe('ResourcePool')
			update_entities_maybe('ClusterComputeResource')
			self.logger.debug(self.dbg_info + "Updated entity lists: number of rps: " + 
							  "%d; number of clusters: %d" % (len(entities['ResourcePool']), len(entities['ClusterComputeResource'])))
			
		return entities

	def _prepare_metrics_lists(self, entities, vc_id):
		"""Prepares and caches metric lists for this collector's entities.

		Metric lists are created to conform to the whitelist/blacklist specifications
		in the config.  Caching is done to ensure that for a given inventory set, 
		the metrics are only retrieved once.

		Returns: metrics as a dict of lists keyed by entity type."""
		inventory_hash = hash(frozenset([vc_id] + [hash(frozenset([y.value for y in vals])) for vals in entities.values()]))
		metrics = {}
		if self.domain not in self._metrics_cache:
			self._metrics_cache[self.domain] = MetricsCache(2000, 50)
		cache = self._metrics_cache[self.domain]  
		if inventory_hash in cache:
			metrics = cache[inventory_hash]
			self.logger.debug(self.dbg_info + "Got a list of metrics from cache")
		else:
			self.logger.debug(self.dbg_info + "Getting a NEW list of metrics")
			for entity_type in entities:
				if not entity_type in metrics:
					metrics[entity_type] = self.get_all_metrics(entities[entity_type])
			cache[inventory_hash] = metrics
		return metrics

	def _is_entity_blacklisted(self, e):
		return any(re.search(x, e) is not None for x in self.config['perf_entity_blacklist'])
		
	def _get_fqname(self, pc):
		return "_".join(['p', pc.rollupType, pc.groupInfo.key, pc.nameInfo.key, pc.unitInfo.key])
		
	def _aggregate_only(self, entity_type):
		return (not self.config[ENTITY_ABBREV[entity_type] + '_instance_blacklist'] 
				and not self.config[ENTITY_ABBREV[entity_type] + '_instance_whitelist'])


	def _query_refresh_rate(self, entity):
		pps = self.perfManager.queryPerfProviderSummary(entity)
		return pps.refreshRate
		
	def _get_ref_rate_for_entity(self, entity):
		"""Gets the refresh rate for the metrics.  
		
		This value is assumed to be fixed for a given entity type on a given
		collection run.  For instance, if collecting ResourcePool data from
		managed hosts the 'current'/20-sec refresh rate is not available and we have
		to use the 300-second summary roll-up.  However, ResourcePools collected
		from unmanaged hosts only have the 20-second data and NO 300-second summary.
		We never deal with managed and unmanaged hosts in the same collection run,
		so we just cache the highest available refresh rate when we first see 
		an entity of a given type and use that value for the duration of collection."""
		def get_ref_rate():
			pps = self.perfManager.queryPerfProviderSummary(entity)
			if pps.currentSupported:
				rr = pps.refreshRate
			elif pps.summarySupported:
				rr = min([x.samplingPeriod for x in self.perfManager.getHistoricalInterval().PerfInterval])
			else:
				raise Exception("Unable to determine perf collection rate")
			self._ref_rate_cache[entity._type] = rr
			return rr
				
		if entity._type in self._ref_rate_cache:
			return self._ref_rate_cache[entity._type]
		else:
			return get_ref_rate()

	def _query_perf(self, entities, pmids, start_time=None, end_time=None, max_samples=None):
		"""Construct PerfQuerySpec and invoke queryPerf vipython method on the performance manager object.
		
		entities (list of MORs)
		start/end_time are optional; they form a (start, end] half-closed interval
		Returns: list of PerfEntityMetricCSV
		
		Long lists of entities require several calls to queryPerf
		"""
		max_api_call = 0
		matching_metrics_limit = 64
		entities_len = len(entities)
		pmids_len = len(pmids)
		total_call = float(entities_len * pmids_len)
		if total_call < 64:
			NUM_CLUSTER_SINGLE_COLLECTION = 1
		else:
			max_api_call = total_call / matching_metrics_limit
			if not max_api_call is 0 :
				NUM_CLUSTER_SINGLE_COLLECTION = int(entities_len / max_api_call)
		if not entities or not pmids:
			self.logger.debug(self.dbg_info + "Skipping collection due to empty lists of entities and/or metrics")
			return []
		num_collections = math.ceil(len(entities) / float(NUM_CLUSTER_SINGLE_COLLECTION))
		chunk_size = int(math.ceil(len(entities) / num_collections))
		assert chunk_size >= 0 and chunk_size <= len(entities)
		res = []
		try:
			for i in range(int(num_collections)):
				# python is OK with slice indexes being longer than max list index
				chunk = entities[i * chunk_size : (i + 1) * chunk_size]
				qspecs = [Connection.vim25client.new('PerfQuerySpec', entity=x, metricId=pmids, format= self.config.get('perf_format_type', 'csv'), intervalId=self._get_ref_rate_for_entity(x), 
												startTime=start_time, endTime=end_time) for x in chunk]
				res.extend(self.perfManager.queryPerf(qspecs))
			self.logger.debug(self.dbg_info + "Collected data: collection_type={coll}, entity_type={type} first_entity={first_ent} "
							  "len_in={num_ent} len_out={len_res} start_time={s} "
							  "end_time={e}".format(coll=self.config['perf_collection_type'], type=entities[0]._type, first_ent=entities[0].value,
													num_ent=len(entities), len_res=len(res), s=start_time, e=end_time))
		except Exception as e:
			self.logger.error("Max allowed metrics size of 64 has been exceeded for ClusterComputeResource.")
			raise
		return res

	def _find_vms_for_host(self, host):
		"""Constructs a list of powered-on VMs given a host MOR; returns a list of VM MORs"""
		# Get vm list
		hierarchy_collector = inventory.CreateHierarchyCollector(targetConfigObject='PerfInventory', oneTime=True)[1]
		gen_collect_propex = hierarchy_collector.collectPropertiesEx(hierarchy_collector.fSpecList)
		vms_list = []
		for vms in gen_collect_propex:
			if vms is None:
				break
			else:
				for x in vms:
					if( hasattr(x.propSet[1].val, "value") and x.propSet[1].val.value == host):
						if( hasattr(x.propSet[2], "val") and x.propSet[2].val == "poweredOn"):
							vms_list.append(x.obj)
		self.logger.debug("Powered on VMs list=%s host=%s" , vms_list, host)
		inventory.DestroyHierarchyCollector(hierarchy_collector)
		del gen_collect_propex, hierarchy_collector
		return vms_list

	def _find_rps(self):
		hierarchy_collector = inventory.CreateHierarchyCollector(targetConfigObject='PerfResourcePoolList', oneTime=True)[1]
		gen_collect_propex = hierarchy_collector.collectPropertiesEx(hierarchy_collector.fSpecList)
		rps_list = []
		for rps in gen_collect_propex:
			if rps is None:
				break
			else:
				for x in rps:
					rps_list.append(x.obj)
		inventory.DestroyHierarchyCollector(hierarchy_collector)
		del gen_collect_propex, hierarchy_collector
		return rps_list
	
	def _find_clusters(self): 
		hierarchy_collector = inventory.CreateHierarchyCollector(targetConfigObject='PerfClusterComputeResourceList', oneTime=True)[1]
		gen_collect_propex = hierarchy_collector.collectPropertiesEx(hierarchy_collector.fSpecList)
		ccrs_list = []
		for ccrs in gen_collect_propex:
			if ccrs is None:
				break
			else:
				for x in ccrs:
					ccrs_list.append(x.obj)
		inventory.DestroyHierarchyCollector(hierarchy_collector)
		del gen_collect_propex, hierarchy_collector
		return ccrs_list

	def _create_mo(self, moid, _type):
		return Connection.vim25client.createExactManagedObject(mor=ManagedObjectReference(value=moid, _type=_type))

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

	def get_all_metrics(self, entities, mode='regex'):
		"""Gets performance metrics for a list of entities provided a given refresh rate and 
		relevant whitelists and blacklists.
		
		entities (list of MORs) - these have to be of the SAME TYPE (e.g. all VirtualMachine)
		
		Keyword args:
		mode: MetricsListMatcher mode parameter ["regex" | "verbatim"]

		Returns:
		list of PerfMetricId's

		Implementation notes:
		Empirically, at 20-second collection intervals, two entities of the same type share counterIds 
		this is NOT necessarily true for other collection intervals.   However, different entities
		of the same type will NOT necessarily share instance ids. Thus, available PerfMetricIds, in general, 
		differ from entity to entity.  When getting intance-level data, we then must either specify ALL 
		available instance Ids in the perfMetricIds OR leave the instance string as "*"; this is
		more efficient and is the current approach.
		"""
		def aggregate_instances_maybe(pmids, style): 
			inst_field = {"glob": "*", "aggregate": ""}
			if style not in inst_field:
				raise ValueError("Style must be in".format(inst_field.keys()))
			res = []
			aggregate_cids = set()
			for mid in pmids:
				if mid.counterId not in aggregate_cids:
					aggregate_cids.add(mid.counterId)
					mid.instance = inst_field[style]
					res.append(mid)
			return res
		
		m = []
		if not entities: return m
		self.logger.debug(self.dbg_info + "Querying and pruning available metrics")
		# If all the metrics are identical, we can build the list of metrics 
		# based on the first entity in the list only.  However, this assumption turns out to be wrong
		# in general, e.g. if we have empty clusters, they do not have all of the relevant metrics
		# (in particular, they are missing the clusterServices metrics)
		entity = entities[0]
		refresh_rate = self._get_ref_rate_for_entity(entity)
		all_metrics = []
		all_metrics_d = {}
		d_key = lambda m: str(m.counterId) + str(m.instance)
		if entity._type in ALL_METRICS_FROM_ALL_ENTITIES_TYPES:
			for e in entities:
				for m in self.perfManager.queryAvailablePerfMetric(e, intervalId=refresh_rate):
					if d_key(m) not in all_metrics_d: all_metrics_d[d_key(m)] = m
		else:
			# Check Perf Metric for 5 instance to avoid if some bad VM or Host has limited perfConunter
			# See SOLNVMW-3358 for more information
			for e in random.sample(entities, min(len(entities), 5)):
				for m in self.perfManager.queryAvailablePerfMetric(e, intervalId=refresh_rate):
					if d_key(m) not in all_metrics_d: all_metrics_d[d_key(m)] = m
		all_metrics = all_metrics_d.values()
		counter_matcher = MetricsListMatcher(self.config[ENTITY_ABBREV[entity._type] + '_metric_whitelist'],
											 self.config[ENTITY_ABBREV[entity._type] + '_metric_blacklist'], mode)
		instance_matcher = MetricsListMatcher(self.config[ENTITY_ABBREV[entity._type] + '_instance_whitelist'],
											  self.config[ENTITY_ABBREV[entity._type] + '_instance_blacklist'], mode)
		
		pmid_to_fqname = lambda pmid: self.pcs_fqname_by_key[pmid.counterId]
		# Filtering logic: first prune the list of metrics to conform to the white/blacklists
		# Then match against the instance white/blacklists as follows: 
		# - if a metric conforms to the instance w/blists, it is included in the collection;
		#   but we must uniquify by counterIds and set instance attributes to "*"
		# - if a metric DOES NOT conform to the instance w/blists, we only care about the aggregated
		#   metric for that particular counterId.  Thus, we want to get the "rejected" list for
		#   instance-level collection, set all imstance attributes to "" and uniquify by counterId attribute
		instance_level_metrics = counter_matcher.prune(all_metrics, pmid_to_fqname)
		if entity._type == "HostSystem": self.logger.debug(self.dbg_info + "Total number of metrics: {0}; pruned to all inst-level: {1}".format(len(all_metrics), len(instance_level_metrics)))
		if not self._aggregate_only(entity._type):
			instance_level_metrics, aggregated_metrics = instance_matcher.prune(instance_level_metrics, pmid_to_fqname, return_excluded=True)
			inst = aggregate_instances_maybe(instance_level_metrics, style='glob')
			agg = aggregate_instances_maybe(aggregated_metrics, style='aggregate')
			if entity._type == "HostSystem": self.logger.debug(self.dbg_info + "Final tally: %d inst-level and %d aggr" % (len(inst), len(agg)))
			self.logger.debug(self.dbg_info + "Done querying and pruning available metrics")
			return inst + agg
		else:
			if entity._type == "HostSystem": self.logger.debug(self.dbg_info + "Requesting all metrics as aggregations")
			self.logger.debug(self.dbg_info + "Done querying and pruning available metrics")
			return aggregate_instances_maybe(instance_level_metrics, style='aggregate')


	def get_metric_names(self, metrics):
		"""Get dict of lists of (full_metric_name, instance_name) tuples given the metrics[entity_type' dict"""
		pmid_to_fqname = lambda pmid: self.pcs_fqname_by_key[pmid.counterId]
		res = {}
		for entity_type in metrics:
				res[entity_type] = sorted([(pmid_to_fqname(x), x.instance) for x in metrics[entity_type]],
										  key=lambda x: [x[0].split('_')[i] for i in (1,2,0,3)])
		return res

	def group_perf_data(self, perfdata_array, format):
		"""Parses performance data and returns a nested dict which can be used
		for outputting data in table form. 
		
		Table keys are formed by the (timestamp, group, entity_type) tuples.
		For each table key, the entries include moid, counter instance, and a list of metrics;
		this information is stored in a nested dictionary."""
		res = {}
		for perfdata in perfdata_array: # entities
			if (format == 'csv' and perfdata.sampleInfoCSV is None) or (format == 'normal' and perfdata.sampleInfo is None): 
				self.logger.debug(self.dbg_info + "Missing sample info for entity={0} of type={1}, skipping record".format(
					perfdata.entity.value, perfdata.entity._type))
				continue
			timestamps = timestamps = self._process_timestamps(perfdata, format)
			for pmser in perfdata.value: # counters (group, instance, name)
				if format == 'csv':
					data_values = pmser.value.split(',')
				else:
					# normal format type has value in array format
					# Converting long to str format same as csv format
					data_values = [str(x) for x in pmser.value]
				pc = self.pcs_by_key[pmser.id.counterId]
				fqname = self.pcs_fqname_by_key[pmser.id.counterId]
				group = pc.groupInfo.key
				entity_name = perfdata.entity.value
				# instance value of None or "" means this is an aggregated metric
				inst = pmser.id.instance if pmser.id.instance else "aggregated"
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
		return res


	def output_results(self, grouped_data, output, host):
		"""Takes the output of group_perf_data and an output handler and 
		creates data tables."""
		
		def build_header(headers_list):
			return "%s"*7 % ("moid", SEP, "instance", SEP, "samp_int", SEP, SEP.join(headers_list))
				
		def build_line(entity, inst, samp_int, data, headers_list):
			def retrieve(name):
				# values labelled percent are actually in units of % * 100, so must convert
				div_by_100_tostr = lambda x: str(float(x) / 100) if x else ""
				val = data.get(name, "")
				return div_by_100_tostr(val) if (re.search("percent$", name) is not None) else val
				
			return "%s"*7 % (entity, SEP, inst, SEP, samp_int, SEP,
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

		buf = []
		unbroken = False
		mi_metadata = {}
		for key in grouped_data:
			ts, g, entity_type = key
			samp_int = str(self._ref_rate_cache[entity_type]) # get sampling interval
			mi_metadata = build_metadata(ts, host, g, entity_type)
			headers_list = list(grouped_data[key][1])
			cur_header = build_header(headers_list)
			buf = [ cur_header ]
			linecount = 0
			for entity in grouped_data[key][0]:
				for inst in grouped_data[key][0][entity]:
					buf.append(build_line(entity, inst, samp_int, grouped_data[key][0][entity][inst], headers_list))
					linecount += 1
					if linecount > HEADER_LIM:
						output.sendData('\n'.join(buf), unbroken=unbroken, **mi_metadata)
						if unbroken: output.sendDoneKey(**mi_metadata)
						buf = [ cur_header ]
						linecount = 0
			output.sendData('\n'.join(buf), unbroken=unbroken, **mi_metadata)
			if unbroken: output.sendDoneKey(**mi_metadata)

						
	def run_collection(self, start_time, end_time):
		"""Updates the vc, entity lists, metrics lists; iterates over entities
		by type, calling queryPerf.  Returns a concatenated array of data 
		returned by queryPerf (array entries correspond to entities).

		start_time (datetime) - earliest data timestamp, argument to the queryPerf vipython call
		end_time (datetime) - latest data timestamp, argument to the queryPerf vipython call

		(start, end] form a half-closed interval
		"""
		
		if end_time - start_time < datetime.timedelta(seconds=1):
			start_time = end_time - datetime.timedelta(seconds=1)
			
		perf_data = []
		vc_id = self._update_counters_cache()
		entities = self._update_entity_lists()
		metrics = self._prepare_metrics_lists(entities, vc_id)
		if 'ResourcePool' in metrics and len(metrics['ResourcePool']) > 0: 
			self.logger.warn(self.dbg_info + "Resource pool collection turned on; may cause performance degradation")

		for entity_type in entities:
			self.logger.debug(self.dbg_info + "calling QueryPerf on %s", entity_type)
			perf_data += self._query_perf(entities[entity_type], metrics[entity_type], start_time=start_time, end_time=end_time)
		self.logger.debug(self.dbg_info + "Done grabbing data from vc")
		return perf_data
		
	def collect_performance(self, start_time, end_time, output_handler, host=None):
		"""Kicks off the data collection: updates inventory, metric lists (if need be), queries the VC for data, and formats results.

		start_time (datetime) - earliest data timestamp, argument to the queryPerf vipython call
		end_time (datetime) - latest data timestamp, argument to the queryPerf vipython call
		output_handler - received from the invoking handler, used to direct the output
		host - name of the target collection VC (used primarily to set host field in the output manager)

		(start, end] form a half-closed interval
		"""
		# get format type (default 'csv')
		format_type = self.config.get('perf_format_type', 'csv')
		self._check_format_type(format_type)
		
		if host is None: host = self.vc_id
		self.output_results(self.group_perf_data(self.run_collection(start_time, end_time), format=format_type), output_handler, host)
		self.logger.debug(self.dbg_info + "Successfully collected perf data batch: type={0}".format(self.config['perf_collection_type']))

