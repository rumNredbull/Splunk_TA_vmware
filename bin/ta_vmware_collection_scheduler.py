# Copyright (C) 2005-2016 Splunk Inc. All Rights Reserved.
# Core Python Imports
import sys
import re

from splunk.entity import controlEntity

# Append SA-Hydra/bin/pacakges to the Python path

from splunk.appserver.mrsparkle.lib.util import make_splunkhome_path
sys.path.append(make_splunkhome_path(['etc', 'apps', 'SA-Hydra', 'bin', 'packages']))

# Import TA-VMware collection code

from ta_vmware.models import TAVMwareCollectionStanza
import ta_vmware.simple_vsphere_utils as vsu

# Import from SA-Hydra

from hydra.hydra_scheduler import HydraScheduler, HydraCollectionManifest, HydraConfigToken
from hydra.models import SplunkStoredCredential

class TAVMwareScheduler(HydraScheduler):
	"""
	TA-VMware implementation of the HydraScheduler. Breaks up collection conf and 
	distributes it to all worker nodes.
	Significant overloads:
		establishCollectionManifest - custom break up of perf task by hosts in the vc
	"""
	title = "TA-VMware Collection Scheduler"
	description = "Breaks up the TA-VMware collection into config tokens and distributes jobs to all worker nodes. Should only have 1 of these active at a time."
	collection_model = TAVMwareCollectionStanza
	app = "Splunk_TA_vmware"
	collection_conf_name = "ta_vmware_collection.conf"
	worker_input_name = "ta_vmware_collection_worker"
	
	def getPassword(self, realm, user):
		"""
		This method pulls the clear password from storage/passwords for a 
		particular realm and user. This wraps the util method for logging purposes.
		args:
			realm - the realm associated with the stored credential
			user - the user name associated with the stored credential
		
		RETURNS the clear string of the password, None if not found
		"""
		#note we are relying on splunk's internal automagical session_key storage
		password = SplunkStoredCredential.get_password(realm, user, app=self.app, host_path=self.local_server_uri, session_key=self.local_session_key)
		if password is None:
			self.logger.warning("Could not find a stored credential for realm={0} and user={1}, returning None".format(realm, user))
			return None
		else:
			return password
	
	def establishCollectionManifest(self, calculate_auto_offset = False, total_heads = 0):
		"""
		Get the information from the collection conf then break it up into 
		atomic tasks and place them in the collection manifest
		
		return HydraCollectionManifest with entire contents of collect conf file
		"""
		#Bounce the hierarchy agent
		input_uri = self.local_server_uri.rstrip("/") + '/servicesNS/nobody/Splunk_TA_vmware/data/inputs/script/%24SPLUNK_HOME%252Fetc%252Fapps%252FSplunk_TA_vmware%252Fbin%252Fta_vmware_hierarchy_agent.py/'
		controlEntity('disable', input_uri + "disable", sessionKey=self.local_session_key)
		controlEntity('enable', input_uri + "enable", sessionKey=self.local_session_key)
		
		#Get collection conf information
		collects = self.collection_model.all(host_path=self.local_server_uri, sessionKey=self.local_session_key)
		collects._owner = "nobody"
		collects = collects.filter_by_app(self.app)
		metadata_dict = {}
		token_list = []
		for collect in collects:
			self.logger.debug("Processing collection stanza={0}".format(collect.name))
			if not collect.credential_validation:
				self.logger.error("collection stanza=%s rejected due to failed credential validation", collect.name)
				continue
			config = {}
			username = collect.username
			for field in collect.model_fields:
				#forgive me this but models don't implement a get item function so we have to do this
				config[field] = getattr(collect, field)
			self.logger.info("parsed collection stanza={0} into a config={1}".format(collect.name, str(config)))
			metadata_id = "metadata_" + collect.name
			metadata_dict[metadata_id] = config
			for target in collect.target:
				for task in collect.task:
					special = {}
					if task == "hostvmperf":
						#if vcenter, we need to break up the task by the number of hosts
						if collect.target_type == "vc":
							#Set up the connection
							password = self.getPassword(target, username)
							try:
								vss = vsu.vSphereService(target, username, password)
								if (collect.managed_host_blacklist is not None) and (collect.managed_host_blacklist != "None"):
									black_re_search = re.compile(collect.managed_host_blacklist, flags=re.S).search
								else:
									#fake re search method, always doesn't match
									black_re_search = lambda s: None
								if (collect.managed_host_whitelist is not None) and (collect.managed_host_whitelist != "None"):
									white_re_search = re.compile(collect.managed_host_whitelist, flags=re.S).search
								else:
									#fake re search method, always matches (sorta, really just always returns true instead of None match object but whatevs)
									white_re_search = lambda s: True
								#Pull the host list from the vc, note this does mean that adding/removing hosts from a vc implies a
								#required restart of the collector, or at least a conf reread. 
								for host in vss.get_host_list():
									host_name = host["name"]
									if black_re_search(host_name) or (white_re_search(host_name) is None):
										self.logger.debug("ignoring host=%s while parsing vc=%s into host specific task due to managed host whitelist/blacklist", host_name, target)
									else:
										special = {}
										special["perf_target_hosts"] = [host["moid"]]
										special["perf_collection_type"] = task
										self.logger.debug("parsing vc=%s task into host specific task for perf_target_hosts=%s", target, special["perf_target_hosts"])
										token_list.append(HydraConfigToken(target, username, task, metadata_id, self.logger, metadata=config, special=special))
								#logout
								if(vss.logout()) :
									self.logger.debug("User={0} successfully logout from {1}".format(username, target))
								else :
									self.logger.warn("User={0} failed to logout from {1}".format(username, target))
							except vsu.ConnectionFailure as e:
								self.logger.error("Could not connect to target=%s, will not assign hostvmperf config token, other config tokens may be assigned and fail", target)
								self.logger.exception(e)
								collect.credential_validation = False
								if not collect.passive_save():
									self.logger.error("Failed to save collection stanza=%s as failing on credential validation", str(collect))
							except vsu.LoginFailure as e:
								self.logger.error("Could connect but could not login to target=%s with username=%s, will not assign hostvmperf config token, other config tokens may be assigned and fail", target, username)
								self.logger.exception(e)
								collect.credential_validation = False
								if not collect.passive_save():
									self.logger.error("Failed to save collection stanza=%s as failing on credential validation", str(collect))
						elif collect.target_type == "unmanaged":
							special["perf_target_hosts"] = ["ha-host"]
							special["perf_collection_type"] = task
							self.logger.debug("parsing unmanaged=%s task into single hostvmperf task with perf_target_hosts=%s", target, special["perf_target_hosts"])
							token_list.append(HydraConfigToken(target, username, task, metadata_id, self.logger, metadata=config, special=special))
						else:
							special["perf_target_hosts"] = []
							special["perf_collection_type"] = task
							self.logger.debug("parsing target_type unknown=%s task into single hostvmperf task with perf_target_hosts=%s", target, special["perf_target_hosts"])
							token_list.append(HydraConfigToken(target, username, task, metadata_id, self.logger, metadata=config, special=special))
					elif task == "otherperf":
						special["perf_target_hosts"] = []
						special["perf_collection_type"] = task
						token_list.append(HydraConfigToken(target, username, task, metadata_id, self.logger, metadata=config, special=special))
					else:
						token_list.append(HydraConfigToken(target, username, task, metadata_id, self.logger, metadata=config, special={}))
		self.logger.debug("Establishing collection manifest with token list: {0}".format(str(token_list)))
		
		# calculate auto offset
		if calculate_auto_offset:
			self.getConfigTokenOffsets(token_list, total_heads, schedular_execution_time=15, head_dist_bucketsize=2)

		#Distribute Metadata to all nodes
		self.metadata_dict = metadata_dict
		return HydraCollectionManifest(self.logger, metadata_dict, token_list, self.app)

if __name__ == '__main__':
	scheduler = TAVMwareScheduler()
	scheduler.execute()
	sys.exit(0)
