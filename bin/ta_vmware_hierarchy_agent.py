#Copyright (C) 2005-2017 Splunk Inc. All Rights Reserved.

# Core Python imports

import sys
import math
from xml.dom import minidom

# Splunk imports

from splunk import mergeHostPath, util
from splunk.auth import getSessionKey
from splunk.appserver.mrsparkle.lib.util import make_splunkhome_path

# Append SA-Hydra/bin/packages to the Python path

from splunk.appserver.mrsparkle.lib.util import make_splunkhome_path
sys.path.append(make_splunkhome_path(['etc', 'apps', 'SA-Hydra', 'bin', 'packages']))

# SA-Hydra imports

from hydra import setupLogger
from hydra.hydra_common import HydraGatewayAdapter
from hydra.models import HydraNodeStanza, SplunkStoredCredential

# TA-vmware imports

import ta_vmware.simple_vsphere_utils as vsu
from ta_vmware.models import TAVMwareCollectionStanza

#Setup Logger
logger = setupLogger(log_format='%(asctime)s %(levelname)s [TAVMwareHierarchyAgent] %(message)s', log_name="ta_vmware_hierarchy_agent.log", logger_name="ta_vmware_hierarchy_agent")

# It can be put in ta_vmware_collection.conf file but DCN does not need these values, hence we hard coded here
MAX_HOSTS_IN_VC =  1000
MAX_POWER_ON_VMS_IN_VC = 10000
MAX_REGISTER_VMS_IN_VC = 15000
MAX_HOST_IN_CLUSTER = 32
MAX_VMS_IN_HOST = 512
MAX_VMS_IN_CLUSTER = 4000

def get_node_adapters(local_host_path, local_session_key):
	"""
	Given the local session key return an iterable of HydraGatewayAdapters to 
	all Hydra Nodes in the TA Vmware app context for which we have valid access. 
	Any failed logins will be logged but otherwise will not impact data collection. 
	
	@type local_host_path: str
	@param local_host_path: path to the local splunkd mgmt interface
	@type local_session_key: str
	@param local_session_key: valid splunk session key to the local splunkd instance
	
	@rtype: list
	@return: iterable of authenticated HydraGatewayAdapters to all DCN's
	"""
	#Establish node list
	node_stanzas = HydraNodeStanza.all(host_path=local_host_path, sessionKey=local_session_key)
	node_stanzas._owner = "nobody" #self.asset_owner
	node_stanzas = node_stanzas.filter_by_app("Splunk_TA_vmware")

	#Iterate on all nodes, checking if alive and sorting appropriately
	adapter_list = []
	for node_stanza in node_stanzas:
		password = SplunkStoredCredential.get_password(node_stanza.name, node_stanza.user, "Splunk_TA_vmware", session_key=local_session_key, host_path=local_host_path)
		if isinstance(node_stanza.gateway_port, int):
			gateway_port = node_stanza.gateway_port
		else:
			gateway_port = 8008
		gateway_uri = node_stanza.name.rstrip("/0123456789") + str(gateway_port)
		
		
		try:
			node_session_key = getSessionKey(node_stanza.user, password, hostPath=node_stanza.name)
			adapter_list.append(HydraGatewayAdapter(node_stanza.name, node_session_key, gateway_uri))
		except Exception as e:
			logger.exception("[get_node_adapters] failed to establish gateway adapter for node=%s due to error=%s", node_stanza.name, str(e))
	
	return adapter_list

def get_virtual_centers(local_host_path, local_session_key):
	"""
	Given the local session key return an iterable of tuples of vsphere address, 
	service user name, and password to the user. 
	
	@type local_host_path: str
	@param local_host_path: path to the local splunkd mgmt interface
	@type local_session_key: str
	@param local_session_key: valid splunk session key to the local splunkd instance
	
	@rtype: list
	@return: iterable of tuples of the form (<vspehere address>, <username>, <password>)
	"""
	#Establish node list
	collection_stanzas = TAVMwareCollectionStanza.all(host_path=local_host_path, sessionKey=local_session_key)
	collection_stanzas._owner = "nobody" #self.asset_owner
	collection_stanzas = collection_stanzas.filter_by_app("Splunk_TA_vmware")

	#Iterate on all nodes, checking if alive and sorting appropriately
	vc_list = []
	for collection_stanza in collection_stanzas:
		## Used autoeventgen property if fake auto event is generated to large scale (maximize vc limit)
		if collection_stanza.autoeventgen is None:
			isautoeventgen = False
		else:
			isautoeventgen = collection_stanza.autoeventgen
		if collection_stanza.realm is None:
			for target in collection_stanza.target:
				password = SplunkStoredCredential.get_password(target, collection_stanza.username, "Splunk_TA_vmware", session_key=local_session_key, host_path=local_host_path)
				vc_list.append((target, collection_stanza.username, password, isautoeventgen))
		else:
			password = SplunkStoredCredential.get_password(collection_stanza.realm, collection_stanza.username, "Splunk_TA_vmware", session_key=local_session_key, host_path=local_host_path)
			for target in collection_stanza.target:
				vc_list.append((target, collection_stanza.username, password, isautoeventgen))
	
	return vc_list
		
	

def collect_vms_by_host(target, user, password):
	"""
	Given a virtual center and the user and password to access it return a 
	data structure of the form { <host moid> : <vm moid>[]}
	
	@type target: str
	@param target: valid vsphere address
	@type user: str
	@param user: valid user to that vsphere address
	@type password: str
	@param password: password for the passed user
	
	@rtype: dict
	@return: dict of host moid to iterable of vm moid
	"""
	
	vss = vsu.vSphereService(target, username=user, password=password)
	response = vss.get_obj_list([{'type':'VirtualMachine','all':'false', 'pathSet':'summary.runtime.powerState'}, 
								{'type':'VirtualMachine','all':'false', 'pathSet':'summary.runtime.host'}], 
							{'type':'Folder', 'moid':"group-d1"})
	vss.logout()
	resp_xml = minidom.parseString(response)
	vms_by_host = {}
	for returnval in resp_xml.getElementsByTagName("returnval"):
		#Get the MOR object, there will only ever be one
		obj =  returnval.getElementsByTagName('obj')[0]
		
		#Convert property sets into a dictionary
		propsets = returnval.getElementsByTagName('propSet')
		prop_dict = {}
		for propset in propsets:
			name = None
			val = None
			for node in propset.childNodes:
				if node.tagName == "name":
					name = node.firstChild.data
				elif node.tagName == "val":
					val = node.firstChild.data
			prop_dict[name] = val
		
		#Check on props and add to list if appropriate
		if prop_dict.get("summary.runtime.powerState", "") == "poweredOn":
			host = prop_dict.get("summary.runtime.host", "orphan")
			if vms_by_host.get(host, None) is None:
				vms_by_host[host] = []
			vms_list = vms_by_host[host]
			
			#Add vm moid to the list
			vms_list.append(str(obj.firstChild.data))
	
	return vms_by_host

def distribute_hierarchy_cache(nodes, target, vms_by_host, vcs_autogenerated_id_info):
	"""
	Distribute the given hierarchy dictionary to all nodes in the given set of 
	hydra gateway adapters
	
	@type nodes: list of HydraGatewayAdapter
	@param nodes: list of authenticated gateway adapters to DCN's
	@type target: str
	@param target: target virtual center value
	@type vms_by_host: dict of <host moid> -> list of <vm moid>
	@param vms_by_host: dictionary of parent moid to list of child moids to cache
	
	@rtype: None
	@return: None
	"""
	cache_items = []
	for host_moid, vms in vms_by_host.iteritems():
		cache_name = "perfhierarchy:" + target + ":" + host_moid
		cache_value = {host_moid: vms}
		cache_items.append((cache_name, cache_value))
	
	is_auto_ids_needed = False
	ids_cache_items = []
	if len(vcs_autogenerated_id_info) > 0:
		is_auto_ids_needed = True
	if is_auto_ids_needed:
		for vc, objs_info in vcs_autogenerated_id_info:
			name = "autogenertedid:" + vc
			value = objs_info
			ids_cache_items.append((name, value))
	
	for hga in nodes:
		try:
			hga.set_cache_batch(cache_items, expiration=14400)
			if is_auto_ids_needed:
				hga.set_cache_batch(ids_cache_items)
		except Exception as e:
			logger.exception("[distribute_hierarchy_cache] failed to set cache for target=%s for node=%s due to error=%s", target, hga.splunkd_uri, str(e))

def generate_moids(vc, existing_hosts_count, existing_vms_count):
	# create cluster
	cluster_index = 1
	can_generate_hosts = MAX_HOSTS_IN_VC - existing_hosts_count
	can_generate_vms = MAX_POWER_ON_VMS_IN_VC - existing_vms_count
	vms_per_host = math.ceil(float(can_generate_vms)/can_generate_hosts)
	vms_done = False
	hosts_done = False
	clusters = []
	while not (vms_done and hosts_done):
		cluster_id = "cluster-" + str(cluster_index) +"-" + vc.replace(".", "-")
		cluster_name ="cluster-name" + str(cluster_index) + vc.replace(".", "-")
		hosts = []
		host_index = 1
		while host_index <= MAX_HOST_IN_CLUSTER:
			if can_generate_hosts <= 0:
				hosts_done = True
				# Once host is done, vm has to be done as vms are added in hosts (avoid infinite loop)
				vms_done = True
				break
			host_id = "host-" + str(host_index) + "-cluster-" + str(cluster_index) + vc.replace(".", "-")
			host_name = "host-name-" + str(host_index) + "-cluster-name-" + str(cluster_index) + vc.replace(".", "-")
			vms = []
			vm_index = 1
			while vm_index <= vms_per_host:
				if can_generate_vms <= 0:
					vms_done = True
					break
				# vms limit in the cluster
				if host_index*vms_per_host+vm_index > MAX_VMS_IN_CLUSTER:
					break
				vm_id = "vm-"+str(vm_index)+"-host-" +str( host_index) + "-cluster-" + str(cluster_index) + vc.replace(".", "-")
				vm_name = "vm-name"+str(vm_index)+"-host-name-" + str(host_index) + "-cluster-name-" + str(cluster_index) + vc.replace(".", "-")
				vms.append({"moid": vm_id, "name" : vm_name, "type":"VirtualMachine"})
				vm_index = vm_index + 1
				can_generate_vms = can_generate_vms - 1
			hosts.append({"moid": host_id, "name" : host_name, "type":"HostSystem", "vms": vms})
			host_index = host_index + 1
			can_generate_hosts = can_generate_hosts - 1
		clusters.append({"moid": cluster_id, "name" : cluster_name, "type":"ClusterComputeResource", "hosts": hosts})
		cluster_index = cluster_index + 1
	return (vc, {"clusters": clusters, "existing_hosts_count" : existing_hosts_count, "existing_vms_count" : existing_vms_count})

if __name__ == "__main__":
	local_session_key = sys.stdin.readline().strip("\r\n")
	local_host_path = mergeHostPath()
	
	#Get Data Collection Nodes
	
	nodes = get_node_adapters(local_host_path, local_session_key)
	if len(nodes) == 0:
		logger.info("could not authenticate with any data collection nodes, exiting run of vmware hierarchy agent")
		sys.exit(0)
	
	#Get target Virtual Centers
	vcs = get_virtual_centers(local_host_path, local_session_key)
	if len(vcs) == 0:
		logger.info("could not find any configured virtual centers, exiting run of vmware hierarchy agent")
		sys.exit(0)
	# Capture vc and list existing hosts and vms count so it would be useful if we make
	vcs_autogenerated_id_info = []
	#Process and distribute virtual center hierarchy cache
	for target, username, password, isautogenerateid in vcs:
		vms_by_host = collect_vms_by_host(target, username, password)
		logger.debug("Successfully get hierarchy list for vc:%s", target)
		if isautogenerateid:
			# calculate hosts, vms count
			vms_count = 0
			hosts_count = 0
			for host_moid, vms in vms_by_host.iteritems():
				hosts_count = hosts_count + 1
				vms_count = vms_count + int(len(vms))
			logger.debug("Existing host count:%s, vms count:%s for vc:%s", hosts_count, vms_count, target)
			logger.debug("Generating random moid and name for large collection")
			ids = generate_moids(target, hosts_count, vms_count)
			logger.debug("Successfully generated ids for vc:%s", target)
			vcs_autogenerated_id_info.append(ids)
		# Distribute to the node
		distribute_hierarchy_cache(nodes, target, vms_by_host, vcs_autogenerated_id_info)
	sys.exit(0)

