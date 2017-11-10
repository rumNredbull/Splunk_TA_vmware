# Copyright (C) 2005-2016 Splunk Inc. All Rights Reserved.

# Core Python Imports
import sys

# Append SA-Hydra/bin/pacakges to the Python path

from splunk.appserver.mrsparkle.lib.util import make_splunkhome_path
sys.path.append(make_splunkhome_path(['etc', 'apps', 'SA-Hydra', 'bin', 'packages']))

# Import TA-VMware collection code

from vim25.connection import Connection
import inventory_handlers
import performance_handlers
import task_handlers
import event_handlers

from hydra.hydra_worker import HydraWorker


class TAVMwareHydraWorker(HydraWorker):
	title = "TA-vmware Hydra Worker"
	description = "Worker to perform VMware vSphere collection tasks."
	handlers = {
				"hostvmperf" : performance_handlers.HostVMPerfHandler,
				"otherperf" : performance_handlers.OtherPerfHandler,
				"task" : task_handlers.TaskHandler,
				"event" : event_handlers.EventHandler,
				"hierarchyinv" : inventory_handlers.HierarchyInventoryHandler,
				"hostinv" : inventory_handlers.HostSystemInventoryHandler,
				"vminv" : inventory_handlers.VirtualMachineInventoryHandler,
				"clusterinv" : inventory_handlers.ClusterComputeResourceInventoryHandler,
				"datastoreinv" : inventory_handlers.DatastoreInventoryHandler,
				"rpinv" : inventory_handlers.ResourcePoolInventoryHandler
				}
	app = "Splunk_TA_vmware"
	
	def loginToTarget(self, target, user, password, realm=None):
		"""
		Normally here is where you'd log into a target, for this example we'll just log and return a dict
		args:
			target - the uri to the domain specific asset we need to log in to
			user - the user name stored in splunkd associated with that target
			password - the password stored in splunkd associated with that target
			realm - currently unused but supplied by framework
		RETURNS a dict containing the login information
		"""
		for retry_count in range(4):
			if Connection.update_connection(target, username=user, password=password):
				self.logger.debug("Successfully updated Connection to target=%s with username=%s", target, user)
				return target, Connection.session_key, Connection.cookie
			else:
				self.logger.error("Failed to login to target=%s with username=%s on retry_num=%s", target, user, retry_count)
		raise Exception("Could not login to target=%s with username=%s after num_retries=%s", target, user, retry_count)
	
	def isSessionValid(self, session):
		"""
		For our example case we will just check that it is not None
		args:
			session - the python object returned by loginToTarget to be tested
		
		RETURNS True if session is valid, False if it must be refreshed
		"""
		if session is None:
			return False
		elif type(session) is tuple:
			target, session_key, cookie = session
		else:
			raise TypeError("Invalid session type passed to isSessionValid, expected Tuple, received: {0}".format(type(session)))
		if Connection.update_connection(target, session_key=session_key, cookie=cookie):
			self.logger.debug("Successfully updated Connection to target=%s with session_key/cookie", target)
			return True
		else:
			self.logger.debug("Could not update Connection to target=%s with session_key/cookie", target)
			return False
		

if __name__ == '__main__':
	worker = TAVMwareHydraWorker()
	worker.execute()
	sys.exit(0)
