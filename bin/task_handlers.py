# Copyright (C) 2005-2016 Splunk Inc. All Rights Reserved. 

#Core Python Imports
import sys
from datetime import datetime

# Append SA-Hydra/bin/pacakges to the Python path

from splunk.appserver.mrsparkle.lib.util import make_splunkhome_path
sys.path.append(make_splunkhome_path(['etc', 'apps', 'SA-Hydra', 'bin', 'packages']))

# Import TA-VMware collection code

import vim25.tasks
import vim25.utils
from vim25.connection import Connection
from ta_vmware.models import TAVMwareCacheStanza

import hydra

class BaseTaskHandler(hydra.HydraHandler):
	"""
	Things all task handlers need
	"""
	def _prepare_timestamps(self, *args):
		"""
		Input: varargs list of datetime objects (assumed UTC).
		Output: UTC datetime(s) corresponding to the server clock that are guaranteed to have
				correct tzinfo field. Outputs single object for a single input argument, a list 
				for multiple input arguments.
		"""
		results = vim25.utils.AddUtcTzinfo(vim25.utils.ConvertToServerTime(args, Connection.svcInstance, zone="UTC")) 
		return results[0] if len(results) == 1 else results
	cache_model = TAVMwareCacheStanza

class TaskHandler(BaseTaskHandler):
	"""
	Handler for running the Task collection 
	"""
	def run(self, session, config, create_time, last_time ):
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
			dest_index = config.get("taskevent_index", False)
			if not dest_index:
				dest_index = None
			#FIXME: last_version and mor and such need to be saved to be reused in future iterations
			start_time, end_time = self._prepare_timestamps(last_time, create_time)
			self.logger.debug("[TaskHandler] DEBUGTIME location=task_handlers.py start_time=%s end_time=%s", start_time, end_time)
			taskCollect = vim25.tasks.CollectTasks(startTime=start_time, endTime=end_time)
			self.logger.debug("[TaskHandler] Finished Collecting Tasks")
			#self.logger.debug(taskCollect)
			self.logger.debug("[TaskHandler] Processing Tasks")
			if taskCollect is None: taskCollect = []
			for task in taskCollect:
				#self.logger.debug(task)
				self.logger.debug("[TaskHandler] Flattening Task")
				flatTask = vim25.utils.FlattenSingleTaskEvent(task)
				self.logger.debug("[TaskHandler] Outputting Task")
				sourcename = "Username:" + (task.userName if hasattr(task, 'userName') and task.userName is not None else "N/A")
				# python does not support tzinfo in strftime('%s') so we need to actually calculate time offset in seconds from epoch.
				self.output.sendData(flatTask, host=session[0], sourcetype="vmware:tasks", 
					source=sourcename, time=str((task.queueTime.replace(tzinfo=None)-datetime(1970,1,1)).total_seconds()), index=dest_index)
			self.logger.debug("[TaskHandler] Finished Task Collection and Processing")
			return True
		except Exception as e:
			self.logger.exception(e)
			return False
