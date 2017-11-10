# Copyright (C) 2005-2016 Splunk Inc. All Rights Reserved.
#Core Python imports
import traceback

#TA-vmware imports
from vim25 import logger
from vim25.connection import Connection

class TaskCollector(Connection):
	def __init__(self):
		try:
			self.targetTaskManager = self.taskManager
			self.taskSpec = None
			self.taskCollector = None
		except Exception as e:
			logger.error("Error getting service instance taskManager")
			logger.exception(e)
			
	def buildTaskQuerySpec(self):
		''' Builds an empty TaskQuerySpec, all items are set to None but the TimeSpec.
		meant to be run before buildTimeSpec.
		'''
		self.taskSpec = Connection.vim25client.new('TaskFilterSpec', entity=None, userName=None, alarm=None, scheduledTask=None)
	
	def buildTimeSpec(self, startTime, stopTime):
		''' Takes 2 args, startTime and stopTime, this will update self.eventSpec with a new 
		TimeSpec with startTime and endTime being the bounds of the supplied arguments.
		Meant to be run AFTER buildTaskQuerySpec.
		'''
		self.taskSpec.time.beginTime = startTime
		self.taskSpec.time.endTime = stopTime
		self.taskSpec.time.timeType.value = "queuedTime"
		
	def buildTaskCollector(self):
		try:
			if self.taskCollector:
				logger.error("Collector already exists")
			else:
				self.taskCollector = self.targetTaskManager.createCollectorForTasks(self.taskSpec)
		except Exception as e:
			logger.exception("taskSpec does not exist, or there was an error during collector creation.")
			logger.exception(e)

	def destroyTaskCollector(self):
		try:
			self.taskCollector.destroyCollector()
			self.taskCollector = None
		except Exception as e:
			logger.exception("Problem trying to remove collector")
			logger.exception(e)
		
	def collectTasks(self):
		'''Preforms a full collection of the self.specList passed.  Will not retain any information
		or update status.  Should be ran after specs are created and before create collector.
		this method will destroy the collector after collection.
		'''
		try:
			taskList = []
			self.buildTaskCollector()
			if self.taskCollector:
				while True:
					tasks = self.taskCollector.readNextTasks(maxCount=100)
					if tasks == None or len(tasks) == 0:
						break
					taskList.extend(tasks)
					if len(tasks)<100:
						break
			else:
				logger.info("TaskCollector for target time range is empty.")
			return taskList
		except Exception as e:
			logger.exception(e)
		finally:
			self.destroyTaskCollector()
	
# End of Class Definitions, starting collection functions.

def CollectTasks(startTime=None, endTime=None):
	''' Collects Tasks for the specified start and end times.
	returns a list of events in key order.
	'''
	try:
		taskListCollector = TaskCollector()
		taskListCollector.buildTaskQuerySpec()
		taskListCollector.buildTimeSpec(startTime, endTime)
		taskList = taskListCollector.collectTasks()
		return taskList
		
	except Exception as e:
		logger.error("error in collect tasks")
		logger.exception(e)
		logger.exception(traceback.print_exc())
