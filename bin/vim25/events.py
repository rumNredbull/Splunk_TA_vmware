# Copyright (C) 2005-2016 Splunk Inc. All Rights Reserved.
#Core Python imports
import traceback

#TA-vmware imports
from vim25 import logger
from vim25.connection import Connection

class EventCollector(Connection):
	def __init__(self):
		try:
			self.targetEventManager = self.eventManager
			self.eventSpec = None
		except Exception as e:
			logger.error("Error getting service instance EventManager")
			logger.exception(e)
			
	def buildEventQuerySpec(self):
		''' Builds an empty EventQuerySpec, all items are set to None but the TimeSpec.
		meant to be run before buildTimeSpec.
		'''
		self.eventSpec = Connection.vim25client.new('EventFilterSpec', entity=None, userName=None, alarm=None, scheduledTask=None)
	
	def buildTimeSpec(self, startTime, stopTime):
		''' Takes 2 args, startTime and stopTime, this will update self.eventSpec with a new 
		TimeSpec with startTime and endTime being the bounds of the supplied arguments.
		Meant to be run AFTER buildEventQuerySpec.
		'''
		self.eventSpec.time.beginTime = startTime
		self.eventSpec.time.endTime = stopTime
		
	def collectEvents(self, eventSpec):
		'''Preforms a full collection of the specList passed.  Will not retain any information
		or update status.
		'''
		try:
			events = self.targetEventManager.queryEvents(eventSpec)
			return events
		except Exception as e:
			logger.exception(e)
	
# End of Class Definitions, starting collection functions.

def CollectEvents(startTime=None, endTime=None):
	''' Collects Events for the specified start and end times.
	returns a list of events in key order.
	'''
	try:
		Collector = EventCollector()
		Collector.buildEventQuerySpec()
		Collector.buildTimeSpec(startTime, endTime)
		events = Collector.collectEvents(Collector.eventSpec)
		return events
		
	except Exception as e:
		logger.error("error in collect events")
		logger.exception(e)
		logger.exception(traceback.print_exc())

	