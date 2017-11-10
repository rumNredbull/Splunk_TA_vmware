# Copyright (C) 2005-2017 Splunk Inc. All Rights Reserved.
import inspect
import suds
import json
import datetime
import re


isviminstance = lambda obj, name: isinstance(obj, suds.sudsobject.Object) and obj.__class__.__name__==name

# This fixes a bug from suds that it returns the result only based on xml elements
# we need to convert it into vim25 object


def ConvertObjectToDict(tempObject):
	''' Returns a dictionary with all the keys as attributes of the 
	object.
	'''
	tempDict = {}
	for name in dir(tempObject):
		if not name.startswith('__'):
			value = getattr(tempObject, name)
			value = CheckAttribute(value)
			tempDict[name] = value
	return tempDict
	
def FlattenTaskEventData(taskSet):
	''' Takes a taskSet or eventSet object and formats the output for splunk.  
	Returns a list of json objects.
	'''
	tempCombinedData = []
	for objectItem in taskSet:
		tempFullObject=dict(CheckAttribute(objectItem))
		tempCombinedData.append(json.dumps(tempFullObject))
	return tempCombinedData

def FlattenSingleTaskEvent(task):
	tempFullTask=dict(CheckAttribute(task))
	flatTask=json.dumps(tempFullTask)
	return flatTask

def ConvertDotStringToDict(dotstring, value):
	''' Will take an input that has periods in the name,
	explode the periods into a list, then create an n-depth dictionary
	with the last item being set to value
	'''
	lst = dotstring.split(".")
	expanded_list={}
	current_level=expanded_list
	for item in lst:
		if item not in current_level:
			current_level[item] = {}
		previous_level=current_level
		current_level = current_level[item]
	previous_level[lst[-1]] = value
	return expanded_list
	
def CombineDicts(oldDict, newDict):
	targetDict = defaultdict(oldDict)
	for key, value in newDict.items():
		targetDict[key].update(value)
	return newDict
	
def Folderize(input):
    output = None
    if isinstance(input, list):
        is_complex = False
        output = []
        merged_dicts = {}
        for item in input:
            if isinstance(item, dict):
                for k, v in item.items():
                    if hasattr(v, '__iter__'):
                        is_complex = True
                    curr = merged_dicts.setdefault(k, [])
                    curr.append(v)
            else:
            	if item == None:
            		pass
            	else:
                	output.append(item)
        if merged_dicts and is_complex:
            # recurse for the dict contents
            output.append(Folderize(merged_dicts))
        else:
            # No complex dict objects were found.
            output = input
        if len(output) == 1:
            # flatten one level
            output = output[0]
    elif isinstance(input, dict):
        # recurse for the dict contents
        output = {k: Folderize(input[k]) for k in input}
    else:
        output = input
    return output
	
def ProcessInventoryHighVersionFix(splitPeriodDict):
	''' Based on newer revesions of inventory data, occasionally we'll get data bake 
	in a host['host-10'] format for a key instead of a dict of the moid and type.  This 
	function will split on those names and return back the data identical to changeVersion=1
	'''
	if len(splitPeriodDict) == 1:
		newDict={}
		mor=None
		key=splitPeriodDict.keys()[0]
		value=splitPeriodDict.values()[0]
		matchedRegEx=re.search('\w+\["(\w+-\d+)"\]', key)
		if matchedRegEx:
			mor=matchedRegEx.group(1)
		if mor:
			#first adjust any host mor blocks into the proper locations:
			if key.startswith('host['):
				newDict['host'] = {}
				#Fix Datastore host.mountInfo
				if 'mountInfo' in value:
					#newDict['host']
					newDict['host']['DatastoreHostMount'] = { 'key':{ 'moid':mor , 'type':'HostSystem'}, 'mountInfo':value['mountInfo']}
			elif key.startswith('vm['):
				newDict['vm'] = { 'ManagedObjectReference' : { 'moid':mor, 'type':'VirtualMachine' }}
		else:
			newDict=splitPeriodDict
		return newDict
	else:
		return splitPeriodDict
	
def CheckIfObject(tempObject):
	if type(tempObject).__name__ == 'instance':
		return True
	else:
		return False

def CheckIfPropertyObject(tempObject):
	if hasattr(tempObject, 'name') and hasattr(tempObject, 'val'):
		return True
	else:
		return False
	
def CheckIfAnyKey(tempObject):
	if (tempObject.__class__.__name__) == 'KeyAnyValue':
		return True
	else:
		return False
	
def CheckIfMOR(tempObject):
	if hasattr(tempObject, 'value') and hasattr(tempObject, '_type'):
		return True
	else:
		return False

def CheckIfOp(tempObject):
	if hasattr(tempObject, 'name') and hasattr(tempObject, 'op') and not hasattr(tempObject, 'val'):
		return True
	else:
		return False
	
def CheckAttribute(tempAttribute):
	''' Checks the value of the attribute for a type,
	then returns the proper output of the attribute
	'''
	if CheckIfMOR(tempAttribute):
		return {"moid":str(tempAttribute.value), "type":str(tempAttribute._type)}
	elif CheckIfAnyKey(tempAttribute):
		value = CheckAttribute(tempAttribute.value)
		return {tempAttribute.key : value}
	elif CheckIfPropertyObject(tempAttribute):
		value = CheckAttribute(tempAttribute.val)
		itemTarget = {}
		if not "." in tempAttribute.name:
			itemTarget[tempAttribute.name] = value
		else:
			itemTarget = ConvertDotStringToDict(tempAttribute.name, value)
		itemTarget = ProcessInventoryHighVersionFix(itemTarget)
		return itemTarget
	elif CheckIfOp(tempAttribute):
		return None
	elif CheckIfObject(tempAttribute):
		return ConvertObjectToDict(tempAttribute)
	elif type(tempAttribute) == list:
		tempList = []
		for attribute in tempAttribute:
			tempList.append(CheckAttribute(attribute))
		return tempList
	elif type(tempAttribute) == dict:
		return tempAttribute
	else:
		return str(tempAttribute)

def ConvertIsoUtcDate(d, format_string="%Y-%m-%dT%H:%M:%SZ"):
	'''Grabs date represented as e.g.: 2013-04-01T23:06:00Z (or other formats given by the
	format_string argument) and generates a datetime object in the local timezone, with the 
	offset between local and utc computed via datetime.datetime.utcnow() - datetime.datetime.now()'''
	offset = datetime.datetime.utcnow() - datetime.datetime.now()
	return datetime.datetime.strptime(d, format_string) - offset
			
def ConvertToServerTime(times, svc_instance, zone="UTC"):
	'''Given a list of UTC or local datetime objects that reference the local machine's clock,
	query the server for its current time and compute the difference between the 
	server clock and the local clock. Return the list of datetime objects corresponding
	to the input list but referencing the server clock.'''
	if zone == "UTC":
		offset_t = svc_instance.currentTime().replace(tzinfo=None) - datetime.datetime.utcnow()
	elif zone == "local":
		offset_t = svc_instance.currentTime().replace(tzinfo=None) - datetime.datetime.now()
	else:
		raise ValueError("zone has to be 'local' or 'UTC'")
	return [x + offset_t for x in times]

def ConvertFromUtc(time):
	offset = datetime.datetime.utcnow() - datetime.datetime.now()
	offset = datetime.timedelta(hours=round(offset.seconds / float(3600)))
	return time - offset
	
def AddUtcTzinfo(times):
	'''
	Given a list of datetime objects, add UTC timezone info to them and returns the list of modified
	objects.  Does not modify objects if they already have tzinfo.
	Note that the argument and return value are always lists.
	'''
	res = []
	for a in times:
		if isinstance(a,datetime.datetime) and a.tzinfo is None:
			res.append(a.replace(tzinfo=suds.sax.date.UtcTimezone()))
	return res

	
