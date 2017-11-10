# Copyright (C) 2005-2016 Splunk Inc. All Rights Reserved.
import sys
import os
import argparse
import getpass
import logging
import re
import json
import vim25

from urllib2 import HTTPError
from urlparse import urlparse
from ta_vmware.simple_vsphere_utils import vSphereService, LoginFailure, ConnectionFailure
from splunk.appserver.mrsparkle.lib.util import make_splunkhome_path

def run_single_instance(fn):
	def run_if_allowed(*args, **kwargs):
		if len(args) >= 3 and isinstance(args[2], dict) and ('print' in args[2] or 'print-detailed' in args[2]):
			logger.debug("Bypassing lock file creation")
			return fn(*args, **kwargs)
		elif len(args) >= 3:
			lockname = args[2].get("vcenter", None)
		else:
			lockname = None
		pidfile = acquire_lock(lockname) or ''
		try:
			return fn(*args, **kwargs)
		except Exception as e:
			print_errinfo_log_stmt(str(e))
			logger.exception(e)
			raise
		finally:
			if os.path.isfile(pidfile):
				os.remove(pidfile)
	return run_if_allowed

class ScriptAlreadyRunningException(Exception):
	def __init__(self, reason="Script is already running. "):
		self.args = reason
		self.reason = reason
	def __str__(self):
		return repr(self.reason)

######### Setup Logging function ##########
def setup_console_logging(logger, logLevel = logging.DEBUG):
	if logger is None:
		logger = logging.getLogger('vim25')
	console_handler = logging.StreamHandler()
	console_handler.setFormatter(logging.Formatter('%(asctime)s %(levelname)s | pid:%(process)d | %(filename)s:%(funcName)s:%(lineno)d | %(message)s'))
	console_handler.setLevel(logLevel)
	logger.addHandler(console_handler)

##########  Utility classes	   #########
class SysLogCommandLineParser:
	'''
		Class to handle sys log command line parsing
	'''
	def setup_parser(self):
		'''
			Setup command line parser and add the following arguments in it
			print help to see all options
		'''
		parser = argparse.ArgumentParser(description='Configure syslog on hosts')
		parser.add_argument('-d', help='To enable console debug logging', action='store_true')
		parser.add_argument('--vcenter', required=True, help='IP or URL of the vcenter')
		parser.add_argument('--username', required=True, help='vcenter username')
		parser.add_argument('--password', help='vcenter password')
		parser.add_argument('--print', help='Print firewall and syslog config settings for all hosts', action='store_true')
		parser.add_argument('--print-detailed', help='Print all available syslog config settings for all hosts', action='store_true')
		parser.add_argument('--reset', help='Rewrites current log config, this is useful to restart stopped syslog collection', action='store_true')
		parser.add_argument('--set-loghost', metavar='LOGHOST', help='Appends LOGHOST to the list of loghost servers')
		parser.add_argument('--target-hosts', metavar='ESX1.FOO.COM,ESX2.FOO.COM', help='Specific hosts to modify')
		parser.add_argument('--clear-existing', help='When used with --set-loghost, clears existing loghost list before appending LOGHOST',
							action='store_true')
		self.parser = parser

	def process_arguments(self):
		'''
			Parse command line and return a dict
		'''
		if len(sys.argv) == 1 or len(sys.argv) == 2 and "-d" in sys.argv:
			self.parser.print_help()
			raise Exception("Missing or invalid configuration options; exiting")
		args = self.parser.parse_args()
		if '--clear-existing' in sys.argv and not '--set-loghost' in sys.argv:
			self.parser.print_help()
			raise Exception('--clear-existing may only be used with --set-loghost')
		if '--clear-existing' in sys.argv and '--reset' in sys.argv:
			self.parser.print_help()
			raise Exception('--clear-existing can not be used with --reset')
		return args


class SyslogFirewallOptions(dict):
	def rule_string(self, x):
		return "port %(port)s (%(protocol)s) %(portType)s %(direction)s" % dict(x)
	@property
	def status(self): 
		return self.get('enabled','false')
	@property
	def rules(self): 
		return ",".join([self.rule_string(x) for x in self.get('rule',[])])
	@property
	def allowed_hosts(self):
		return ", ".join(str(x[0])+"="+str(x[1]) for x in self.get('allowedHosts',{}).iteritems())
	def __str__(self):
		return str((self.status, self.rules, self.allowed_hosts))


##########  Configurator class	   #########
class SysLogConfigurator:
	'''
		Class which is used to configure SysLog for each host
	'''
	HOST_SYSTEM_OBJ_TYPE = "HostSystem"
	HOST_SYSTEM_CONFIG_MANAGER = "configManager"
	HOST_FIREWALL_OBJ_TYPE = "HostFirewallSystem"
	HOST_FIREWALL_OBJ_NAME = "firewallInfo"

	def __init__(self, vc_conn, host_name, host_moid, host_product_version, host_product_name):
		self.conn = vc_conn
		self.host_moid = host_moid
		self.host_name = host_name
		self.host_product_version = host_product_version
		self.host_product_name = host_product_name
		self.host_firewall_moid = None
		self.host_advOption_moid = None
		self._set_host_required_moids()

	def _set_host_required_moids(self):
		'''
			Get firewall and esx advance option moids
		'''
		hmo_config = self.conn.retrieve_Properties(host_moid=self.host_moid, obj_type=self.HOST_SYSTEM_OBJ_TYPE, pathSet=self.HOST_SYSTEM_CONFIG_MANAGER)
		for val in hmo_config :
			if self.HOST_SYSTEM_CONFIG_MANAGER in val:
				for item in val[self.HOST_SYSTEM_CONFIG_MANAGER]:
					if 'OptionManager' in item :
						self.host_advOption_moid = item['OptionManager']
					# Note ESXi 4.X does not have firewall
					if not self._isEsxi4x() and 'HostFirewallSystem' in item:
						self.host_firewall_moid = item['HostFirewallSystem']

	def _isEsxi4x(self):
		'''
			Check if ESXi version is 4.x or not
		'''
		return self.host_product_name == "VMware ESXi" and self.host_product_version < "5.0.0"
	
	def _isEsx4x(self):
		'''
			Check if ESXi or ESX version is 4.x or not
		'''
		return self.host_product_version < "5.0.0"

	def gethost_fromuri(self, uri):
		'''
			Return host and port name from given uri, otherwise None
		'''
		host = ''
		port = ''
		if uri :
			regex = '(?:(tcp|udp).*://)?(?P<host>[^:/ ]+).?(?P<port>[0-9]*).*'
			regp = re.search(regex, uri)
			if regp :
				host = regp.group('host')
				port = regp.group('port')

		return (host, port)

	def _convert_list_dict(self, unformat_values):
		'''
			Customized function to get values in key, value format
		'''
		temp = {}
		for v in  unformat_values:
			for key, value in v.iteritems():
				temp[key] = value
		return temp

	def get_existing_syslog(self, output_format=None):
		'''
			Get existing Syslog.* properties, store in variable and return it
			On Failure this function will return empty dict
		'''
		syslog_properties = self._convert_list_dict(self.conn.query_options(self.host_advOption_moid, "Syslog."))
		return syslog_properties if output_format is None else reformat_output(syslog_properties, output_format)

		return self.syslog_existing_properties


	def get_firewall_options(self, output_format=None):
		'''
			Get ESX firewall settings
		'''
		result = None
		if self._isEsxi4x() :
			logger.info("ESXi 4.x does not support firewall options, skipping..")
		else:
			try:
				firewall_options = self.conn.retrieve_Properties(host_moid=self.host_firewall_moid, obj_type=self.HOST_FIREWALL_OBJ_TYPE, pathSet=self.HOST_FIREWALL_OBJ_NAME)
				if len(firewall_options) > 0 :
					# logger.debug("Raw firewall data :"+str(firewall_options))
					# this is very likely to be happen but handle it code if there is any case
					if len(firewall_options) > 1 :
						logger.warn("Found more than one firewall settings, considering only first value and ignoring others.")
					ruleset = firewall_options[0]['firewallInfo']['ruleset']
					sys_firewall_options = filter(lambda x : x['key'] == 'syslog', ruleset)[0]
					result = SyslogFirewallOptions(sys_firewall_options)
			except Exception as e :
				print_errinfo_log_stmt("Failed to get firewall options for host {0}".format(self.host_name))
				logger.exception(e)
				
			return result if output_format is None else reformat_output(result, output_format)

	def enable_firewall(self, firewall_key="syslog"):
		'''
			Set firewall rule for sys log
		'''
		if not self._isEsxi4x():
			is_firewall_set = self.conn.enable_ruleset(self.HOST_FIREWALL_OBJ_TYPE, self.host_firewall_moid, firewall_key)
			if is_firewall_set:
				logger.info("Successfully enabled firewall for host {0}".format(self.host_name))
			else :
				logger.info("Failed to enabled firewall for host {0}".format(self.host_name))

	def _get_syslog_loghost(self, sys_log_prop_dict):
		'''
			Return syslog host value from dict which holds all syslog properties
		'''
		if self._isEsx4x():
			sysloghost_val = sys_log_prop_dict['Syslog.Remote.Hostname'] + ":" + sys_log_prop_dict['Syslog.Remote.Port']
		else:
			sysloghost_val = sys_log_prop_dict['Syslog.global.logHost']
		return sysloghost_val

	def set_syslog(self, syslog_new_val, clear_existing=False, reset=False, provided_loghostlist = None):
		'''
			Set new remote sys log host name
			ARGS :
			 syslog_new_val : new sys log host value
			 clear_existing : Overwrite flag for existing value (Not Applicable for ESX/i 4.x)
			 reset : Need to reset the same value
			 provided_loghostlist : List of syslog uri from that uris one of uri is being set
		'''
		existing_val_dict = self.get_existing_syslog()
		if existing_val_dict is None or len(existing_val_dict) == 0:
			print_errinfo_log_stmt("Failed to get existing log host value for host {0}".format(self.host_name))
			raise Exception("Failed to get existing log host value for host".format(self.host_name))
		existing_val = self._get_syslog_loghost(existing_val_dict)
		logger.info("Existing loghost value : {0} for host:{1}".format(existing_val, self.host_name))

		if clear_existing or len(existing_val) <= 0:
			val = syslog_new_val
		else:
			# check if one of provided loghost exists in existing uri
			if provided_loghostlist is not None:
				if len(set(provided_loghostlist).intersection(set(existing_val.rstrip(',').split(',')))) > 0:
					logger.info("provided list :%s, existing uri :%s", set(provided_loghostlist), set(existing_val.rstrip(',').split(',')))
					logger.info("Already found one of the uri from given uris, so no need to add it, hence only perform reset operation")
					reset = True
			val = (existing_val.rstrip(',') + ',' + syslog_new_val).rstrip(',')

		if reset or (not self._isEsx4x() and existing_val == val):
			# VMWare ESX has bug, SDK throws exception if we set same value
			if not self._isEsx4x():
				dummy_val = "tcp://0.0.0.0:514"
				self.set_syslog(dummy_val)
				# Remove existing dummy value followed by , if it is present in existing value
				existing_val = re.sub(r'{0}(?=,),'.format(dummy_val), '', existing_val)
				# Remove existing dummy value if , is followed by dummy value
				existing_val = re.sub(r',\s*{0}'.format(dummy_val), '', existing_val)
				logger.info("Removed dummy uri value if any existed from existing uri, new value=%s for host:=%s", existing_val, self.host_name)
				val = existing_val

		logger.debug("Setting remote sys log value:{0} for host:{1}".format(val, self.host_name))
		success = False
		if not self._isEsx4x():
			success = self.conn.update_options(self.host_advOption_moid, "Syslog.global.logHost", val)
		else :
			# 4.x does not support protocol, multiple loghost value
			logger.warn("ESX 4.x does not support protocol and multiple loghost value in the configuration.")
			logger.warn("Ignoring protocol from provided field...")
			if val is None:
				raise Exception("sys log remote host value can't be None")

			val_list = val.split(",")
			if len(val_list) > 1:
				logger.warn("Ignoring multiple value, taking only first value from list ..")
				val = val_list[0]
			host, port = self.gethost_fromuri(val)
			logger.info("Updating Remote Host value and port separately...")
			success = self.conn.update_options(self.host_advOption_moid, "Syslog.Remote.Hostname", host) and \
					  self.conn.update_options(self.host_advOption_moid, "Syslog.Remote.Port", port, "xsd:int")
		if success:
			logger.info("Successfully set Syslog remote host value: {0} for host : {1}".format(val, self.host_name))
		else :
			logger.info("Failed set Syslog remote host value: {0} for host : {1}".format(val, self.host_name))

	def config_operation(self, args):
		'''
			Perform host config opertion as per passed args
			
			ARGS :
			   args : dict of support args
		'''
		firewall_required_options = self.get_firewall_options()
		if args.get('print_detailed', False) or args.get('print', False) or args.get('get_info_json', False):
			syslog_existing_options = self.get_existing_syslog()
			if not args.get('print_detailed', False):
				syslog_existing_options = {"Syslog.global.logHost": self._get_syslog_loghost(syslog_existing_options)}
			return {'host_name': self.host_name,
					'host_esx_version': self.host_product_version,
					'firewall_info': firewall_required_options,
					'syslog_info': syslog_existing_options}
		elif 'reset' in args or 'set_loghost' in args:
			if args['set_loghost'] is None or len(args['set_loghost'].strip('')) == 0:
				args['set_loghost'] = ''
			if firewall_required_options is not None and not firewall_required_options.status == 'true':
				self.enable_firewall(firewall_key="syslog")
			if args.get('reset', False):
				self.set_syslog("", reset=True)
			else:
				self.set_syslog(args.get('set_loghost', ''), clear_existing=args.get('clear_existing', False), provided_loghostlist = args.get('provided_loghostlist', None))
		else:
			print_errinfo_log_stmt("Unsupported operations is called")
			raise ValueError('Unsupported operation')
		logger.info("Successfully perform the operation for host: {0}".format(self.host_name))


########### Supporting functions ################
def reformat_output(data, output_format='dict'):
	try:
		if isinstance(data, dict) and output_format == 'dict':
			return data
		elif output_format == 'json':
			return json.dumps(data)
		else:
			raise ValueError("Bad output format")
	except Exception as e:
		print_errinfo_log_stmt("Error in formatting the output w/ output_format %s", output_format)
		logger.exception(e)

def create_connection(vc_fqdn, user, password):
	'''
		Create VC connection and return connection object

		Return :
			Connection object
	'''
	try :
		return vSphereService(vc_fqdn, user, password)
	except LoginFailure as e:
		print_errinfo_log_stmt("Failed to login by provided credentials.")
		logger.exception(e)
	except ConnectionFailure as e:
		print_errinfo_log_stmt("Failed to reachable to provide VC {0}".format(vc_fqdn))
		logger.exception(e)


def get_hosts(connected_hosts, target_hosts=None):
	"""
		Return array of tuple (host_name host moid, host version, host type (ESX/ESXi)
		
		Args :
		  connected_hosts =  List of connected hosts; each list element is a dict containing at least
							 the following keys: moid, name, config.product.version, config.product.name
		  target_hosts = list of host passed by --target-host optins. If this is none then all connected host is return
		
		Return : List of (name, moid, config.product.version, config.product.name) tuples
	"""
	# get name, moid, version and type of connected_hosts
	host_name_id_dict = {}
	for val in connected_hosts :
		host_name_id_dict[val['name']] = (val['name'], val['moid'], val['config.product.version'], val['config.product.name'])

	if target_hosts is not None:
		unknown_target_hosts = list(set(target_hosts).difference(set(host_name_id_dict.keys())))
		connected_target_hosts = list(set(target_hosts).intersection(set(host_name_id_dict.keys())))
		if len(unknown_target_hosts) > 0:
			logger.warn("Some specified target hosts are not known to this vCenter: " + str(unknown_target_hosts))
		return [host_name_id_dict[x] for x in connected_target_hosts]
	return host_name_id_dict.values()

def validate_uri(uri, isTcpOrUdp=False):
	'''
		Check if uri has a protocol, host and port defined
		Agrs
		 uri : uri which needs to be validated
		 isTcpOrUdp : uri protocol value should be tcp or udp
		 
		Return value :
		   True if uri is correct (has protocol, host and port defined), False otherwise
	'''
	url = urlparse(uri)
	if url is None:
		logger.warn('Not a valid uri {0}. Make sure provided uri should have protocol, host and port defined.'.format(uri))
		return False
	else :
		retVal = True
		if url.netloc in [None, '']:
			logger.warn('Network location (Host and Port) is not specified in uri:{0}. Make sure provided uri should have protocol, host and port defined.'.format(uri))
			retVal = False
		if url.scheme in [None, '']:
			logger.warn('Protocol is not specified in uri:{0}. Make sure provided uri should have protocol, host and port defined.'.format(uri))
			retVal = False
		# check if protocol is tcp or udp
		if isTcpOrUdp and url.scheme not in [None, '']:
			if url.scheme not in ['tcp', 'udp']:
				logger.warn('Only TCP or UDP Protocol is supported in uri:{0}. Make sure provided uri should have protocol, host and port defined.'.format(uri))
				retVal = False
		return retVal

def validate_loghost(loghost):
	''' 
		Verified if provided path is valid uri or not 
	
		ARGS : 
		   loghost : String separated by ,
		
		Return :
		   True : If provided all value is valid uri (contains protocol, host and port)
	'''
	# Do not allow empty value
	if loghost is None or len(loghost.strip(' ')) == 0:
		return False
	# loghost can have more than one host value split by ,
	ret = True
	for host in loghost.split(','):
		ret = validate_uri(host, True)
		if not ret:
			break
	return ret

def worker(conn_obj, hostname, host_moid, host_prod_version, host_prod_name, args, queue):
	'''
	  Worker processor to run process for each host
	  
	  ARGS :
		conn_obj : VC connection object  ( tuple 0 index)
		host_moid : Host Moid
		host_name : Host Name
		host_prod_version : Host version
		host_prod_name =  Host Product Name (ESX or ESXi)
		args : Command line arguments
	
	  Return : whatever the given config operation might return, e.g. a JSON of data

	'''
	try:
		print_errinfo_log_stmt("Performing operation on host: {0} ....".format(hostname), "info")
		ret = SysLogConfigurator(conn_obj, hostname, host_moid, host_prod_version, host_prod_name).config_operation(args)
		if ret is not None:
			queue.put(ret)
		print_errinfo_log_stmt("Completed operation on host: {0}.".format(hostname), "info")
	except HTTPError as e:
		print_errinfo_log_stmt("Failed to perform operation on host {0}: with error:".format(hostname) +str(e)+ " ,refer log for more information.")
		logger.exception(e)
		raise Exception("Syslog couldn't be configured")

def run_limited_process(conn_obj, hosts, args, start_index, last_index, loghosts, loghost_idx):
	'''
		Run limited process to increase the scale
	'''
	from multiprocessing import Process, Queue
	queue = Queue(len(hosts))
	jobs = []
	for hostname, host_moid, host_prod_version, host_prod_name in hosts[start_index:last_index]:
		# Load balancing of loghosts value
		adjust_loghost_arg_maybe(loghosts, loghost_idx, args)
		p = Process(target=worker, args=(conn_obj, hostname, host_moid, host_prod_version, host_prod_name, args, queue))
		jobs.append(p)
		p.start()
	# wait to complete
	for job in jobs:
		job.join()
	return queue


def mod_enumerate(iterable, start=0):
	'''
		Index generator
	'''
	while True:
		yield start, iterable[start] 
		start = (start + 1) % len(iterable)

def adjust_loghost_arg_maybe(loghosts, loghost_idx, args):
	'''
		@param loghosts: List of log host
		@param loghost_idx: loghost index
		@param args: dict of argument where set_loghost value is being set   
	'''
	if loghosts is not None and len(loghosts) > 1:
		idx, loghost = next(loghost_idx)
		logger.debug("Load-balancing the loghosts: assigning cur host to loghost %d (%s)", idx, loghost)
		args['set_loghost'] = loghost

def run_hosts_operation(conn_obj, hosts, args):
	'''
		Run host operations
		 If Multiprocess is supported then it run the process in parallel to perform syslog operation, otherwise run in single process
		ARGS :
			conn_obj : VC connection object
			hosts : List of tuple which hold (host name, host moid,  host product version, host product name)
			
		Return : Output of the multiprocess workers
	'''
	# to implement load-balancing across multiple loghosts, we iterate through
	# the list of loghosts in a circular fashion, assigning a different loghost to 
	# each new host (or host group, for multiprocessing) that we see
	loghosts = args['set_loghost'].split(',') if args.get('set_loghost', False) else []

	# Add additional arg in args so we do not set multiple loghost from given list in repair operation
	args['provided_loghostlist'] = loghosts

	loghost_idx = mod_enumerate(loghosts)

	results = []
	# Run multiprocessing if it is supported if it is not support ImportError is thrown
	try:
		process_limit = args.get("no_of_processor", 8)
		index = 0
		total_hosts = len(hosts)
		while index < total_hosts and index+process_limit <= total_hosts:
			out_queue = run_limited_process(conn_obj, hosts, args, index, index+process_limit, loghosts, loghost_idx)
			index += process_limit
			while not out_queue.empty() :
				results.append(out_queue.get())
		# remaining host
		out_queue = run_limited_process(conn_obj, hosts, args, index, total_hosts, loghosts, loghost_idx)
		while not out_queue.empty() :
			results.append(out_queue.get())
	except ImportError:
		# When multiprocessing is not supported
		import Queue
		out_queue = Queue.Queue()
		for hostname, host_moid, host_prod_version, host_prod_name in hosts:
			adjust_loghost_arg_maybe(loghosts, loghost_idx, args)
			worker(conn_obj, hostname, host_moid, host_prod_version, host_prod_name, args, out_queue)
		while not out_queue.empty() :
			results.append(out_queue.get())
	return results

def print_info(res):
	"""
	Prints syslog info results dict which has the following keys:
	firewall_info, syslog_info, host_esx_version, host_name
	"""
	print "Syslog informations for host {0}:".format(res['host_name'])
	# Check as ESXi does not support firewall
	if 'firewall_info' in res and res['firewall_info'] is not None:
		firewall_info = SyslogFirewallOptions(res['firewall_info'])
		status_string = "ALLOWED" if firewall_info.status == 'true' else "DISALLOWED"
		print "	Firewall info: {status}: {rules}; allowed hosts: {allowed_hosts}".format(
			status=status_string, rules=firewall_info.rules, allowed_hosts=firewall_info.allowed_hosts)
	else:
		print "	Firewall setting is not available on host {0}".format(res['host_name'])
	# Syslog properties
	sys_log_info = res['syslog_info']
	for key, val in sys_log_info.iteritems():
		print "	{opt}: {value}".format(opt=key, value=val)

################ Main function for use in command-line mode  ###############
def print_errinfo_log_stmt(reason, level="error"):
	'''
		Print log statement (info and error level only), this will help to aviod
		duplicate logging if console logging is enabled
		ARGS :
		   reason : Log message to print
		   level : info or error level
	'''
	if level == 'info':
		logger.info(reason)
	else:
		logger.error(reason)
        # if is_console_logging is True, we do NOT need to print since the message 
        # is being logged to the console already
	if not is_console_logging:
		print reason

def get_processpid_formfile(filename):
	'''
		Get Pid from pid file
	'''
	with open(filename, 'r') as f:
		pid = f.readline()
	return pid

def check_pid_running(pid):
	'''
	   Check if pid is running is not
	'''
	try:
		os.kill(int(pid), 0)
	except OSError:
		return False
	else:
		return True

def acquire_lock(lockname=None):
	'''
		Check if another instance of this script is running by checking pid of old process.
		
		ARGS:
			lockname: if lockname is none, locks on scriptname else locks on lockname
		
		Return: pid file name if successful
		Raises: ScriptAlreadyRunningException exception if another instance is running
	'''
	try:
		pidfile = os.path.split(sys.argv[0])[1]+".pid"
		if lockname is not None:
			pidfile = lockname.replace("/","_").replace(":","_") + "." + pidfile
		pidfile = os.path.join(make_splunkhome_path(['var', 'log', 'splunk', pidfile]))
		
		if os.path.isfile(pidfile):
			pid = get_processpid_formfile(pidfile)
			if check_pid_running(pid):
				logger.warn("Instance of this script is already running with pid:"+pid+".. exiting.")
				raise ScriptAlreadyRunningException("Another instance of scripts is running, with pid:"+ pid)
		with open(pidfile, 'w+') as f:
			f.write(str(os.getpid()))
			return pidfile
	except ScriptAlreadyRunningException:
		raise
	except Exception as e:
		print_errinfo_log_stmt("General error acquiring lock")
		logger.exception(e)


@run_single_instance
def execute_operation(*args, **kwargs):
	'''
	Single-instance entry point to run_hosts_operation
	'''
	return run_hosts_operation(*args, **kwargs)

		
@run_single_instance
def main():
	'''
		Main function which is invoked during command line
		
		Return : True if operation is successful, False otherwise
	'''
	logger.info("==== Begin syslog script logging ====")
	global is_console_logging
	is_console_logging = False
	cmdLine = SysLogCommandLineParser()
	cmdLine.setup_parser()
	args = cmdLine.process_arguments()
	# Enable debug logging for console if -d flag is passed
	if args.d:
		setup_console_logging(logger)
		is_console_logging = True
		logger.info("==== Begin sys log console logging ====")
	# Check if one of required option is present in command line option
	# Note : args.print give an complier error hance vars(args) is used as work around
	if args.set_loghost is not None or args.print_detailed or args.reset or vars(args)['print']:
		if args.set_loghost is not None:
			args = vars(args)
			if len(args['set_loghost'].strip(' ')) == 0:
				# set it to empty value
				args['set_loghost'] = ''
			elif not validate_loghost(args['set_loghost']):
				print_errinfo_log_stmt("set_loghost option does not contain valid uri.")
				return False
		else:
			args = vars(args)
	else:
		print_errinfo_log_stmt("Missing or invalid configuration options; exiting")
		cmdLine.parser.print_help()
		return False
	# Getting password, if it is not passed
	if args.get('password', None) is None :
		args['password'] = getpass.getpass("Enter the password:")
	# Create connection
	si = create_connection(args['vcenter'], args['username'], args['password'])
	if si is None:
		return False

	target_hosts = args['target_hosts'].split(',') if args['target_hosts'] is not None else None
	# Trim spaces
	target_hosts = [x.strip(' ') for x in target_hosts] if args['target_hosts'] is not None else None
	# Get connection host list
	vc_host_list = si.get_host_list()
	logger.debug("Connected host information : {0}".format(str(vc_host_list)))
	if len(vc_host_list) == 0:
		print_errinfo_log_stmt("Failed to get ESX/i host(s) from provided VC, existing...")
		si.logout()
		return False

	# Get only moid and host name which needs to be updated
	hosts = get_hosts(vc_host_list, target_hosts)
	if len(hosts) == 0:
		print_errinfo_log_stmt("Could not get any host list to update, existing...")
		si.logout()
		return False
	try:
		retValues = run_hosts_operation(si, hosts, args)
		if args['print'] or args['print_detailed']:
			logger.info("Printing Syslog Information :{0}".format(retValues))
			for ret in retValues:
				print_info(ret)
	except Exception as e:
		print_errinfo_log_stmt(str(e))
		logger.exception(e)
		return False
	finally:
		si.logout()
		logger.info("==== Exiting syslog script logging ====")
		return True


logger = vim25.setupLogger()
is_console_logging = True
if __name__ == "__main__":
	try:
		# help in unit test case to check for process return code
		if not main():
			sys.exit(1)
	except ScriptAlreadyRunningException as e:
		print_errinfo_log_stmt(str(e))
