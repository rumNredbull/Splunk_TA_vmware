# Copyright (C) 2005-2017 Splunk Inc. All Rights Reserved.
[ta_vmware_collection_worker://<name>]
capabilities = <value>
* this is the comma delimited list of actions that the worker can perform (hostvmperf, otherperf, etc.)
log_level = <value>
* the level at which the worker will log data.
duration = <value>
* the minimum time between runs of the input should it exit for some reason

[ta_vmware_collection_scheduler://<name>]
* the scheduler should only exist once
log_level = <value>
* the level at which the scheduler will log data.
duration = <value>
* the minimum time between runs of the input should it exit for some reason