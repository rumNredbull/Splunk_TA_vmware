# Copyright (C) 2005-2017 Splunk Inc. All Rights Reserved.
from datetime import datetime

class MetricsCache(object):
    """LRU cache for storing metric lists.
    
    Instantiated with kwargs:
      max_size - max number of items before expulsion
      expunge_size - number of least-recently accessed items
        to purge when exceeding max_size.

    Class wraps a dictionary implementing a minimal interface."""
    def __init__(self, max_size=20, expunge_size=10):
        self.d = {}
        self.CACHE_MAX_SIZE = max_size
        self.CACHE_EXPUNGE_SIZE = expunge_size
        if expunge_size >= max_size or max_size <= 2:
            raise ValueError("Bad cache size parameters")
    def __setitem__(self, key, value):
        self.d[key] = [value, datetime.now()]
        if len(self.d) > self.CACHE_MAX_SIZE:
            for ts, key in sorted([(v[1], k) for k,v in self.d.items()])[:self.CACHE_EXPUNGE_SIZE]:
                del self.d[key]
    def __getitem__(self, key):
        self.d[key][1] = datetime.now()
        return self.d[key][0]
    def __contains__(self, key):
        return key in self.d
    def __len__(self):
        return len(self.d)
    def __delitem__(self, key):
        del self.d[key]
    
