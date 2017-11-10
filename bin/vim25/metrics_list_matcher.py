# Copyright (C) 2005-2016 Splunk Inc. All Rights Reserved.
import re

class MetricsListMatcher(object):
    """Class to perform whitelist/blacklist selections.
    
    Instantiated with kwargs:
      whitelist - list of regex or verbatim strings
      blacklist - list of regex or verbatim strings
      mode ["verbatim" | "regex"] - matching mode
    
    Lists are filtered using the prune method."""
    def __init__(self, whitelist=None, blacklist=None, mode="verbatim"):
        self.w = set(whitelist) if bool(whitelist) else None
        self.b = set(blacklist) if bool(blacklist) else None
        self.mode = mode
    def _match_elt_regex(self, elt, name_extractor):
        accept_wl = self.w is None or any(re.search(x, name_extractor(elt)) for x in self.w)
        accept_bl = self.b is None or not any(re.search(x, name_extractor(elt)) for x in self.b)
        return accept_wl and accept_bl
    def _match_elt_list(self, elt, name_extractor):
        accept_wl = self.w is None or name_extractor(elt) in self.w
        accept_bl = self.b is None or name_extractor(elt) not in self.b
        return accept_wl and accept_bl
    def prune(self, l, name_extractor=lambda x: x, return_excluded=False):
        """Filter a list based on whitelists/blacklists.
        
        Optional arguments: 
          name_extractor - apply to every list element before trying a match
          return_excluded (boolean) - if True, separate the original list into 
              two, one with items that conform to the white/blacklists, and the other 
              with ones that do not."""
        if self.mode == "verbatim":
            test_match = self._match_elt_list
        elif self.mode == "regex":
            test_match = self._match_elt_regex
        else:
            raise ValueError('Mode must be verbatim or regex')
        if return_excluded:
            incl = []
            excl = []
            [incl.append(x) if test_match(x, name_extractor) else excl.append(x) for x in l]
            return (incl, excl)
        else:
            return [x for x in l if test_match(x, name_extractor)]
