package configmigrate

// migrateTo29 performs the following changes:
//
//	# BEFORE:
//	'clients':
//	  'persistent':
//	     - safe_search:
//		     # …
//	       'tags': []
//		  # …
//	# …
//
//	# AFTER:
//	'clients_filters': []
//	'clients':
//	  'persistent':
//	     - safe_search:
//		    # …
//	     'tags': []
//	     'filters': []
//	     'whitelist_filters': []
//	     'use_global_filters': true
//		  # …
//		# …
func migrateTo29(diskConf yobj) (err error) {
	diskConf["schema_version"] = 29

	_, ok, _ := fieldVal[yarr](diskConf, "clients_filters")
	if !ok {
		diskConf["clients_filters"] = yarr{}
	}

	clients, ok, err := fieldVal[yobj](diskConf, "clients")
	if !ok {
		return err
	}

	persistent, ok, _ := fieldVal[yarr](clients, "persistent")
	if !ok {
		return nil
	}

	for _, p := range persistent {
		var c yobj
		c, ok = p.(yobj)
		if !ok {
			continue
		}
		c["filters"] = yarr{}
		c["whitelist_filters"] = yarr{}
		c["use_global_filters"] = true
	}

	return nil
}
