package configmigrate

// migrateTo29 performs the following changes:
//
//	# BEFORE:
//	'tls':
//	  'server_name': domain
//	'clients':
//	  'persistent':
//	     - safe_search:
//		     # …
//	       'tags': []
//		  # …
//	# …
//
//	# AFTER:
//	'tls':
//	  'server_names':
//	     - domain
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
		c["user_rules"] = yarr{}
	}

	tls, ok, err := fieldVal[yobj](diskConf, "tls")
	if !ok {
		return err
	}

	server_name, ok, err := fieldVal[string](tls, "server_name")
	if !ok {
		tls["server_names"] = yarr{""}
	} else {
		tls["server_names"] = yarr{server_name}
	}

	delete(tls, "server_name")

	return nil
}
