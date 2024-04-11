package configmigrate

// migrateTo29 performs the following changes:
//
//	# BEFORE:
//	'tls':
//	  'server_name': domain
//	  # …
//	# …
//
//	# AFTER:
//	'tls':
//	  'server_names':
//	     - domain
//	  # …
//	# …
func migrateTo29(diskConf yobj) (err error) {
	diskConf["schema_version"] = 29

	tls, ok, err := fieldVal[yobj](diskConf, "tls")
	if !ok {
		return err
	}

	server_name, ok, err := fieldVal[string](tls, "server_name")
	if !ok {
		return err
	}

	tls["server_names"] = yarr{server_name}

	delete(tls, "server_name")

	return nil
}
