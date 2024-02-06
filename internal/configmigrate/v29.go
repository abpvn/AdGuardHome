package configmigrate

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
		_, ok, _ := fieldVal[yarr](c, "filters")
		if !ok {
			c["filters"] = yarr{}
		}
		_, ok, _ = fieldVal[yarr](c, "whitelist_filters")
		if !ok {
			c["whitelist_filters"] = yarr{}
		}
		_, ok, _ = fieldVal[bool](c, "use_global_filter")
		if !ok {
			c["use_global_filter"] = true
		}
	}

	return nil
}
