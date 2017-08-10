module LogFilters;

export {
    # logged_file_analyzers is a whitelist of file analyzers that when 
    # attached to a file will cause it to be logged in the files.log
    const logged_file_analyzers = set() &redef;
}

event bro_init() 
    {
    # Remove the default files log filter
    Log::remove_default_filter(Files::LOG);

    Log::add_filter(Files::LOG, [$name = "whitelist-analyzers-fileslog",
		$pred(rec: Files::Info) = {
            # By default, all files are discarded from the files.log
            local result = F;
            # Only matching analyzers are logged. All other analyzers
            # including no analyzer will be discarded.
            if ( rec?$analyzers )
                {
                for ( analyzer in rec$analyzers )
                    {
                        if ( analyzer in logged_file_analyzers )
                            {
                            result = T;
                            break;
                            }
                    }
                }
            return result;
        }
        ]);
    }