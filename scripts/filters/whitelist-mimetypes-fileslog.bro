module LogFilters;

export {
    # logged_file_mimetypes is a whitelist of mimetypes to log to files.log
    # all other mimetypes will be discarded and not logged.
    const logged_file_mimetypes = set() &redef;
}

event bro_init() 
    {
    # Remove the default files log filter
    Log::remove_default_filter(Files::LOG);

    Log::add_filter(Files::LOG, [$name = "whitelist-mimetypes-fileslog",
		$pred(rec: Files::Info) = {
            # By default, all files are discarded from the files.log
		    local result = F;
            # Only matching mimetypes are logged. This means that files
            # with even undetected mimetypes will be discarded.
		    if (rec?$mime_type && rec$mime_type in logged_file_mimetypes)
		        {
		        result = T;
		        }
		    return result;
		}
		]);
    }