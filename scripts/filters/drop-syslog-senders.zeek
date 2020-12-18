module LogFilters;

export {
    # syslog senders to ignore and not log
    option dropped_senders: set[subnet] = {};
}

function drop_senders(rec: Syslog::Info): bool 
    {
    # record syslog messages that aren't sent by 
    return !(rec$id$orig_h in LogFilters::dropped_senders);
    }

event zeek_init()
    {
    Log::add_filter(Syslog::LOG, [$name = "drop-senders-sysloglog",
                    $pred=drop_senders]);
    }