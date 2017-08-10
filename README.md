# log-filters
Common log filters for Bro IDS

This is a Bro package that provides commonly requested log filters. These filters either modify or prevent the logging of events or records.

## Installing with bro-pkg (preferred)

This package can be installed through the [bro package manager](http://bro-package-manager.readthedocs.io) by utilizing the following commands:

```sh
bro-pkg install bro/hosom/log-filters

# you must separately load the package for it to actually do anything
bro-pkg load bro/hosom/log-filters
```

## Configuration

The package installs with no log filters configured, however, log filters can be defined and loaded safely within **config.bro**. 

The filters are described below.

## Provided Filters

### whitelist-analyzers-fileslog.bro

A filter that restricts the files.log to only files that have a specified file analyzer attached to them. 

#### Configuration

To load this filter, add the following line to your config.bro:

```
@load filters/whitelist-analyzers-fileslog
```

To whitelist an analyzer, redef the set **logged_file_analyzers**.

### whitelist-mimetypes-fileslog.bro

A filter that restricts the files.log to only files that have a specified file mimetype detected.

#### Configuration

To load this filter, add the following line to your config.bro:

```
@load filters/whitelist-mimetypes-fileslog
```

To whitelist a mimetype, redef the set **logged_file_mimetypes**.