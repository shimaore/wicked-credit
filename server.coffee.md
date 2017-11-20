TS stream muxer-demuxer
-----------------------

Problem statement:

Although `ffmpeg` may be used for a similar goal (using the `copy` codec), it only accepts to map ES that are available at startup time. This means in particular that subtitles are often not made available.

Analysis:

- TS Streams (such as those made available by third parties or by `dvblast`) are transported as UDP multicast.
- A TS stream is made out of [TS packets](https://en.wikipedia.org/wiki/MPEG_transport_stream#Packet).
- Each TS packet carries the PID it is associated with; the PID identifies an ES within the TS.
- The PID's semantics are provided by the PMT.
- The [Elementary Stream Types](https://en.wikipedia.org/wiki/Program-specific_information#Elementary_stream_types) indicated by each PID are not sufficient to know the content of the stream.
- However PMT's in broadcast media are relatively static and can be known in advance (e.g. from http://fr.kingofsat.fr/pos-13E.php, or from dvblast output: `dvblastctl -r /tmp/dvblast-3-2.sock get_pmt 1031`).

Solution:

- We provide mapping of a TS UDP stream to one or multiple outbound streams.

Note that our solution supports:
- UDP unicast or multicast as source;
- UDP unicast or multicast as sink.

Configuration
-------------

```
{
"source": {
"protocol": "udp4",
"address":"239.200.5.2",
"port":2002,
"multicast": true
"h264": true
}
"sinks":[
{
"description":"Arte, audio allemand, sous-titres français",
"source": {
"protocol": "udp4",
"port": 10000,
"address": "10.1.1.1"
},
"multicast": true,
"address":"239.200.5.2",
"port":12002,
"pids":[320,333,340]
}
,
{
"description":"Arte, audio allemand, sous-titres français",
"directory": "/dev/shm/hls",
"base_uri": "http://kargo.k-net.fr/tv/play/500"
"m3u8": "channel.m3u8",
"target_duration":6000,
"keep_segments":5,
"pids":[320,333,340]
}
]
}
```

    dgram = require 'dgram'
    seem = require 'seem'
    {debug,hand,heal} = (require 'tangible') 'wicked-credit:server'
    promisify = require './promisify'

The whole problem is made simple by the fact that TS packets have a static length and are aligned on UDP packet boundaries.
This means we do not have to do framing inside the UDP packets, and deducing the number of TS packets in a UDP packet is trivial.
(See ITU H.220.0 for more information on TS.)

    TS_PACKET_LENGTH = 188

    receiver = require './receiver'
    transcribe_as_udp = require './transcribe_as_udp'
    transcribe_as_hls = require './transcribe_as_hls'

Main
----


    main = seem (configuration) ->

Start the receiver

      r = yield receiver configuration.source

and a sending process for each sink.

      for opts in configuration.sinks
        if opts.directory?
          yield transcribe_as_hls r, opts
        else
          yield transcribe_as_udp r, opts

      debug 'Started.'
      return

Startup
-------

The configuration can be provided either as the program's parameter, or in the `CONFIG` environment variable.

    config_file = process.argv[2] ? process.env.CONFIG
    unless config_file?
      console.log "Usage:  #{process.argv[1]} config.json  , or provide CONFIG in environment."
      process.exit 1

The configuration might be inband, consisting of a JSON description,

    if config_file[0] is '{'
      config = JSON.parse config_file

or out of band, in which case we load it from the file location indicated.

    else
      config = require config_file

    debug 'Configuration', config_file, config

Start the main process with the configuration.

    main config
