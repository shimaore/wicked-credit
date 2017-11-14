TS stream muxer-demuxer
-----------------------

- TS Streams are transported as UDP multicast.
- A TS stream is made out of [TS packets](https://en.wikipedia.org/wiki/MPEG_transport_stream#Packet).
- Each TS packet carries the PID it is associated with.
- The PID's semantics are provided by the PMT.
- The [Elementary Stream Types](https://en.wikipedia.org/wiki/Program-specific_information#Elementary_stream_types) indicated by each PID are not sufficient to know the content of the stream.
- PMT's in broadcast media are relatively static and can be known in advance (e.g. from http://fr.kingofsat.fr/pos-13E.php, or dvblast output: `dvblastctl -r /tmp/dvblast-3-2.sock get_pmt 1031`).
- We provide mapping of a TS UDP stream to one or multiple outbound stream.

Configuration:
```
{
"source": {
"protocol": "udp4",
"address":"239.200.5.2",
"port":2002,
"multicast": true
}
"sinks":[
{
"description":"Arte, audio allemand, sous-titres français",
"source": {
"protocol": "udp4",
"port": 10000,
"address": "10.1.1.1"
}
"multicast": true,
"address":"239.200.5.2",
"port":12002,
"pids":[320,333,340]
}
]
}
```

    dgram = require 'dgram'
    seem = require 'seem'
    {debug,hand} = (require 'tangible') 'wicked-credit:server'

    promisify = (obj,method,args...) ->
      new Promise (resolve,reject) ->
        method.call obj, args..., (err,res) ->
          if err?
            reject err
          else
            resolve res

    TS_PACKET_LENGTH = 188

    received_udp = 0
    received_ts  = 0
    sent_udp = 0
    sent_ts = 0
    reporter = ->
      console.log """
        Received: #{received_udp} UDP, #{received_ts} TS. Sent: #{sent_udp} UDP, #{sent_ts} TS.
      """
    # setInterval reporter, 1000

    receiver = (opts) ->
      {protocol,port,address,multicast} = opts
      r = dgram.createSocket
        type: protocol ? 'udp4'
        reuseAddr: true

      r.on 'message', (msg,rinfo) ->
        nb_packets = Math.floor msg.length / TS_PACKET_LENGTH
        received_udp++
        received_ts += nb_packets

        ts_packets = [0...nb_packets].map (i) ->
          ts_packet = msg.slice i*TS_PACKET_LENGTH, (i+1)*TS_PACKET_LENGTH
          header = ts_packet.readUInt32BE 0
          pid = (header & 0x001fff00) >> 8
          {pid,ts_packet}

        r.emit 'ts_packets', ts_packets

      (do seem ->
          yield promisify r, r.bind, {port, address, exclusive: false}
          r.addMembership address if multicast
      ).catch (error) ->
        console.error opts, error
        process.exit 1

      return r

    transcribe = (receiver,opts) ->
      {source,multicast,address,port,pids} = opts
      my_pids = new Set pids

      t = dgram.createSocket source?.protocol ? 'udp4'

      send_args = []
      receiver.on 'ts_packets', (ts_packets) ->
        my_packets = ts_packets
          .filter ({pid}) -> my_pids.has pid
          .map ({ts_packet}) -> ts_packet

        nb_packets = my_packets.length
        return unless nb_packets > 0
        msg = Buffer.concat my_packets
        t.send msg, 0, nb_packets * TS_PACKET_LENGTH, port, address
        sent_udp++
        sent_ts += nb_packets

      (do seem ->
        if source?
          args = []
          args.push source.port if source.port?
          args.push source.address if source.address?
          yield promisify t, t.bind, args... if args.length > 0
          if multicast
            t.setMulticastInterface? source.address
          else
      ).catch (error) ->
        console.error opts, error
        process.exit 1

      return

    main = seem (configuration) ->
      r = yield receiver configuration.source
      configuration.sinks.forEach (opts) -> transcribe r, opts

    config_file = process.argv[2] ? process.env.CONFIG
    unless config_file?
      console.log "Usage:  #{process.argv[1]} config.json  , or provide CONFIG in environment."
      process.exit 1
    if config_file[0] is '{'
      config = JSON.parse config_file
    else
      config = require config_file

    debug 'Configuration', config_file, config

    main config
