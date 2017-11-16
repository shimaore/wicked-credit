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
    promisify = require './promisify'

The whole problem is made simple by the fact that TS packets have a static length and are aligned on UDP packet boundaries.
This means we do not have to do framing inside the UDP packets, and deducing the number of TS packets in a UDP packet is trivial.

    TS_PACKET_LENGTH = 188

The H.264 start code, which can be used (according to Annex B) to locate the start of a NAL Unit.

    H264_START_CODE = Buffer.from [0x00,0x00,0x00,0x01]

Some filler data that gets injected in the last-pad.
Since the last-pad must be long enough to cover the Start Code (4 octets), the NAL Unit Type (1 octet), and the extra octet needed by SEI/AUD, this means the filler must be six octets long.

    H264_FILLER     = Buffer.from [0xff,0xff,0xff,0xff,0xff,0xff]

Statistics

    received_udp = 0
    received_ts  = 0
    sent_udp = 0
    sent_ts = 0
    reporter = ->
      console.log """
        Received: #{received_udp} UDP, #{received_ts} TS. Sent: #{sent_udp} UDP, #{sent_ts} TS.
      """
    # setInterval reporter, 1000

Receiver
--------

The receiver is responsible for handling incoming UDP packets, and split them into individual TS packets.

    receiver = (opts) ->
      {protocol,port,address,multicast,h264} = opts

Create the UDP socket, making sure the port and address we will use can be shared with other processes (typically ffmpeg).

      r = dgram.createSocket
        type: protocol ? 'udp4'
        reuseAddr: true

FIXME Should handle `error`, `listening`, etc.

### H.264 handling

We try to automatically detect the video PES (assuming there is only one in the TS stream).

      h264_video_pid = null

The last pad contains the last 4 octets of the previous H.264 PES.

      h264_last_pad = Buffer.from H264_FILLER

Storage for the H.264 buffer. It may consist of the PES payload (for the first ES frame) or of the last 4 octets of the previous frame plus the current frame.

      h264_buf = Buffer.alloc TS_PACKET_LENGTH + h264_last_pad.length

### UDP packets receiver

      r.on 'message', (msg,rinfo) ->

Since TS packets have a fixed length, we split the UDP packet in TS-packet-length chunks.
(If the UDP packet length is not aligned on TS-packet-length boundaries we junk the last chunk.)

        nb_packets = Math.floor msg.length / TS_PACKET_LENGTH

Update statistics.

        received_udp++
        received_ts += nb_packets

Build the list of TS packets,

        ts_packets = [0...nb_packets].map (i) ->

slicing the original (received) buffer into TS-packet-lenght chunks,

          ts_packet = msg.slice i*TS_PACKET_LENGTH, (i+1)*TS_PACKET_LENGTH

reading the header of each TS packet

          header = ts_packet.readUInt32BE 0

in order to extract the ES' PID;

          pid = (header & 0x001fff00) >> 8

#### Keyframe detection

The PUSI indicator is present on the first higher-protocol frame.

          pusi = (header & 0x00400000) > 0

For keyframe detection we parse the PES payload.

          ts_payload_offset = 4

First we figure out whether the adaptation field is present

          adaptation_field_present = (header & 0x20) > 0
          payload_present = (header & 0x10) > 0

in which case we need to account for its length.

          if adaptation_field_present
            adaptation_field_length = ts_packet.readUInt8 4
            ts_payload_offset += 1 + adaptation_field_length

In the first octet of the adaptation field itself we find the discontinuity indicator and the random access indicator
(these are normally only used with MPEG streams).

            adaptation_field = ts_packet.readUInt8 5
            ts_discontinuity_indicator = (adaptation_field & 0x80) > 0
            ts_random_access_indicator = (adaptation_field & 0x40) > 0
            # console.log "pid #{pid} disc #{ts_discontinuity_indicator} rai #{ts_random_access_indicator}" if ts_discontinuity_indicator or ts_random_access_indicator

          h264_nal_unit_start = null

          if pusi and payload_present

The PES payload starts with 00 00 01 (packet start code prefix),
while the fourth octet is the PES stream id

            pes_stream_id = ts_packet.readUInt8 ts_payload_offset + 3

and the fifth and sixth are the PES packet length (which for video tends to be zero).

If the PES indicates we are effectively dealing with video,

            if (pes_stream_id & 0xf0) is 0xe0 # video

let's keep that ES as our video ES,

              h264_video_pid = pid

assume the optional PES header is present

              optional_pes_header = ts_packet.readUInt16BE ts_payload_offset + 6

and gather the data alignment indicator.

              pes_data_alignment_indicator = (optional_pes_header & 0x0400) > 0

Then skip the PES optional fields

              pes_optional_field_length = ts_packet.readUInt8 ts_payload_offset + 8

and access the PES payload.

              pes_payload_offset = ts_payload_offset + 8 + 1 + pes_optional_field_length

##### Last pad

          if pid is h264_video_pid and payload_present

            if pusi

On the first frame of a PES packet, the H.264 (Annex B) NAL Units stream starts after the PES headers

              ts_packet.copy h264_buf, 0, pes_payload_offset
              h264_nal_unit_length = TS_PACKET_LENGTH-pes_payload_offset

and it is aligned.

              h264_nal_unit_start = 0

On the other hand, if this is the continuation of the PES packet,

            else

concatenate the last-pad and the current payload,

              h264_last_pad.copy h264_buf, 0
              ts_packet.copy h264_buf, ts_payload_offset
              h264_nal_unit_length = h264_last_pad.length + TS_PACKET_LENGTH-ts_payload_offset

and to get things started, look for an H.264 start code pattern in the buffer (per Annex B).

              h264_nal_unit_start = h264_buf.indexOf H264_START_CODE, 0

In both cases, save the last octets of the current buffer into the last-pad.

            h264_buf.copy h264_last_pad, 0, h264_nal_unit_length - h264_last_pad.length

The keyframe detection start in earnest.

          h264_iframe = false

          if pid is h264_video_pid and h264_nal_unit_start?

Note: we stop 6 bytes before the end of the current NAL. The extra data has already been saved

            while not h264_iframe and 0 <= h264_nal_unit_start < h264_nal_unit_length-5

The first four octets are the Annex B framing (00 00 00 01), and

              annexb_framing = h264_buf.readUInt32BE h264_nal_unit_start

the next octet contains the nal-ref-idc and the nal-unit-type.

              nal_first_octet = h264_buf.readUInt8 h264_nal_unit_start + 4
              forbidden_zero_bit = (nal_first_octet & 0x80) is 0
              nal_ref_idc = (nal_first_octet & 0x60) >> 5
              nal_unit_type = nal_first_octet & 0x1f

              # console.log "NAL (#{pusi} #{h264_nal_unit_start} #{nal_unit_type})"

Now let's apply some heuristic to indicate when might be a good time to split a H.264 video stream:

              switch nal_unit_type

- when we explicitely see an IDR picture NAL;

                when 5
                  h264_iframe or= true
                  # console.log 'IDR'

- when we explicitely see a recovery-point SEI;

                when 6 # SEI
                  sei_type = h264_buf.readUInt8 h264_nal_unit_start + 5
                  recovery_point = sei_type is 6
                  h264_iframe or= recovery_point
                  # console.log 'Recovery point' if recovery_point

- but more probably in actual streams, when the Access Unit contains only "I" slice types.

                when 9 # Access Unit Delimiter
                  primary_pic_type = (h264_buf.readUInt8 h264_nal_unit_start + 5) >> 5
                  islice = primary_pic_type is 0 or primary_pic_type is 3 or primary_pic_type is 5
                  h264_iframe or= islice
                  # console.log 'I-slice AUD' if islice

If we haven't found a keyframe NAL yet, try to locate the next NAL Unit in the current buffer.

              unless h264_iframe
                h264_nal_unit_start = h264_buf.indexOf H264_START_CODE, h264_nal_unit_start+5

Finally build a data structure to hold the PID, TS packet, and other information about this TS packet.

          # console.log ">> H.264 I-Frame for PID #{pid} (#{pusi} #{h264_nal_unit_start}) <<" if h264_iframe

          {
            pid
            ts_packet
            ts_discontinuity_indicator
            ts_random_access_indicator
            pes_data_alignment_indicator
            h264_iframe
          }

For each received UDP packet we emit one message towards the sending side, with an array containing the series of `{pid,ts_packets}` from the input.

        r.emit 'ts_packets', ts_packets

        return

### Receiver startup

Asynchronously start the receiver,

      (do seem ->

binding it to the port and address
FIXME: exclusive is probably not needed

          yield promisify r, r.bind, {port, address, exclusive: false}

and if the source is marked `multicast`, make sure we register for membership on the destination address.

          r.addMembership address if multicast

If startup failed, exit the process.
FIXME: Should simply report the error if we allow to dynamically add/remove mappings.

      ).catch (error) ->
        console.error opts, error
        process.exit 1

Return the receiver.

      return r

Transcribe
----------

On the sending side, we handle events generated by the receiver, filtering on the PIDs we were told to monitor.

For each incoming UDP packet, we will send out a new UDP packet if data is available for at least one of the PIDs we are responsible for.

Note: we do not attempt to "optimize" things by packing multiple ES into a smaller number of UDP packets because:
- it would introduce jitter;
- video ES make up the bulk of content (audio, subtitles, PAT, PMT are much smaller), and in most cases we will have almost-full UDP packets.

    transcribe = (receiver,opts) ->
      {source,multicast,address,port,pids} = opts

Build a `Set` object in order to efficiently query the list of PIDs.

      my_pids = new Set pids

Create the outbound socket.

      t = dgram.createSocket source?.protocol ? 'udp4'

### Message handler

For each inbound UDP packet that was split into TS packets by the receiver,

      receiver.on 'ts_packets', (ts_packets) ->

our list of TS packets consists of
those TS packets whose PID are in our desired set

        my_packets = ts_packets
          .filter ({pid}) -> my_pids.has pid
          .map ({ts_packet}) -> ts_packet

If we have at least one TS packet to transmit,

        nb_packets = my_packets.length
        return unless nb_packets > 0

build the UDP packet by concatenating the TS packet in the order they were received,

        msg = Buffer.concat my_packets

and send the UDP packet out.
Note: this syntax is compatible with pre-5.5 Node.js, although one should probably not attempt to use such old versions in production.

        t.send msg, 0, nb_packets * TS_PACKET_LENGTH, port, address

Collect statistics.

        sent_udp++
        sent_ts += nb_packets

        return

### Startup

Asynchronously start the sender,

      (do seem ->

which only needs to be bound if the information was provided.

        if source?

We first bind the socket to the (optional) port and (optional) address,

          args = []
          args.push source.port if source.port?
          args.push source.address if source.address?
          yield promisify t, t.bind, args... if args.length > 0

and if the destination is multicast, we request multicast access on the corresponding interface.
Note: older Node.js do not support `setMulticastInterface`, again one should probably not use those older versions.

          t.setMulticastInterface? source.address if multicast

If startup failed, exit the process.
FIXME: Should simply report the error if we allow for dynamically add/remove mappings.

      ).catch (error) ->
        console.error opts, error
        process.exit 1

      return

Main
----


    main = seem (configuration) ->

Start the receiver

      r = yield receiver configuration.source

and a sending process for each sink.

      configuration.sinks.forEach (opts) -> transcribe r, opts

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
