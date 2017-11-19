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
    nextTick = -> new Promise process.nextTick

The whole problem is made simple by the fact that TS packets have a static length and are aligned on UDP packet boundaries.
This means we do not have to do framing inside the UDP packets, and deducing the number of TS packets in a UDP packet is trivial.
(See ITU H.220.0 for more information on TS.)

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

    crc32 = require './crc32'
    crc32_base = -1

    make_frame = (hdr,bdy) ->
      frame = Buffer.alloc TS_PACKET_LENGTH, 0xff
      hdr.copy frame, 0
      bdy.copy frame, hdr.length
      crc = crc32 bdy, crc32_base
      frame.writeInt32LE crc, hdr.length+bdy.length
      frame

Erase PID

    erase_pid = (ts_packet) ->
      pid_bytes = 0x1fff | ts_packet.readUInt16BE 1
      ts_packet.writeUInt16BE pid_bytes, 1
      ts_packet

Set PID

    set_pid = (ts_packet,pid) ->
      pid_bytes = (pid & 0x1fff) | (0xe000 & ts_packet.readUInt16BE 1)
      ts_packet.writeUInt16BE pid_bytes, 1

Set Continuity Counter

    set_cc = (ts_packet,ctx) ->
      ts_packet.wruiteUInt8 (ctx.cc + 0xf0 & ts_packet.readUInt8 3)
      ctx.cc = 0x0f & (ctx.cc+1)
      ts_packet

Not sure where this is defined, FFmpeg includes those at the top of their TS files.

    sdt_hdr = Buffer.from [
      0x47, 0x40, 0x11, 0x18 # PID 0x011
      0x00 # pointer
    ]
    sdt_bdy = Buffer.from [
      0x42 # SDT
      0xf0, 0x24 # Length: 36
      0x00, 0x01 # TS ID 1
      0xc1 # Currently applicable
      0x00, 0x00 # Section number, last section number

      0xff, 0x01 # Original network ID
      0xff # reserved
      0x00, 0x01 # Service ID 1
      0xfc
      0x80, 0x13 # Descriptors Loop Length: 0x013
      0x48 # Descriptor tag 0x48

      0x11 # Length (apparently not including the next octet?)
      0x01 # digitial television service
      0x05 # Provider name length
      0x4B, 0x2D, 0x73, 0x79, 0x73
      0x09 # Service name length
      0x53, 0x65, 0x72, 0x76, 0x69, 0x63, 0x65, 0x30, 0x31
    ]
    SDT = make_frame sdt_hdr, sdt_bdy

PAT structure from H.220.0

    pat_hdr = Buffer.from [
      0x47, 0x40, 0x00, 0x19 # PID 0x0 = PAT

H.220.0 section 2.4.4.1 table 2-29

      0x00 # PSI pointer

    ]
    pat_bdy = Buffer.from [

H.220.0 Table 2-30 page 49

      0x00 # Table ID: PAS (see H.220.0 section 2.4.4.4 table 2-31)
      0xb0, 0x0d # Length: 13 (including CRC, see H.220.0 2.4.4.5)
      0x00, 0x01 # TS ID 1
      0xc1 # version 0, currently applicable
      0x00 # section 0
      0x00 # last-section 0

      0x00, 0x01 # Program number 1
      0xf0, 0x00 # PMT PID 0x1000

    ]
    make_pat = ({pmt_pid},ctx) ->
      set_cc pat_hdr, ctx
      pat_bdy.writeUInt16BE 0xe000 | pmt_pid, 10
      make_frame pat_hdr, pat_bdy

    pmt_hdr = Buffer.from [
      0x47, 0x50, 0x00, 0x19 # PID 0x1000

H.220.0 section 2.4.4.1 table 2-29

      0x00 # PSI pointer

    ]
    pmt_bdy = Buffer.from [

Program Map Table per H.220.0 section 2.4.4.8

      0x02 # Table ID: PMT
      0xb0, 0x1c # Length: 28 (including CRC per H.220.0 2.4.4.9)
      0x00, 0x01 # Program number 1
      0xc1 # version 0, currently applicable
      0x00 # section 0
      0x00 # last-section 0

      0xe1, 0x00 # PCR PID: 0x0100
      0xf0, 0x00 # Program Info Length: 0 (no descriptors)
    ]
    make_pmt = (pids,{pmt_desc,pmt_pid,pcr_pid},ctx) ->
      set_pid pmt_hdr, pmt_pid
      set_cc pmt_hdr, ctx
      pmts = pids
        .map (pid) -> pmt_desc[pid]
        .filter (b) -> b?
      pmt_src = Buffer.concat [
        pmt_bdy
        pmts...
      ]
      pmt_src.writeUInt16BE 0xb000 + (pmt_src.length - 3) + 4, 1
      pmt_src.writeUInt16BE 0xe000 + pcr_pid, 8
      make_frame pmt_hdr, pmt_src

    receiver = seem (opts) ->
      {protocol,port,address,multicast,h264} = opts

      debug 'Starting receiver', opts

Set of PIDs that carry PMT.

      psi_pids = null

PCR estimator

      ### PCR_CLOCK_ESTIMATE
      non_pcr_packets = 0
      pcr_clock = null
      pcr_per_packet_estimate = null
      ###

PCR PID

      pcr_pid = null

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

        nb_packets = msg.length // TS_PACKET_LENGTH

Update statistics.

        received_udp++

Build the list of TS packets,

        ts_packets = [0...nb_packets].map (i) ->

          received_ts++

slicing the original (received) buffer into TS-packet-lenght chunks,

          ts_packet = msg.slice i*TS_PACKET_LENGTH, (i+1)*TS_PACKET_LENGTH

reading the header of each TS packet

          header = ts_packet.readUInt32BE 0

in order to extract the ES' PID;

          pid = (header & 0x001fff00) >> 8

#### PES Framing

The PUSI indicator is present on the first higher-protocol frame.

          pusi = (header & 0x00400000) > 0

For keyframe detection we parse the PES payload.

          ts_payload_offset = 4

First we figure out whether the adaptation field (H.220.0 section 2.4.3.4, table 2-6, page 25) is present

          adaptation_field_present = (header & 0x20) > 0
          payload_present = (header & 0x10) > 0

in which case we need to account for its length.

          p = 4

          ### PCR_CLOCK_ESTIMATE
          non_pcr_packets++
          ###

          if adaptation_field_present
            adaptation_field_length = ts_packet.readUInt8 p++
            ts_payload_offset += 1 + adaptation_field_length

In the first octet of the adaptation field itself we find the discontinuity indicator and the random access indicator
(these are normally only used with MPEG streams).

            adaptation_field = ts_packet.readUInt8 p++
            ts_discontinuity_indicator = (adaptation_field & 0x80) > 0
            ts_random_access_indicator = (adaptation_field & 0x40) > 0
            ts_pcr_flag = (adaptation_field & 0x10) > 0
            # ts_extension_flag = (adaptation_field & 0x01) > 0

            ### PCR_CLOCK_ESTIMATE
            if ts_discontinuity_indicator
              non_pcr_packets = 0
              pcr_clock = null
              # Keep the pcr_per_packet_estimate

            if ts_pcr_flag
              ts_pcr_high = ts_packet.readUInt32BE p
              p += 4
              ts_pcr_low = ts_packet.readUInt16BE p
              p += 2
              ts_bit = if ts_pcr_low & 0x8000 then 1 else 0
              clock = ts_pcr_high * 600 + ts_bit * 300 + (ts_pcr_low & 0x01ff)

              if non_pcr_packets > 0
                pcr_per_packet_estimate = clock / non_pcr_packets

              pcr_clock = clock
              non_pcr_packets = 0
            else
              if pcr_clock?
                if pcr_per_packet_estimate
                  pcr_clock += pcr_per_packet_estimate
                else
                  pcr_clock = null
            ###

          data = {
            pid
            ts_packet
            ts_discontinuity_indicator
            ts_random_access_indicator
            ts_pcr_flag
            pcr_pid
            # pcr_clock ### PCR_CLOCK_ESTIMATE
          }

          # console.log "TS #{received_ts} PID #{pid} pusi=#{pusi} disc=#{ts_discontinuity_indicator} rai=#{ts_random_access_indicator} pcr=#{ts_pcr_flag} #{pcr_pid}" if ts_pcr_flag

#### PSI

          if pusi and pid < 4 or psi_pids?.has pid

            pointer_field = ts_packet.readUInt8 ts_payload_offset
            psi_offset = ts_payload_offset + 1 + pointer_field

            table_id = ts_packet.readUInt8 psi_offset + 0
            # console.log "PSI #{table_id}", ts_packet.slice(psi_offset).toString 'hex'

#### PAT (H.220.0 section 2.4.4.3)

          if table_id is 0

            pat_len = 0x03ff & ts_packet.readUInt16BE psi_offset + 1
            nb_pmt = (pat_len - 4 - 5) // 4
            psi_pids = new Set [0...nb_pmt].map (i) ->
              0x1fff & ts_packet.readUInt16BE 4*i + psi_offset + 10

          if pid < 4
            return data

#### PMT

          if table_id is 2

            pmt_pid = pid

            section_length = 0x03ff & ts_packet.readUInt16BE psi_offset + 1
            info_len = 0x03ff & ts_packet.readUInt16BE psi_offset + 10

            pcr_pid = 0x07ff & ts_packet.readUInt16BE psi_offset + 8

            desc_start = psi_offset + 12 + info_len
            desc_end = desc_start + info_len

Map ES PIDs to their PMT (binary/Buffer) description

            pmt_desc = {}

            while desc_start < section_length - 4 - 9

              stream_type = ts_packet.readUInt8 desc_start + 0
              es_pid = 0x1fff & ts_packet.readUInt16BE desc_start + 1
              es_info_len = 0x0fff & ts_packet.readUInt16BE desc_start + 3

              next_start = desc_start + 5 + es_info_len
              pmt_desc[es_pid] = ts_packet.slice desc_start, next_start

              desc_start = next_start

            data.pmt_desc = pmt_desc
            data.pmt_pid = pmt_pid
            data.pcr_pid = pcr_pid

            r.emit 'pmt', data
            return data

#### PES only

          return data if table_id?

#### Keyframe detection

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

          data.pes_data_alignment_indicator = pes_data_alignment_indicator

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
              ts_packet.copy h264_buf, h264_last_pad.length, ts_payload_offset
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

          # console.log ">> H.264 I-Frame for PID #{pid} (#{pusi} #{h264_nal_unit_start} #{ts_pcr_flag}) <<" if h264_iframe

          data.h264_iframe = h264_iframe

          return data

For each received UDP packet we emit one message towards the sending side, with an array containing the series of `{pid,ts_packets}` from the input.

        r.emit 'ts_packets', ts_packets

        return

### Receiver startup

Asynchronously start the receiver,

binding it to the port and address
FIXME: exclusive is probably not needed

      yield promisify r, r.bind, {port, address, exclusive: false}

and if the source is marked `multicast`, make sure we register for membership on the destination address.

      r.addMembership address if multicast

Return the receiver.

      return r

Transcribe as UDP
-----------------

On the sending side, we handle events generated by the receiver, filtering on the PIDs we were told to monitor.

For each incoming UDP packet, we will send out a new UDP packet if data is available for at least one of the PIDs we are responsible for.

Note: we do not attempt to "optimize" things by packing multiple ES into a smaller number of UDP packets because:
- it would introduce jitter;
- video ES make up the bulk of content (audio, subtitles, PAT, PMT are much smaller), and in most cases we will have almost-full UDP packets.

    transcribe_as_udp = seem (receiver,opts) ->
      {source,multicast,address,port,pids} = opts

      debug 'Starting transcribe as UDP', opts

Build a `Set` object in order to efficiently query the list of PIDs.

      my_pids = new Set pids

Create the outbound socket.

      t = dgram.createSocket source?.protocol ? 'udp4'

### Message handler

      send = (packets) ->

If we have at least one TS packet to transmit,

        nb_packets = packets.length
        return unless nb_packets > 0

build the UDP packet by concatenating the TS packet in the order they were received,

        msg = Buffer.concat packets

and send the UDP packet out.
Note: this syntax is compatible with pre-5.5 Node.js, although one should probably not attempt to use such old versions in production.

        t.send msg, 0, nb_packets * TS_PACKET_LENGTH, port, address

Collect statistics.

        sent_udp++
        sent_ts += nb_packets
        return

      pmt_pid = null
      pat_buf = null
      pmt_buf = null
      pat_ctx = cc:0
      pmt_ctx = cc:0

      receiver.on 'pmt', (opts) ->
        {pmt_pid} = opts
        pat_buf = make_pat opts, pat_ctx
        pmt_buf = make_pmt pids, opts, pmt_ctx
        return

For each inbound UDP packet that was split into TS packets by the receiver,

      receiver.on 'ts_packets', (ts_packets) ->

our list of TS packets consists of
those TS packets whose PID are in our desired set

        send ts_packets.map (p) ->
          {pid,pcr_pid} = p
          pkt = p.ts_packet
          switch
            when pid is 0
              pat_buf ? erase_pid pkt
            when pid is pmt_pid
              pmt_buf ? erase_pid pkt
            when my_pids.has pid
              pkt
            else
              erase_pid pkt

        return

### Transcribe UDP: Startup

Asynchronously start the sender,
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

      return

Transcribe as HLS
-----------------

We're talking about [RFC8216](https://tools.ietf.org/html/rfc8216) here.

    fs = require 'fs'
    path = require 'path'

    transcribe_as_hls = seem (receiver,opts) ->
      {directory,m3u8,base_uri,target_duration,keep_segments,buffer_size,pids} = opts

      debug 'Starting transcribe as HLS', opts

Define defaults.

      m3u8 ?= 'channel.m3u8'
      base_uri ?= ''
      target_duration ?= 6000
      keep_segments ?= 5
      buffer_size ?= 1024*1024 # 4Mio

Build a `Set` object in order to efficiently query the list of PIDs.

      my_pids = new Set pids

Optionally create the directory if it does not exist (the parent directory must exist).

      yield (promisify fs, fs.mkdir, directory).catch -> yes

To meet the requirements of RFC8216 section 6.2.2, we keep a number of segments live.

      segments = []

      current_segment = {}

### Create a new TS file

In order to create a new TS file,

      rotate_ts_file = ->

build a timestamp for the file we are about to create,

        timestamp = Date.now()

and compute the duration of the current file (which we are about to close).

        if current_segment.timestamp?
          duration = timestamp - current_segment.timestamp
        else
          duration = target_duration

        current_segment.duration = duration

Make sure we only keep the number of segments we were asked to keep,

        if segments.length > keep_segments
          oldest_segment = segments.shift()
          heal promisify fs, fs.unlink, oldest_segment.full_path

and cleanup the segment data before we save it.

        old_file = current_segment.file
        current_segment.file = null

If there was indeed an open file,

        if old_file?

add its metadata to the list of segments served by the m3u8,

          segments.push current_segment

and close the current file

          heal nextTick()
            .then -> promisify old_file, old_file.end

then generate the new M3U8.

            .then generate_m3u8

Finally, proceed to create the new file,

        filename = "#{timestamp}.ts"
        full_path = path.join directory, filename
        file = fs.createWriteStream full_path

        target_timestamp = timestamp + target_duration

and record its metadata as the current segment.

        current_segment = {filename,timestamp,target_timestamp,full_path,file}
        return

#### Build an M3U8 playlist

      generate_m3u8 = seem ->
        m3u8_file = fs.createWriteStream path.join directory, m3u8
        yield promisify m3u8_file, m3u8_file.write, """
          #EXTM3U
          #EXT-X-VERSION:1
          #EXT-X-TARGETDURATION:#{target_duration//1000}
          #EXT-X-MEDIA-SEQUENCE:#{segments[0].timestamp}

        """
        for segment in segments
          yield promisify m3u8_file, m3u8_file.write, """
            #EXTINF:#{segment.duration//1000},
            #{base_uri}/#{segment.filename}

          """

        yield promisify m3u8_file, m3u8_file.end
        return

#### Process incoming data

For each inbound UDP packet that was split into TS packets by the receiver,

      ts_buf_len = TS_PACKET_LENGTH * (buffer_size // TS_PACKET_LENGTH)
      ts_buf = Buffer.alloc ts_buf_len
      ts_buf_index = 0

buffer up to `buffer_size` octets,

      ts_buf_append = (buf) ->
        # assert buf.length is TS_PACKET_LENGTH
        buf.copy ts_buf, ts_buf_index, 0, TS_PACKET_LENGTH
        ts_buf_index += TS_PACKET_LENGTH
        if ts_buf_index >= ts_buf_len
          ts_buf_flush()
        else
          Promise.resolve()

      ts_buf_flush = ->
        if ts_buf_index > 0
          save_buf = Buffer.from(ts_buf).slice 0, ts_buf_index
          ts_buf_index = 0
          if current_segment.file?
            return promisify current_segment.file, current_segment.file.write, save_buf
        Promise.resolve()

      pmt_pid = null
      pat_buf = null
      pmt_buf = null
      pat_ctx = cc:0
      pmt_ctx = cc:0

      receiver.on 'pmt', hand (opts) ->
        {pmt_pid} = opts
        pat_buf = make_pat opts, pat_ctx
        pmt_buf = make_pmt pids, opts, pmt_ctx
        if not current_segment.file?
          yield rotate_ts_file()
          yield ts_buf_append SDT
          yield ts_buf_append pat_buf
          yield ts_buf_append pmt_buf

      receiver.on 'ts_packets', hand (ts_packets) ->

        return unless pat_buf? and pmt_buf?

        current_ts = Date.now()

        for p in ts_packets
          pkt = p.ts_packet
          switch
            when p.pid is 0
              pkt = pat_buf
            when p.pid is pmt_pid
              pkt = pmt_buf
            when my_pids.has p.pid
              if p.h264_iframe and current_ts >= current_segment.target_timestamp
                heal ts_buf_flush()
                yield rotate_ts_file()
                yield ts_buf_append SDT
                yield ts_buf_append pat_buf
                yield ts_buf_append pmt_buf

            else
              erase_pid pkt

          heal ts_buf_append pkt

        return

      return

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
