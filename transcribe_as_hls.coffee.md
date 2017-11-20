Transcribe as HLS
-----------------

We're talking about [RFC8216](https://tools.ietf.org/html/rfc8216) here.

    seem = require 'seem'
    {debug,hand,heal} = (require 'tangible') 'wicked-credit:transcribe_as_hls'
    promisify = require './promisify'
    fs = require 'fs'
    path = require 'path'
    {make_sdt,make_pat,make_pmt} = require './tools'
    nextTick = -> new Promise process.nextTick

    TS_PACKET_LENGTH = 188

    module.exports =
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
          #EXT-X-VERSION:3
          #EXT-X-TARGETDURATION:#{target_duration//1000}
          #EXT-X-MEDIA-SEQUENCE:#{segments[0].timestamp}

        """
        for segment in segments
          yield promisify m3u8_file, m3u8_file.write, """
            #EXTINF:#{segment.duration/1000},
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
        if not buf?
          return Promise.resolve()

        # assert buf.length is TS_PACKET_LENGTH
        buf.copy ts_buf, ts_buf_index, 0, TS_PACKET_LENGTH
        ts_buf_index += TS_PACKET_LENGTH
        if ts_buf_index >= ts_buf_len
          ts_buf_flush()
        else
          Promise.resolve()

      ts_buf_flush = ->
        if not ts_buf_index > 0
          return Promise.resolve()

        actually_save = current_segment.file?
        if actually_save
          save_buf = Buffer.alloc ts_buf_index
          ts_buf.copy save_buf, 0, 0, ts_buf_index
        ts_buf_index = 0
        if actually_save
          return promisify current_segment.file, current_segment.file.write, save_buf
        Promise.resolve()

      pmt_pid = null
      last_opts = null

      sdt_ctx = cc:0
      pat_ctx = cc:0
      pmt_ctx = cc:0

      sdt = -> make_sdt sdt_ctx
      pat = -> if last_opts? then make_pat last_opts, pat_ctx else null
      pmt = -> if last_opts? then make_pmt pids, last_opts, pmt_ctx else null

Handle PMT indications
----------------------

      receiver.on 'pmt', hand (opts) ->
        {pmt_pid} = opts
        last_opts = opts
        if not current_segment.file?
          yield rotate_ts_file()
          yield ts_buf_append sdt()
          yield ts_buf_append pat()
          yield ts_buf_append pmt()
        return

For each inbound UDP packet that was split into TS packets by the receiver,

      last_ts_packet = null

      ts_packet_handler = seem (p,current_ts) ->
        if last_ts_packet and p.received_ts isnt last_ts_packet + 1
          debug "Out of order #{p.received_ts - last_ts_packet+1}"
        last_ts_packet = p.received_ts

        if p.h264_iframe and current_ts >= current_segment.target_timestamp
          heal ts_buf_flush()
          yield rotate_ts_file()
          yield ts_buf_append sdt()
          yield ts_buf_append pat()
          yield ts_buf_append pmt()

        {pid,pcr_pid} = p
        pkt = p.ts_packet
        pkt = switch
          when pid is 0
            pat()
          when pid is pmt_pid
            pmt()
          when pid is pcr_pid or my_pids.has pid
            pkt
          else
            null

        heal ts_buf_append pkt
        return

      receiver.on 'ts_packets', hand (ts_packets) ->

        return unless last_opts?

        current_ts = Date.now()

        for p in ts_packets
          yield ts_packet_handler p, current_ts
        return

      return

