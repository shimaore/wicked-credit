    dgram = require 'dgram'
    seem = require 'seem'
    {debug,hand,heal} = (require 'tangible') 'wicked-credit:server'
    promisify = require './promisify'

    TS_PACKET_LENGTH = 188

The H.264 start code, which can be used (according to Annex B) to locate the start of a NAL Unit.

    H264_START_CODE = Buffer.from [0x00,0x00,0x00,0x01]

Some filler data that gets injected in the last-pad.
Since the last-pad must be long enough to cover the Start Code (4 octets), the NAL Unit Type (1 octet), and the extra octet needed by SEI/AUD, this means the filler must be six octets long.

    H264_FILLER     = Buffer.from [0xff,0xff,0xff,0xff,0xff,0xff]

Statistics

    received_udp = 0
    received_ts  = 0
    reporter = ->
      console.log """
        Received: #{received_udp} UDP, #{received_ts} TS.
      """
    # setInterval reporter, 1000

Receiver
--------

The receiver is responsible for handling incoming UDP packets, and split them into individual TS packets.

    module.exports =
    receiver = seem (opts) ->
      {protocol,port,address,multicast,h264} = opts

      debug 'Starting receiver', opts

Set of PIDs that carry PMT.

      psi_pids = new Set

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

slicing the original (received) buffer into TS-packet-length chunks,

          ts_packet = msg.slice i*TS_PACKET_LENGTH, (i+1)*TS_PACKET_LENGTH

reading the header of each TS packet

          header = ts_packet.readUInt32BE 0

          sync_byte = (header >> 24) & 0xff
          unless sync_byte is 0x47
            debug.dev "Invalid sync byte in header #{header.toString 16} (frame #{i}/#{nb_packets}, received #{received_udp} UDP / #{received_ts} TS) from #{rinfo.family}/#{rinfo.address}:#{rinfo.port}."
            return null

in order to extract the ES' PID;

          pid = (header & 0x001fff00) >> 8

          data = {
            pid
            ts_packet
            received_ts
          }

          transport_error = (header & 0x00800000)
          if transport_error
            debug.dev "PID #{pid}: Transport error."
            return data

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

            if ts_payload_offset > TS_PACKET_LENGTH
              debug.dev "PID #{pid}: Invalid ts_payload_offset #{ts_payload_offset}, adaptation field length is #{adaptation_field_length}."
              return data

In the first octet of the adaptation field itself we find the discontinuity indicator and the random access indicator
(these are normally only used with MPEG streams).

            adaptation_field = ts_packet.readUInt8 p++
            ts_discontinuity_indicator = (adaptation_field & 0x80) > 0
            ts_random_access_indicator = (adaptation_field & 0x40) > 0
            ts_pcr_flag = (adaptation_field & 0x10) > 0
            # ts_extension_flag = (adaptation_field & 0x01) > 0

            data.ts_discontinuity_indicator = ts_discontinuity_indicator
            data.ts_random_access_indicator = ts_random_access_indicator
            data.ts_pcr_flag                = ts_pcr_flag
            data.pcr_pid                    = pcr_pid

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

          # console.log "TS #{received_ts} PID #{pid} pusi=#{pusi} disc=#{ts_discontinuity_indicator} rai=#{ts_random_access_indicator} pcr=#{ts_pcr_flag} #{pcr_pid}" if ts_pcr_flag

#### PSI

          if pusi and pid < 4 or psi_pids?.has pid

            pointer_field = ts_packet.readUInt8 ts_payload_offset
            psi_offset = ts_payload_offset + 1 + pointer_field

            if psi_offset < TS_PACKET_LENGTH
              table_id = ts_packet.readUInt8 psi_offset + 0
              # console.log "PSI #{table_id}", ts_packet.slice(psi_offset).toString 'hex'
            else
              debug.dev "PID #{pid}: PSI Offset #{psi_offset} >= #{TS_PACKET_LENGTH}, pointer_field = #{pointer_field}"
              return data

#### PAT (H.220.0 section 2.4.4.3)

          if table_id is 0

            pat_len = 0x03ff & ts_packet.readUInt16BE psi_offset + 1
            nb_psi = (pat_len - 4 - 5) // 4
            # FIXME: This used to say   psi_pids = new Set …
            #        Replace with multiple receivers for TS pakcets and a generic Muxer (with the PSI table)?
            [0...nb_psi].forEach (i) ->
              psi_id = 0x1fff & ts_packet.readUInt16BE 4*i + psi_offset + 10
              unless psi_pids.has psi_id
                psi_pids.add psi_id
                debug "Added PSI ID #{psi_id}"

No further processing for PAT, CAT, TSDT or IPMP.

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

PSI are not PES, obviously.

          return data if table_id?

Nor are these (per table 2-3 of H.220.0).

          return data if pid < 16 or pid is 0x1fff

Nor are those used by DVB metadata, see [wikipedia](https://en.wikipedia.org/wiki/MPEG_transport_stream#cite_note-PID_used_by_DVB-10) which references in particular EN. 300 468 (v1.13.1 ed.). ETSI. 2012. p. 20.

          return data if pid < 32 or pid is 8187

          # FIXME: Really we should use the PMT to know which streams are PES.

#### Keyframe detection

          h264_nal_unit_start = null

          if pusi and payload_present

            if ts_payload_offset+3 > TS_PACKET_LENGTH
              debug.dev "PID #{pid}: Invalid ts_payload_offset #{ts_payload_offset}, adaptation field length is #{adaptation_field_length}."
              return data

The PES payload starts with 00 00 01 (packet start code prefix),

            pes_start = ts_packet.readUInt32BE ts_payload_offset

            if (pes_start & 0xffffff00) isnt 0x00000100
              debug.dev "PID #{pid}: Invalid PES start code prefix in #{pes_start.toString 16}."
              return data

while the fourth octet is the PES stream id

            pes_stream_id = ts_packet.readUInt8 ts_payload_offset + 3

and the fifth and sixth are the PES packet length (which for video tends to be zero).

If the PES indicates we are effectively dealing with video,

            if (pes_stream_id & 0xf0) is 0xe0 # video

              if ts_payload_offset+8 > TS_PACKET_LENGTH
                debug.dev "PID #{pid}: Invalid ts_payload_offset #{ts_payload_offset} to access PES stream."
                return data

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

              if pes_payload_offset > TS_PACKET_LENGTH
                debug.dev "PID #{pid}: Invalid or empty PES payload: pes_payload_offset #{pes_payload_offset}, pes_optional_field_length #{pes_optional_field_length}."
                return data

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
              h264_nal_unit_length = TS_PACKET_LENGTH-ts_payload_offset
              h264_nal_unit_length += h264_last_pad.length

and to get things started, look for an H.264 start code pattern in the buffer (per Annex B).

              h264_nal_unit_start = h264_buf.indexOf H264_START_CODE, 0

In both cases, save the last octets of the current buffer into the last-pad.

            ts_packet.copy h264_last_pad, 0, TS_PACKET_LENGTH-h264_last_pad.length, h264_last_pad.length

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

        r.emit 'ts_packets', ts_packets.filter (x) -> x?

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

