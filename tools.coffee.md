    crc32 = require './crc32'
    crc32_base = -1

    TS_PACKET_LENGTH = 188

    make_frame = (hdr,bdy) ->
      frame = Buffer.alloc TS_PACKET_LENGTH, 0xff
      hdr.copy frame, 0
      bdy.copy frame, hdr.length
      crc = crc32 bdy, crc32_base
      frame.writeInt32LE crc, hdr.length+bdy.length
      frame

Set PID

    set_pid = (ts_packet,pid) ->
      pid_bytes = (pid & 0x1fff) | (0xe000 & ts_packet.readUInt16BE 1)
      ts_packet.writeUInt16BE pid_bytes, 1
      ts_packet

Set Continuity Counter

    set_cc = (ts_packet,ctx) ->
      ts_packet.writeUInt8 (ctx.cc & 0x0f) | (0xf0 & ts_packet.readUInt8 3), 3
      ctx.cc = 0x0f & (ctx.cc+1)
      ts_packet

Not sure where this is defined, FFmpeg includes those at the top of their TS files.

    sdt_hdr = Buffer.from [
      0x47, 0x40, 0x11, 0x10 # PID 0x011
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
    make_sdt = (ctx) ->
      set_cc sdt_hdr, ctx
      make_frame sdt_hdr, sdt_bdy

PAT structure from H.220.0

    pat_hdr = Buffer.from [
      0x47, 0x40, 0x00, 0x10 # PID 0x0 = PAT

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
      0x47, 0x50, 0x00, 0x10 # PID 0x1000

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


    module.exports = {make_sdt,make_pat,make_pmt}
