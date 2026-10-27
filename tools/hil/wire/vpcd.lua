-- vpcd.lua — Wireshark dissector for the vsmartcard VPCD protocol
-- (virtual smart card daemon), with NTAG424 APDU classification.
--
-- Protocol (vsmartcard vpcd): every message is [len:2 BE][payload].
--   payload len == 1 : power control from the reader daemon
--       0x00 = VPCD_OFF (no reply), 0x01 = VPCD_ON (ATR reply),
--       0x02 = VPCD_RESET (ATR reply). 0x04 observed on the
--       amperstrand ifd (presence probe; answered with ATR).
--   payload len  > 1 : APDU. reader->card = C-APDU; card->reader =
--       R-APDU (data + SW) or ATR (as power reply).
-- Direction: the vpcd daemon LISTENS on the configured TCP port; the
-- VICC bridge CONNECTS from an ephemeral port. dst==port => host->card.
--
-- Install: copy to ~/.local/lib/wireshark/plugins/ (or load per-run:
--   tshark -X lua_script:vpcd.lua -r capture.pcapng)
-- Ports are configurable: Edit->Preferences->Protocols->VPCD.

local vpcd = Proto("vpcd", "Virtual Smart Card Daemon (vpcd)")

-- preferences: comma-separated port list
local VPCD_PORTS = { 35963, 35967, 35970, 35971, 35973, 35974 }

local f_len    = ProtoField.uint16("vpcd.length", "Message length", base.DEC)
local f_dir    = ProtoField.string("vpcd.direction", "Direction")
local f_kind   = ProtoField.uint8("vpcd.kind", "Kind", base.HEX)
local f_ctrl   = ProtoField.string("vpcd.ctrl", "Control")
local f_cla    = ProtoField.uint8("vpcd.cla", "CLA", base.HEX)
local f_ins    = ProtoField.uint8("vpcd.ins", "INS", base.HEX)
local f_ins_name = ProtoField.string("vpcd.ins_name", "Command")
local f_p1p2   = ProtoField.uint16("vpcd.p1p2", "P1 P2", base.HEX)
local f_capdu  = ProtoField.bytes("vpcd.capdu", "C-APDU")
local f_rdata  = ProtoField.bytes("vpcd.rdata", "Response data")
local f_sw     = ProtoField.uint16("vpcd.sw", "Status word", base.HEX)
local f_swname = ProtoField.string("vpcd.sw_class", "Status class")

vpcd.fields = { f_len, f_dir, f_kind, f_ctrl, f_cla, f_ins, f_ins_name, f_p1p2, f_capdu, f_rdata, f_sw, f_swname }

local INS_NAMES = {
    [0x71] = "AuthFirst", [0xAF] = "AuthSecond/Chain", [0x60] = "GetVersion",
    [0xF5] = "GetFileSettings", [0x5F] = "ChangeFileSettings",
    [0xAD] = "ReadData", [0x8D] = "WriteData", [0xC4] = "ChangeKey",
    [0x64] = "GetKeySettings", [0x51] = "GetCardUid", [0x52] = "SetCardUid",
    [0x3C] = "ReadSig", [0xCD] = "CreateFile", [0xDF] = "DeleteFile",
    [0x6A] = "GetApplicationIds", [0x5A] = "SelectApplication",
    [0xA4] = "ISO-Select", [0xB0] = "ISO-ReadBinary", [0xD6] = "ISO-UpdateBinary",
    [0xCA] = "GetUid-Pseudo", [0x32] = "GetReadCounter",
}

local SW_NAMES = {
    [0x9000] = "OK",
    [0x9100] = "NTAG-OK",
    [0x91AF] = "ADDITIONAL-FRAME",
    [0x91AE] = "AUTH-ERROR",
    [0x91AD] = "AUTH-DELAY",
    [0x911E] = "INTEGRITY-ERROR",
    [0x9103] = "LENGTH-ERROR",
    [0x6982] = "SECURITY-NOT-SATISFIED",
    [0x6A82] = "FILE-NOT-FOUND",
    [0x6D00] = "INS-NOT-SUPPORTED",
    [0x6E00] = "CLA-NOT-SUPPORTED",
}

local function sw_name(sw)
    return SW_NAMES[sw] or string.format("0x%04X", sw)
end

-- a stream reassembler per conversation (vpcd frames may span segments)
local streams = {}  -- [conv_key] = { dir, buffer }

function vpcd.dissector(buffer, pinfo, tree)
    pinfo.cols.protocol = vpcd.name

    local src_port = pinfo.src_port
    local dst_port = pinfo.dst_port

    -- only claim traffic on configured ports (one side)
    -- the vpcd ifd LISTENS on the port (reader side): frames with
    -- src==port are reader->card (C-APDU / power); dst==port are the
    -- VICC's responses (R-APDU / ATR)
    local port = nil
    for _, p in ipairs(VPCD_PORTS) do
        if p == src_port then port = p; to_card = true end
        if p == dst_port then port = p; to_card = false end
    end
    if not port then return 0 end

    -- multi-segment frames: ask TCP to reassemble
    local offset = 0
    while offset < buffer:len() do
        if buffer:len() - offset < 2 then
            pinfo.desegment_len = 2 - (buffer:len() - offset)
            pinfo.desegment_offset = offset
            return
        end
        local mlen = buffer(offset, 2):uint()
        if buffer:len() - offset - 2 < mlen then
            pinfo.desegment_len = mlen - (buffer:len() - offset - 2)
            pinfo.desegment_offset = offset
            return
        end

        local payload = buffer(offset + 2, mlen)
        local subtree = tree:add(vpcd, buffer(offset, 2 + mlen),
            string.format("VPCD message (%d bytes)", mlen))
        subtree:add(f_len, mlen)
        subtree:add(f_dir, to_card and "Host -> Card" or "Card -> Host")

        if mlen == 1 then
            local ctrl = payload(0, 1):uint()
            local names = { [0] = "OFF", [1] = "ON", [2] = "RESET", [4] = "PROBE(ext)" }
            subtree:add(f_kind, payload(0, 1))
            subtree:add(f_ctrl, names[ctrl] or string.format("0x%02X", ctrl))
            pinfo.cols.info = string.format("Power %s", names[ctrl] or "?")
        else
            if to_card then
                -- C-APDU
                local t = subtree:add(f_capdu, payload)
                if mlen >= 5 then
                    local cla = payload(0, 1):uint()
                    local ins = payload(1, 1):uint()
                    t:add(f_cla, payload(0, 1))
                    t:add(f_ins, payload(1, 1))
                    t:add(f_ins_name, INS_NAMES[ins] or string.format("INS-%02X", ins))
                    if mlen >= 7 then
                        t:add(f_p1p2, payload(2, 2):uint())
                    end
                    pinfo.cols.info = string.format("C-APDU %s (%dB)",
                        INS_NAMES[ins] or string.format("%02X", ins), mlen)
                else
                    pinfo.cols.info = string.format("C-APDU short (%dB)", mlen)
                end
            else
                -- card -> host: R-APDU (data + SW) or ATR (starts 0x3B)
                local b0 = payload(0, 1):uint()
                if b0 == 0x3B and mlen < 40 then
                    subtree:add(f_rdata, payload)
                    pinfo.cols.info = string.format("ATR (%d bytes)", mlen)
                elseif mlen >= 2 then
                    local sw = payload(mlen - 2, 2):uint()
                    subtree:add(f_rdata, payload(0, mlen - 2))
                    subtree:add(f_sw, payload(mlen - 2, 2))
                    local name = sw_name(sw)
                    subtree:add(f_swname, name)
                    pinfo.cols.info = string.format("R-APDU %s (%dB data)",
                        name, mlen - 2)
                else
                    subtree:add(f_rdata, payload)
                    pinfo.cols.info = "R-APDU (short)"
                end
            end
        end
        offset = offset + 2 + mlen
    end
    return buffer:len()
end

-- register on the vpcd TCP ports (edit VPCD_PORTS above for your rig)
for _, p in ipairs(VPCD_PORTS) do
    DissectorTable.get("tcp.port"):add(p, vpcd)
end
