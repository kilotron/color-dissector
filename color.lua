--[[ CoLoR packet dissector

Setup:
If you go to Help –> About Wireshark –> Folders, you’ll find all the folders 
Wireshark reads Lua scripts from. Choose either the Personal Lua Plugins, 
Global Lua Plugins or Personal configuration folder. 
E.g. C:\Program Files\Wireshark\plugins\2.4.2 on Windows. The script will be
active when Wireshark is started. You have to restart Wireshark after you do
changes to the script, or reload all the Lua scripts with Ctrl + Shift + L.

Swich from big endian to little endian:
1. Seach (match case): "add", replace with: "add_le"
   Do NOT replace the "add" in last line:
   ip_proto:add(150, color_protocol)
   and the "add" in comment.
2. Search (match case): ":uint", replace with: ":le_uint"
   Do NOT replace the ":uint" in comment.

Swich from little endian to big endian:
1. Seach (match case): "add_le", replace with: "add"
   Do NOT replace the "add" in comment.
2. Search (match case): ":le_uint", replace with: ":uint"
   Do NOT replace the ":uint" in comment.

References:
    1. Wireshark’s Lua API Reference Manual
        https://www.wireshark.org/docs/wsdg_html_chunked/wsluarm_modules.html
    2. Creating a Wireshark dissector in Lua - part 1 (the basics)
        https://mika-s.github.io/wireshark/lua/dissector/2017/11/04/creating-a-wireshark-dissector-in-lua-1.html
    3. Creating a Wireshark dissector in Lua - part 2 (debugging and a more advanced dissector)
        https://mika-s.github.io/wireshark/lua/dissector/2017/11/06/creating-a-wireshark-dissector-in-lua-2.html
    4. Creating a Wireshark dissector in Lua - part 3 (parsing the payload)
        https://mika-s.github.io/wireshark/lua/dissector/2017/11/08/creating-a-wireshark-dissector-in-lua-3.html
--]]

local color_protocol = Proto("CoLoR", "CoLoR Protocol")

local version_package = ProtoField.uint8("color.version_package", "version_package", base.HEX)
local ttl = ProtoField.uint8("color.ttl", "Time to live", base.DEC)
local package_length = ProtoField.uint16("color.package_length", "Package Length", base.DEC)
local header_checksum = ProtoField.uint16("color.checksum", "Header Checksum", base.HEX)

-- GET packet
local mtu = ProtoField.uint16("color.mtu", "Maximum Transmission Unit", base.DEC)
local pid_num = ProtoField.uint8("color.pid_num", "Number of PIDs", base.DEC)
local flags = ProtoField.uint8("color.flags", "Flags", base.HEX)
local minimal_pid_cp = ProtoField.uint16("color.minimal_pid_cp", "Minimal PID Change Period", base.DEC)
local n_sid = ProtoField.bytes("color.n_sid", "N_SID", base.DASH)
local l_sid = ProtoField.bytes("color.l_sid", "L_SID", base.DASH)
local nid = ProtoField.bytes("color.nid", "NID", base.DASH)
local public_key_len = ProtoField.uint16("color.public_key_len", "Public Key Length", base.DEC)
local public_key = ProtoField.bytes("color.public_key", "Public Key", base.DASH)
local qos_len = ProtoField.uint8("color.qos_len", "QoS Length", base.DEC)
local qos_req = ProtoField.bytes("color.qos_req", "QoS Requirement", base.DASH)
local seg_id = ProtoField.uint32("color.seg_id", "Segment ID", base.HEX)
local pid = ProtoField.uint32("color.pid", "PID", base.HEX)

-- DATA packet
local header_length = ProtoField.uint8("color.header_len", "Header Length", base.DEC)
local pid_pt = ProtoField.uint8("color.pid_pt", "PID pointer", base.DEC)
local nid_provider = ProtoField.bytes("color.nid", "NID of Provider", base.DASH)
--[[
fields defined in GET packet:
    pid_num
    flags
    minimal_pid_cp
    n_sid
    l_sid
    nid
    qos_len
    qos_req
    seg_id
    pid
--]]
local hmac = ProtoField.uint32("color.hmac", "HMAC", base.HEX)
local data = ProtoField.none("color.data", "Data", base.HEX)

-- ANN packet
--[[
fields defined in GET packet:
    flags
    public_key_len
    public_key
--]]
local unit_px_num = ProtoField.uint8("color.unit_px_num", "unit_px_num", base.HEX)
local as_path_len = ProtoField.uint8("color.as_path_len", "AS Path Length", base.DEC)
local aid = ProtoField.uint8("color.asid", "ASID", base.HEX)
local px = ProtoField.uint16("color.px", "PX", base.HEX)
local unit_length = ProtoField.uint8("color.unit_len", "Unit Length", base.DEC)
local strategy_num = ProtoField.uint8("color.strategy_num", "Number of Strategy Units", base.DEC)
local strategy_tag = ProtoField.uint8("color.tag", "Tag", base.DEC)
local strategy_len = ProtoField.uint8("color.strategy_len", "Length", base.DEC)
local strategy_value = ProtoField.bytes("color.strategy_value", "Value", base.DASH)


-- CONTROL packet
--[[
fields defined in GET packet:
    nid
fields defined in DATA packet:
    header_length
fields defined in ANN packet:
    aid
    px
--]]
local ctrl_tag = ProtoField.uint8("color.control_tag", "Tag", base.DEC)
local ctrl_data_len = ProtoField.uint16("color.control_data_len", "Length of Control Message", base.DEC)
local sk = ProtoField.uint32("color.sk", "SK", base.HEX)
local ip = ProtoField.ipv4("color.ip", "IP address")
local security_level = ProtoField.uint8("color.secu_level", "Security Level", base.DEC)
local list_len = ProtoField.uint8("color.list_len", "Length of List", base.DEC)
local br_n = ProtoField.uint8("color.br_n", "BR No.", base.DEC)
local aw_asid = ProtoField.uint8("color.aw_asid", "ASID", base.DEC)
local aw_num = ProtoField.uint32("color.aw_num", "Number", base.DEC)

color_protocol.fields = {version_package, ttl, package_length, header_checksum,
    mtu, pid_num, flags, minimal_pid_cp, n_sid, l_sid, nid, public_key_len, 
    public_key, qos_len, qos_req, seg_id, pid, header_length, pid_pt, nid_provider,
    hmac, data, unit_px_num, as_path_len, aid, px, unit_length, strategy_num,
    strategy_tag, strategy_len, strategy_value, ctrl_tag, ctrl_data_len, sk, ip,
    security_level, list_len, br_n, aw_asid, aw_num
}

function get_packet_type_name(package)
    local packet_type_name = "Undefined"
    if package == 1 then
        packet_type_name = "ANN"
    elseif package == 2 then
        packet_type_name = "GET"
    elseif package == 3 then
        packet_type_name = "DATA"
    elseif package == 4 then
        packet_type_name = "CONTROL"
    end
    return packet_type_name
end

function get_flag_am_name(flag_AM)
    local name = "Undefined"
    if flag_AM == 1 then
        name = "ADD"
    elseif flag_AM == 2 then
        name = "UPDATE"
    elseif flag_AM == 3 then
        name = "REMOVE"
    end
    return name
end

function get_ctrl_tag_name(tag_value)
    local tag_name = {
        [1] = "CONFIG_RM", [2] = "CONFIG_RM_ACK", [3] = "CONFIG_BR", 
        [4] = "CONFIG_BR_ACK", [5] = "PROXY_REGISTER", [6] = "PROXY_REGISTER_REPLY", 
        [7] = "PROXY_REGISTER_REPLY_ACK", [8] = "CONFIG_PROXY", 
        [9] = "CONFIG_PROXY_ACK", [10] = "CONFIG_RM_STRATEGY", 
        [11] = "CONFIG_RM_STRATEGY_ACK", [16] = "ODC_ADD_ENTRY", [17] = "ODC_WARNING",
        [18] = "ATTACK_WARNING"
    }
    if tag_name[tag_value] ~= nil then
        return tag_name[tag_value]
    else
        return "Undefined"
    end
end

function tvbrange_format_binary(tvbrange, position, length)
    local str = ""
    for i = 0, length - 1 do
        str = str .. tvbrange:bitfield(position + i)
    end
    return str
end

function flag_description(flag, position, desc)
    local str_dot = ".... ...."
    local str = ""
    if position < 4 then
        str = str_dot:sub(1, position) .. flag .. str_dot:sub(position + 2)
    else
        str = str_dot:sub(1, position + 1) .. flag .. str_dot:sub(position + 3)
    end
    str = str .. " = " .. desc .. ": "
    if flag == 1 then
        str = str .. "Set"
    else
        str = str .. "Not set"
    end
    return str
end

-- Checksum for CoLoR packet only
-- checksum_offset: the offset of checksum field
function cksum(buffer, len, checksum_offset)
    local sum = 0
    local position = 0
    while len > 1 do
        -- If you remove the following if statement,
        -- the checksum is correct if it equals 0xffff.
        if position ~= checksum_offset then
            sum = sum + buffer(position, 2):le_uint()
        end
        len = len - 2
        position = position + 2
    end
    if len == 1 then
        sum = sum + buffer(position, 1):le_uint()
    end
    sum = bit.rshift(sum, 16) + bit.band(sum, 0xffff)
    sum = bit.rshift(sum, 16) + bit.band(sum, 0xffff)
    return bit.bxor(sum, 0xffff) -- ~sum
end

function color_protocol.dissector(buffer, pinfo, tree)
    pinfo.cols.protocol = color_protocol.name

    local subtree = tree:add_le(color_protocol, buffer(), "CoLoR Protocol Data")

    if buffer:len() < 8 then
        subtree:add_le(color_protocol, buffer(), "MALFORMED PACKET: length less than 8 bytes")
        return
    end

    -- Version
    local version = buffer(0, 1):bitfield(0, 4)
    local version_str = tvbrange_format_binary(buffer(0, 1), 0, 4) .. 
                        " .... = Version: " .. buffer(0, 1):bitfield(0, 4)
    subtree:add_le(version_package, buffer(0, 1)):set_text(version_str)

    -- Package
    local package = buffer(0, 1):bitfield(4, 4)
    local packet_type_name = get_packet_type_name(package)
    local packet_type_str = ".... " .. tvbrange_format_binary(buffer(0, 1), 4, 4) ..
                            " = Package: " .. buffer(0, 1):bitfield(4, 4) ..
                            " (" .. packet_type_name .. ")"
    subtree:add_le(version_package, buffer(0, 1)):set_text(packet_type_str)
    subtree:add_le(ttl, buffer(1, 1))

    if packet_type_name == "CONTROL" then
        local hdr_len = buffer(4, 1):le_uint()
        local calculated_cksum = cksum(buffer, hdr_len, 2)
        local cksum_item = subtree:add_le(header_checksum, buffer(2, 2))
        if calculated_cksum == buffer(2, 2):le_uint() then
            cksum_item:append_text(" [correct]")
        else
            cksum_item:append_text(" [incorrect]")
        end
        subtree:add_le(header_checksum, buffer(2, 2)):set_text("[Calculated Checksum: " ..
            string.format("0x%04x", calculated_cksum) .. "]")
        subtree:add_le(header_length, buffer(4, 1)):append_text(" bytes")
        local ctrl_tag_value = buffer(5, 1):le_uint()
        local ctrl_tag_str = get_ctrl_tag_name(ctrl_tag_value)
        pinfo.cols.info = 'CONTROL packet: ' .. ctrl_tag_str
        subtree:add_le(ctrl_tag, buffer(5, 1)):append_text(" (" .. ctrl_tag_str .. ")")
        subtree:add_le(ctrl_data_len, buffer(6, 2)):append_text(" bytes")
        local ctrl_data_len_value = buffer(6, 2):le_uint()
        if ctrl_tag_str == "CONFIG_RM" then
            subtree:add_le(nid, buffer(8, 16))
            subtree:add_le(aid, buffer(24, 1))
            subtree:add_le(security_level, buffer(25, 1))
            subtree:add_le(sk, buffer(26, 4))
            local br_list_num = buffer(30, 1):le_uint()
            subtree:add_le(list_len, buffer(30, 1)):set_text("Length of BR List: " .. br_list_num)
            local offset = 31
            for i = 1, br_list_num do
                local br_info_subtree = subtree:add_le(color_protocol, buffer(offset, 21), "BR Info Item")
                br_info_subtree:add_le(br_n, buffer(offset, 1))
                br_info_subtree:add_le(nid, buffer(offset + 1, 16))
                br_info_subtree:add_le(ip, buffer(offset + 17, 4))
                offset = offset + 21
            end
            local as_br_px_num = buffer(offset, 1):le_uint()
            subtree:add_le(list_len, buffer(offset, 1)):set_text("Length of AS-BR-PX List: " .. as_br_px_num)
            offset = offset + 1
            for i = 1, as_br_px_num do
                -- calculate the length of the item
                local abp_item_len = 3 -- aid, security_level, br_px_num
                local br_px_num = buffer(offset + 2, 1):le_uint()
                for j = 1, br_px_num do
                    abp_item_len = abp_item_len + 1 -- br_n
                    local num_px = buffer(offset + abp_item_len, 1):le_uint()
                    abp_item_len = abp_item_len + 1 + num_px * 2 -- num_px, px
                end
                 --End of calculate the length of the item
                local abp_subtree = subtree:add_le(color_protocol, buffer(offset, abp_item_len), "AS-BR-PX Item")
                abp_subtree:add_le(aid, buffer(offset, 1))
                offset = offset + 1
                abp_subtree:add_le(security_level, buffer(offset, 1))
                offset = offset + 1
                abp_subtree:add_le(list_len, buffer(offset, 1)):set_text("Length of BR-PX List: " .. br_px_num)
                offset = offset + 1
                for j = 1, br_px_num do
                    -- calculate the length of br_px item
                    local num_px = buffer(offset + 1, 1):le_uint()
                    local bp_item_len = 2 + num_px * 2
                    --End of calculate the length of br_px item

                    local bp_subtree = abp_subtree:add_le(color_protocol, buffer(offset, bp_item_len), "BR-PX Item")
                    bp_subtree:add_le(br_n, buffer(offset, 1))
                    offset = offset + 1
                    bp_subtree:add_le(list_len, buffer(offset, 1)):set_text("Number of PXs: " .. num_px)
                    offset = offset + 1
                    for k = 1, num_px do
                        bp_subtree:add_le(px, buffer(offset, 2)):set_text("PX " .. k .. ": " .. 
                            string.format("0x%04x", buffer(offset, 2):le_uint()))
                    end
                end
            end
        elseif ctrl_tag_str == "CONFIG_RM_ACK" then
            -- No data
        elseif ctrl_tag_str == "CONFIG_BR" then
            subtree:add_le(nid, buffer(8, 16))
            subtree:add_le(sk, buffer(24, 4))
            local api_item_len = buffer(28, 1):le_uint()
            subtree:add_le(list_len, buffer(28, 1)):set_text("Length of AS-PX-IP List: " .. api_item_len)
            local offset = 29
            for i = 1, api_item_len do
                local api_subtree = subtree:add_le(color_protocol, buffer(offset, 7), "AS-PX_IP Item")
                api_subtree:add_le(aid, buffer(offset, 1))
                api_subtree:add_le(px, buffer(offset + 1, 2))
                api_subtree:add_le(ip, buffer(offset + 3, 4))
                offset = offset + 7
            end
        elseif ctrl_tag_str == "CONFIG_BR_ACK" then
            -- No data
        elseif ctrl_tag_str == "PROXY_REGISTER" then
            subtree:add_le(ip, buffer(8, 4))
            subtree:add_le(nid, buffer(12, 16))
        elseif ctrl_tag_str == "PROXY_REGISTER_REPLY" then
            local nid_ip_num = buffer(8, 1):le_uint()
            subtree:add_le(list_len, buffer(8, 1)):set_text("Length of NID-IP List: " .. nid_ip_num)
            local offset = 9
            for i = 1, nid_ip_num do
                local nid_ip_subtree = subtree:add_le(color_protocol, buffer(offset, 20), "NID-IP Item")
                nid_ip_subtree:add_le(nid, buffer(offset, 16))
                nid_ip_subtree:add_le(ip, buffer(offset + 16, 4))
                offset = offset + 20
            end
            local px_ip_num = buffer(offset, 1):le_uint()
            subtree:add_le(list_len, buffer(offset, 1)):set_text("Length of PX-IP List: " .. px_ip_num)
            offset = offset + 1
            for i = 1, px_ip_num do
                local px_ip_subtree = subtree:add_le(color_protocol, buffer(offset, 6), "PX-IP Item")
                px_ip_subtree:add_le(px, buffer(offset, 2))
                px_ip_subtree:add_le(ip, buffer(offset + 2, 4))
                offset = offset + 6
            end
        elseif ctrl_tag_str == "PROXY_REGISTER_REPLY_ACK" then
            -- No data
        elseif ctrl_tag_str == "CONFIG_PROXY" then
            subtree:add_le(ip, buffer(8, 4))
            subtree:add_le(nid, buffer(12, 16))
        elseif ctrl_tag_str == "CONFIG_PROXY_ACK" then
            -- No data
        elseif ctrl_tag_str == "CONFIG_RM_STRATEGY" then
            subtree:add_le(color_protocol, buffer(8)):set_text("Not supported!")
        elseif ctrl_tag_str == "CONFIG_RM_STRATEGY_ACK" then
            -- No data
        elseif ctrl_tag_str == "ODC_ADD_ENTRY" then
            subtree:add_le(nid, buffer(8, 16))
            subtree:add_le(l_sid, buffer(24, 20))
        elseif ctrl_tag_str == "ODC_WARNING" then
            subtree:add_le(color_protocol, buffer(8, 20), "IP header")
            subtree:add_le(color_protocol, buffer(28), "DATA header")
        elseif ctrl_tag_str == "ATTACK_WARNING" then
            if (ctrl_data_len_value < 16 or (ctrl_data_len_value - 16) % 5 ~= 0) then
                subtree:add_le(color_protocol, buffer(6, 2), 
                    "[Incorrect length]: Length should be more than 16 and (Length - 16) is multiples of 5.")
                return
            end
            subtree:add_le(nid, buffer(8, 16))
            local aw_offset = 24
            while aw_offset < buffer:len() do
                aw_subtree = subtree:add_le(color_protocol, buffer(aw_offset, 5), "AS Attack Summary")
                aw_subtree:add_le(aw_asid, buffer(aw_offset, 1))
                aw_subtree:add_le(aw_num, buffer(aw_offset + 1, 4))
                aw_offset = aw_offset + 5
            end -- end of while
        end -- elseif ctrl_tag_str == "ATTACK_WARNING"
        return 
    end --End of CONTROL packet

    local package_length_value = buffer(2, 2):le_uint()
    subtree:add_le(package_length, buffer(2, 2)):append_text(" bytes")

    if package_length_value ~= buffer:len() then
        subtree:add_le(color_protocol, buffer(0), "[Inconsistent packet length]: " .. 
            "Package length: " .. package_length_value .. " bytes, " ..
            "Buffer length: " .. buffer:len() .. " bytes")
        return
    end

    -- Checksum
    local hdr_len = package_length_value
    if packet_type_name == "DATA" then
        hdr_len = buffer(6, 1):le_uint()
    end
    local calculated_cksum = cksum(buffer, hdr_len, 4)
    local cksum_item = subtree:add_le(header_checksum, buffer(4, 2))
    if calculated_cksum == buffer(4, 2):le_uint() then
        cksum_item:append_text(" [correct]")
    else
        cksum_item:append_text(" [incorrect]")
    end
    subtree:add_le(header_checksum, buffer(4, 2)):set_text("[Calculated Checksum: " ..
        string.format("0x%04x", calculated_cksum) .. "]")

    if packet_type_name == "GET" then
        pinfo.cols.info = "GET packet"
        local offset = 64
        local buffer_length = buffer:len()
        if buffer_length < offset then
            subtree:add_le(color_protocol, buffer(), "MALFORMED PACKET: length" ..
                " less than " .. offset .. " bytes")
            return
        end
        
        subtree:add_le(mtu, buffer(6, 2))
        subtree:add_le(pid_num, buffer(8, 1))
        local pid_num_value = buffer(8, 1):le_uint()
        
        -- Flags
        local flag_subtree = subtree:add_le(color_protocol, buffer(9, 1), "Flags")
        flag_subtree:append_text(string.format(": 0x%02x", buffer(9, 1):le_uint()))
        
        local flag_F = buffer(9, 1):bitfield(0)
        local flag_K = buffer(9, 1):bitfield(1)
        local flag_Q = buffer(9, 1):bitfield(2)
        local flag_S = buffer(9, 1):bitfield(3)
        local flag_A = buffer(9, 1):bitfield(4)

        local flag_F_text = flag_description(flag_F, 0, "From other domain")
        local flag_K_text = flag_description(flag_K, 1, "public Key")
        local flag_Q_text = flag_description(flag_Q, 2, "QoS")
        local flag_S_text = flag_description(flag_S, 3, "Segment ID")
        local flag_A_text = flag_description(flag_A, 4, "ACK is supported")

        flag_subtree:add_le(flags, buffer(9, 1)):set_text(flag_F_text)
        flag_subtree:add_le(flags, buffer(9, 1)):set_text(flag_K_text)
        flag_subtree:add_le(flags, buffer(9, 1)):set_text(flag_Q_text)
        flag_subtree:add_le(flags, buffer(9, 1)):set_text(flag_S_text)
        flag_subtree:add_le(flags, buffer(9, 1)):set_text(flag_A_text)

        local flag_reserved_text = 
            ".... ." .. tvbrange_format_binary(buffer(9, 1), 5, 3) .. " = Reserved"
        flag_subtree:add_le(flags, buffer(9, 1)):set_text(flag_reserved_text)

        -- Make sure the length of the packet is correct.
        if flag_K == 1 then
            if buffer_length < offset + 2 then
                subtree:add_le(color_protocol, buffer(), "MALFORMED PACKET: length" ..
                " less than " .. (offset + 2).. " bytes")
                return
            end
            public_key_len_value = buffer(offset, 2):le_uint()
            offset = offset + 2 + public_key_len_value
        end

        if flag_Q == 1 then
            if buffer_length < offset + 1 then
                subtree:add_le(color_protocol, buffer(), "MALFORMED PACKET: length" ..
                " less than " .. (offset + 1).. " bytes")
                return
            end
            qos_len_value = buffer(offset, 1):le_uint() / 8
            offset = offset + 1 + qos_len_value
        end

        -- segment id
        if flag_S == 1 then
            offset = offset + 4
        end

        offset = offset + pid_num_value * 4
        if buffer_length < offset then
            subtree:add_le(color_protocol, buffer(), "MALFORMED PACKET: length" ..
                " less than " .. offset .. " bytes")
            return
        elseif buffer_length > offset then
            subtree:add_le(color_protocol, buffer(), "MALFORMED PACKET: length" ..
                " more than " .. offset .. " bytes")
            return
        end
        --[End] Make sure the length of the packet is correct.

        subtree:add_le(minimal_pid_cp, buffer(10, 2))
        subtree:add_le(n_sid, buffer(12, 16))
        subtree:add_le(l_sid, buffer(28, 20))
        subtree:add_le(nid, buffer(48, 16))

        offset = 64
        
        -- optional fields
        -- TODO：test optional fields 
        if flag_K == 1 then
            subtree:add_le(public_key_len, buffer(offset, 2)):append_text(" bytes")
            offset = offset + 2
            subtree:add_le(public_key, buffer(offset, public_key_len_value))
            offset = offset + public_key_len_value
        end

        if flag_Q == 1 then
            subtree:add_le(qos_len, buffer(offset, 1)):append_text(" bytes")
            offset = offset + 1
            subtree:add_le(qos_req, buffer(offset, qos_len_value))
            offset = offset + qos_len_value
        end

        if flag_S == 1 then
            subtree:add_le(seg_id, buffer(offset, 4))
            pinfo.cols.info:append(', Segment ID: ' .. string.format('0x%08x', buffer(offset, 4):le_uint()))
            offset = offset + 4
        end

        -- PIDs
        pid_text = "PIDs (Number of PIDs: " .. pid_num_value .. ")"
        pid_subtree = subtree:add_le(color_protocol, buffer(offset, 4 * pid_num_value), pid_text)
        for i = 1, pid_num_value do
            pid_subtree:add_le(pid, buffer(offset, 4)):set_text("PID " .. i .. ": " .. 
                string.format("0x%08x", buffer(offset, 4):le_uint()))
            offset = offset + 4
        end
    elseif packet_type_name == "DATA" then
        pinfo.cols.info = "DATA packet"
        local buffer_length = buffer:len()
        if buffer_length < 60 then
            subtree:add_le(color_protocol, buffer(), "MALFORMED PACKET: length" ..
                " less than 60 bytes")
            return
        end

        local header_length_value = buffer(6, 1):le_uint()
        local pid_pt_value = buffer(7, 1):le_uint()
        local pid_num_value = buffer(8, 1):le_uint()
        subtree:add_le(header_length, buffer(6, 1)):append_text(" bytes")
        subtree:add_le(pid_pt, buffer(7, 1))
        subtree:add_le(pid_num, buffer(8, 1))

        -- Flags
        local flag_F = buffer(9, 1):bitfield(0)
        local flag_B = buffer(9, 1):bitfield(1)
        local flag_R = buffer(9, 1):bitfield(2)
        local flag_M = buffer(9, 1):bitfield(3)
        local flag_Q = buffer(9, 1):bitfield(4)
        local flag_C = buffer(9, 1):bitfield(5)
        local flag_S = buffer(9, 1):bitfield(6)

        local flag_subtree = subtree:add_le(color_protocol, buffer(9, 1), "Flags")
        if flag_B == 1 then
            pinfo.cols.info:append(" (ACK)")
            flag_subtree:append_text(string.format(": 0x%02x (ACK)", buffer(9, 1):le_uint()))
        else
            flag_subtree:append_text(string.format(": 0x%02x", buffer(9, 1):le_uint()))
        end

        local flag_F_text = flag_description(flag_F, 0, "From other domain")
        local flag_B_text = flag_description(flag_B, 1, "ACK packet")
        local flag_R_text = flag_description(flag_R, 2, "Reverse PID calculation required")
        local flag_M_text = flag_description(flag_M, 3, "Minimal PID change period")
        local flag_Q_text = flag_description(flag_Q, 4, "QoS")
        local flag_C_text = flag_description(flag_C, 5, "HMAC(C)")
        local flag_S_text = flag_description(flag_S, 6, "Segment ID")
        
        flag_subtree:add_le(flags, buffer(9, 1)):set_text(flag_F_text)
        flag_subtree:add_le(flags, buffer(9, 1)):set_text(flag_B_text)
        flag_subtree:add_le(flags, buffer(9, 1)):set_text(flag_R_text)
        flag_subtree:add_le(flags, buffer(9, 1)):set_text(flag_M_text)
        flag_subtree:add_le(flags, buffer(9, 1)):set_text(flag_Q_text)
        flag_subtree:add_le(flags, buffer(9, 1)):set_text(flag_C_text)
        flag_subtree:add_le(flags, buffer(9, 1)):set_text(flag_S_text)

        local flag_reserved_text = 
            ".... ..." .. tvbrange_format_binary(buffer(9, 1), 7, 1) .. " = Reserved"
        flag_subtree:add_le(flags, buffer(9, 1)):set_text(flag_reserved_text)

        -- Make sure the length of the packet is correct.
        local offset = 10
        if flag_M == 1 then
            offset = offset + 2
        end

        offset = offset + 52

        -- provider nid
        if flag_B == 0 and flag_R == 1 then
            offset = offset + 16
        end

        if flag_Q == 1 then
            if buffer_length < offset + 1 then
                subtree:add_le(color_protocol, buffer(), "MALFORMED PACKET: length" ..
                " less than " .. (offset + 1).. " bytes")
                return
            end
            qos_len_value = buffer(offset, 1):le_uint() / 8
            offset = offset + 1 + qos_len_value
        end

        -- hmac
        if flag_C == 1 then
            offset = offset + 4
        end

        -- segment id
        if flag_S == 1 then
            offset = offset + 4
        end

        offset = offset + pid_num_value * 4
        
        -- backward pid
        if flag_B == 0 and flag_R == 1 then
            offset = offset + 4
        end

        if header_length_value ~= offset then
            subtree:add_le(color_protocol, buffer(), "[Inconsistent header length]: " ..
                "Header Length: " .. header_length_value .. " bytes, " ..
                "Actual header length: " .. offset .. " bytes")
        end
        --[End] Make sure the length of the packet is correct.

        offset = 10

        -- TODO：test optional fields 
        if flag_M == 1 then
            subtree:add_le(minimal_pid_cp, buffer(offset, 2))
            offset = offset + 2
        end

        subtree:add_le(n_sid, buffer(offset, 16))
        offset = offset + 16
        subtree:add_le(l_sid, buffer(offset, 20))
        offset = offset + 20
        subtree:add_le(nid, buffer(offset, 16))
        offset = offset + 16

        if flag_B == 0 and flag_R == 1 then
            subtree:add_le(nid_provider, buffer(offset, 16))
            offset = offset + 16
        end

        -- TODO：test optional fields 
        if flag_Q == 1 then
            subtree:add_le(qos_len, buffer(offset, 1)):append_text(" bytes")
            qos_len_value = buffer(offset, 1):le_uint()
            offset = offset + 1
            subtree:add_le(qos_req, buffer(offset, qos_len_value))
            offset = offset + qos_len_value
        end

        if flag_C == 1 then
            subtree:add_le(hmac, buffer(offset, 4))
            offset = offset + 4
        end

        if flag_S == 1 then
            subtree:add_le(seg_id, buffer(offset, 4))
            pinfo.cols.info:append(', Segment ID: ' .. string.format('0x%08x', buffer(offset, 4):le_uint()))
            offset = offset + 4
        end

        -- PIDs
        pid_text = "PIDs (Number of PIDs: " .. pid_num_value .. ", PID pointer: " .. 
            pid_pt_value .. ")"
        pid_subtree = subtree:add_le(color_protocol, buffer(offset, 4 * pid_num_value), pid_text)
        for i = 1, pid_num_value do
            local pid_text = "PID " .. i .. ": " .. 
                string.format("0x%08x", buffer(offset, 4):le_uint())
            if pid_pt_value == i then
                pid_text = "*" .. pid_text
            else
                pid_text = " " .. pid_text
            end
            pid_subtree:add_le(pid, buffer(offset, 4)):set_text(pid_text)
            offset = offset + 4
        end

        if flag_B == 0 and flag_R == 1 then
            local pid_text = "Reserved PID: " .. 
                string.format("0x%08x", buffer(offset, 4):le_uint())
            subtree:add_le(nid_provider, buffer(offset, 4)):set_text(pid_text)
            offset = offset + 4
        end

        if header_length_value < package_length_value then
            local data_len = package_length_value - header_length_value
            local s = subtree:add_le(data, buffer(offset))
            s:append_text(": " .. data_len .. " bytes")
            if flag_B == 1 then
                s:append_text(" (ACK packet should not carry data)")
            end
        end

    elseif packet_type_name == "ANN" then
        pinfo.cols.info = "ANN"
        buffer_length = buffer:len()
        if buffer_length < 8 then
            subtree:add_le(color_protocol, buffer(), "MALFORMED PACKET: length" ..
                " less than 8 bytes")
            return
        end

        -- Flags
        local flag_F = buffer(6, 1):bitfield(0)
        local flag_K = buffer(6, 1):bitfield(1)
        local flag_P = buffer(6, 1):bitfield(2)
        local flag_subtree = subtree:add_le(color_protocol, buffer(6, 1), "Flags")
        flag_subtree:append_text(string.format(": 0x%02x", buffer(6, 1):le_uint()))

        local flag_F_text = flag_description(flag_F, 0, "From other domain")
        local flag_K_text = flag_description(flag_K, 1, "public Key")
        local flag_P_text = flag_description(flag_P, 2, "AS Path")
        
        flag_subtree:add_le(flags, buffer(6, 1)):set_text(flag_F_text)
        flag_subtree:add_le(flags, buffer(6, 1)):set_text(flag_K_text)
        flag_subtree:add_le(flags, buffer(6, 1)):set_text(flag_P_text)

        local flag_reserved_text = 
            "..." .. buffer(6, 1):bitfield(3) .. " " .. 
            tvbrange_format_binary(buffer(6, 1), 4, 4) .. " = Reserved"
        flag_subtree:add_le(flags, buffer(6, 1)):set_text(flag_reserved_text)
        
         -- Number of Announce Units
        local unit_num = buffer(7, 1):bitfield(0, 4)
        local unit_num_str = tvbrange_format_binary(buffer(7, 1), 0, 4) .. 
                            " .... = Number of Announce Units: " .. 
                            buffer(7, 1):bitfield(0, 4)
        subtree:add_le(unit_px_num, buffer(7, 1)):set_text(unit_num_str)

        -- Number of PXs
        local px_num = buffer(7, 1):bitfield(4, 4)
        local px_num_str = ".... " .. tvbrange_format_binary(buffer(7, 1), 4, 4) ..
                            " = Number of PXs: " .. buffer(7, 1):bitfield(4, 4) 
        subtree:add_le(unit_px_num, buffer(7, 1)):set_text(px_num_str)
         
        -- Announce Units
        -- Check if the packet length is correct
        local offset = 8
        for i = 1, unit_num do
            if buffer_length < offset + 2 then
                subtree:add_le(color_protocol, buffer(), "MALFORMED PACKET: length" ..
                    " less than " .. (offset + 2) .. " bytes")
                return
            end
            local unit_len_value = buffer(offset + 1, 1):le_uint()
            offset = offset + unit_len_value
            if buffer_length < offset then
                subtree:add_le(color_protocol, buffer(), "MALFORMED PACKET: length" ..
                    " less than " .. offset .. " bytes")
                return
            end
        end
        --[End] Check if the packet length is correct

        offset = 8
        for i = 1, unit_num do
            local unit_len_value = buffer(offset + 1, 1):le_uint()
            local strategy_num_value = buffer(offset + 2, 1):le_uint()
            local announce_subtree = subtree:add_le(color_protocol, buffer(offset, unit_len_value),
                "Announce Unit " .. i)
           
            local flag_subtree = announce_subtree:add_le(color_protocol, buffer(offset, 1), "Flags")
            flag_subtree:append_text(string.format(": 0x%02x", buffer(offset, 1):le_uint()))
           
            local flag_N = buffer(offset, 1):bitfield(0)
            local flag_L = buffer(offset, 1):bitfield(1)
            local flag_I = buffer(offset, 1):bitfield(2)
            local flag_AM = buffer(offset, 1):bitfield(3, 2)

            local flag_N_text = flag_description(flag_N, 0, "N_SID")
            local flag_L_text = flag_description(flag_L, 1, "L_SID")
            local flag_I_text = flag_description(flag_I, 2, "NID")
            local flag_AM_text = "..." .. buffer(offset, 1):bitfield(3) ..
                " " .. buffer(offset, 1):bitfield(4) .. "... = AM: " ..
                flag_AM .. " (" .. get_flag_am_name(flag_AM) .. ")"

            flag_subtree:add_le(flags, buffer(offset, 1)):set_text(flag_N_text)
            flag_subtree:add_le(flags, buffer(offset, 1)):set_text(flag_L_text)
            flag_subtree:add_le(flags, buffer(offset, 1)):set_text(flag_I_text)
            flag_subtree:add_le(flags, buffer(offset, 1)):set_text(flag_AM_text)

            local flag_reserved_text = 
                ".... ." .. tvbrange_format_binary(buffer(offset, 1), 5, 3) .. " = Reserved"
            flag_subtree:add_le(flags, buffer(offset, 1)):set_text(flag_reserved_text)
            offset = offset + 1
            announce_subtree:add_le(unit_length, buffer(offset, 1)):append_text(" bytes")
            offset = offset + 1
            announce_subtree:add_le(strategy_num, buffer(offset, 1))
            offset = offset + 1

            if flag_N == 1 then
                announce_subtree:add_le(n_sid, buffer(offset, 16))
                offset = offset + 16
            end

            if flag_L == 1 then
                announce_subtree:add_le(l_sid, buffer(offset, 20))
                offset = offset + 20
            end

            if flag_I == 1 then
                announce_subtree:add_le(nid, buffer(offset, 16))
                offset = offset + 16
            end

            -- Strategy Units
            for j = 1, strategy_num_value do
                local strategy_len_value = buffer(offset + 1, 1):le_uint()
                local strategy_subtree = announce_subtree:add_le(color_protocol, 
                    buffer(offset, strategy_len_value + 2), "Strategy " .. j) -- todo
                strategy_subtree:add_le(strategy_tag, buffer(offset, 1))
                offset = offset + 1
                strategy_subtree:add_le(strategy_len, buffer(offset, 1))
                offset = offset + 1
                strategy_subtree:add_le(strategy_value, buffer(offset, strategy_len_value))
                offset = offset + strategy_len_value
            end
        end -- announce unit

        -- Check if the packet length is correct
        local after_announce_unit_offset = offset
        if flag_K == 1 then
            if buffer_length < offset + 2 then
                subtree:add_le(color_protocol, buffer(), "MALFORMED PACKET: length" ..
                " less than " .. (offset + 2).. " bytes")
                return
            end
            public_key_len_value = buffer(offset, 2):le_uint()
            offset = offset + 2 + public_key_len_value
        end

        if flag_P == 1 then
            if buffer_length < offset + 1 then
                subtree:add_le(color_protocol, buffer(), "MALFORMED PACKET: length" ..
                " less than " .. (offset + 1).. " bytes")
                return
            end
            local as_path_len_value = buffer(offset, 1):le_uint()
            offset = offset + 1 + as_path_len_value
        end

        offset = offset + px_num * 2
        if buffer_length < offset then
            subtree:add_le(color_protocol, buffer(), "MALFORMED PACKET: length" ..
                " less than " .. offset .. " bytes")
            return
        elseif buffer_length > offset then
            subtree:add_le(color_protocol, buffer(), "MALFORMED PACKET: length" ..
                " more than " .. offset .. " bytes")
            return
        end
        --[End] Check if the packet length is correct

        offset = after_announce_unit_offset
        if flag_K == 1 then
            subtree:add_le(public_key_len, buffer(offset, 2)):append_text(" bytes")
            local public_key_len_value = buffer(offset, 2):le_uint()
            offset = offset + 2
            subtree:add_le(public_key, buffer(offset, public_key_len_value))
            offset = offset + public_key_len_value
        end

        if flag_P == 1 then
            subtree:add_le(as_path_len, buffer(offset, 1)):append_text(" bytes")
            local as_path_len_value = buffer(offset, 1):le_uint()
            offset = offset + 1
            local as_path_subtree = subtree:add_le(color_protocol, 
                buffer(offset, as_path_len_value), "AS Path")
            for i = 1, as_path_len_value do
                as_path_subtree:add_le(aid, buffer(offset, 1))
                offset = offset + 1
            end
        end

        for i = 1, px_num do
            subtree:add_le(px, buffer(offset, 2)):set_text("PX " .. i .. ": " .. 
                string.format("0x%04x", buffer(offset, 2):le_uint()))
            offset = offset + 2
        end
    end
end

local ip_proto = DissectorTable.get("ip.proto")
ip_proto:add(150, color_protocol)
