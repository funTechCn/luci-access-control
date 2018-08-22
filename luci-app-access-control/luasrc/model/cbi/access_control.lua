--[[
LuCI - Lua Configuration Interface - Internet access control

Copyright 2015,2016 Krzysztof Szuster.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

	http://www.apache.org/licenses/LICENSE-2.0

$Id$
]]--

local log = require "luci.log"
local CONFIG_FILE_RULES = "firewall"  
local CONFIG_FILE_TCRULES = "access_control_tc_rule"  
local CONFIG_FILE_AC    = "access_control"
local Days = {'mon','tue','wed','thu','fri','sat','sun'}
local Days1 = translate('M,T,W,T,F,S,S')
local mr, ma, o 


local uci = require "luci.model.uci"

local ac_keyword = "access_control"
local CRONTABFILE = "/etc/crontabs/root"
local CRONTABRELOAD = "/etc/init.d/cron reload"
--清空计划任务,通过filter过滤
local function clear_crontab(filter)
        local ret=os.execute("tempStr=$(crontab -l|grep -v "..filter..");echo \"${tempStr}\" >/etc/crontabs/root ")
        --local list=util.execi("crontab -l|grep -v "..ac_keyword)
        --if not list then
        --      return
        --end
        --local t_lines ={}
        --for line in list do
        --      table.insert(t_lines,line)
        --      table.insert(t_lines,"\r")
        --end
        --print(">>>>>"..table.concat(t_lines))
        --local cfile = io.open(CRONTABFILE,"w+")
        --cfile:write(table.concat(t_lines))
        --cfile:write(t_str)
        --cfile:close()
        return ret
end

--添加到计划任务
local function add_crontab(time,day,filter,parms)
        local hh, mm
        hh,mm = string.match (time, "^(%d?%d):(%d%d)$")
        hh = tonumber (hh)
        mm = tonumber (mm)
        local task = (mm .. " " .. hh .. " * * "..day.." /usr/sbin/tc.sh -k "..filter.." "..parms)
        local cfile = io.open(CRONTABFILE,"a+")
        cfile:write(task.."\n")
        cfile:close()
        return task
end

--从配置字符串找到星期ID
local function get_days(dayStr)
	local ret=""
	if dayStr == nil or dayStr == "" then
		return "*"
	end
	for key,val in pairs(Days) do
		ret = ret..(string.find (dayStr,val) and key or "" )
	end
	if ret.length == 0 then
		ret = "*"
	end
	return ret
end

function applyRule ()

	--[[
	{
	ac_enabled = '1'
	.anonymous = true
	enabled = '1'
	extra = '--kerneltz'
	.name = 'cfg1b92bd'
	target = 'REJECT'
	proto = '0'
	src = '*'
	.index = 26
	name = '禁止电视下午'
	stop_time = '17:30'
	dest = 'wan'
	start_time = '14:30'
	.type = 'rule'
	src_mac = 'F8:45:AD:12:38:E9'
	}
	{
	ac_enabled = '1'
	.anonymous = true
	enabled = '1'
	extra = '--kerneltz'
	proto = '0'
	.name = 'cfg1c92bd'
	src = '*'
	target = 'REJECT'
	.index = 27
	name = '禁止电视晚上'
	stop_time = '22:00'
	dest = 'wan'
	start_time = '19:30'
	weekdays ' mon tue wed thu sat'
	.type = 'rule'
	src_mac = 'F8:45:AD:12:38:E9'
	}

	]]--

	clear_crontab(ac_keyword)
	local x = uci.cursor()
	x:foreach (CONFIG_FILE_TCRULES, "rule",
	function(s)
--		if s.ac_enabled=='1' then
--			if s.force_allow == '1' then
--				os.execute ("/usr/sbin/tc.sh -t mac -c del -m "..s.src_mac.." >/dev/null 2>/dev/null")
--			end
--			if s.force_deny == '1' then
--				os.execute ("/usr/sbin/tc.sh -t mac -c del -m "..s.src_mac.." >/dev/null 2>/dev/null")
--				os.execute ("/usr/sbin/tc.sh -t mac -c add -m "..s.src_mac.." >/dev/null 2>/dev/null")
--			end
--			local d=s.weekdays
--			d=get_days(d)
--			if s.force_allow ~= '1' and s.force_deny ~= '1' and s.start_time ~= nil then
--				add_crontab(s.start_time,d,ac_keyword,"-t mac -c add -m "..s.src_mac)
--			end
--			if s.force_allow ~= '1' and s.force_deny ~= '1' and s.stop_time ~= nil then
--				add_crontab(s.stop_time,d,ac_keyword,"-t mac -c del -m "..s.src_mac)
--			end
--			--os.execute ("/root/share/openwrt/bin/tc.sh -t mac -c add -m "..s.src_mac.." >>/var/log/luci.output")
--			--log.print_r(str,6)
--		end
		if s.ac_enabled=='1' then
			--[[//do this in /usr/sbin/accesscontroltc.lua
			if s.force_allow == '1' then
			os.execute ("/usr/sbin/tc.sh -t ip -c del -i "..s.src_ip.." >/dev/null 2>/dev/null")
			end
			if s.force_deny == '1' then
			os.execute ("/usr/sbin/tc.sh -t ip -c del -i "..s.src_ip.." >/dev/null 2>/dev/null")
			os.execute ("/usr/sbin/tc.sh -t ip -c add - "..s.src_ip.." >/dev/null 2>/dev/null")
			end
			]]--
			
			--create crontab
			local d=s.weekdays
			d=get_days(d)
			if s.force_allow ~= '1' and s.force_deny ~= '1' and s.start_time ~= nil then
				add_crontab(s.start_time,d,ac_keyword,"-t ip -c add -i "..s.src_ip)
			end
			if s.force_allow ~= '1' and s.force_deny ~= '1' and s.stop_time ~= nil then
				add_crontab(s.stop_time,d,ac_keyword,"-t ip -c del -i "..s.src_ip)
			end
			--os.execute ("/root/share/openwrt/bin/tc.sh -t mac -c add -m "..s.src_mac.." >>/var/log/luci.output")
			--log.print_r(str,6)
		end
		--执行初始化脚本，恢复规则
		os.execute ("/usr/sbin/accesscontroltc.lua >/dev/null 2>/dev/null")

	end)
end


local function time_elapsed (tend) 
	local now = math.floor (os.time() / 60)  --  [min]
	return now > math.floor (tonumber (tend) / 60) 
end


local ma = Map(CONFIG_FILE_AC, translate("Internet Access Control"),
translate("Access Control allows you to manage Internet access for specific local hosts.<br/>\
Each rule defines when a device should be blocked from having Internet access. The rules may be active permanently or during certain times of the day.<br/>\
The rules may also be restricted to specific days of the week.<br/>\
Any device that is blocked may obtain a ticket suspending the restriction for a specified time."))
if CONFIG_FILE_AC==CONFIG_FILE_RULES then
	mr = ma
else
	--mr = Map(CONFIG_FILE_RULES)
	mr = Map(CONFIG_FILE_TCRULES)
end

function mr.on_after_commit (self)
	--	local rule = ma:section(TypedSection, "rule", translate("Client Rules"))
	--	local rule2 = mr:section(TypedSection, "rule", translate("Client Rules"))
	--	log.print("self:")
	--	log.print_r(rule,8)
	--	log.print("self rules:")
	--	log.print(table.concat(rule))
	--	log.print("self rules2:")
	--	log.print_r(rule,8)
	--log.print(table.concat(self.s_rule))
	
	log.print("access control applay config...")
	local x = uci.cursor()
	local enable = x:get(CONFIG_FILE_AC,"general","enabled")
	if enable == "1" then
		--os.execute ("/usr/sbin/tc.sh -t ip -c initTc >>/var/log/luci.output")
		applyRule()
	else
		--os.execute ("/usr/sbin/tc.sh -t ip -c stopBase >>/var/log/luci.output")
		clear_crontab(ac_keyword)
	end
	os.execute(CRONTABRELOAD)
	--log.print("os.execute (\"/etc/init.d/inetac restart >/dev/null 2>/dev/null\")")
	--os.execute ("/etc/init.d/inetac restart >/dev/null 2>/dev/null")
end

--=============================================================================================
--  General section

local s_gen = ma:section(NamedSection, "general", "access_control", translate("General settings"))
local o_global_enable = s_gen:option(Flag, "enabled", translate("Enabled"),
translate ("Must be set to enable the internet access blocking"))
o_global_enable.rmempty = false

local o_global_tcMode = s_gen:option(Flag, "tcMode", translate("Use tc mode"),
translate ("Use tc to control access"))
o_global_tcMode.rmempty = false



local o_download = s_gen:option(Value, "tc_downloadLimit", translate("download limit"), 
translate("download speed limit[kbps]"))
o_download.datatype = "uinteger"
o_download.default = 10

local o_upload = s_gen:option(Value, "tc_uploadLimit", translate("upload limit"), 
translate("upload speed limit[kbps]"))
o_upload.datatype = "uinteger"
o_upload.default = 10

--[[
local o_ticket = s_gen:option(Value, "ticket", translate("Ticket time [min]"), 
translate("Time granted when a ticket is issued"))
o_ticket.datatype = "uinteger"
o_ticket.default = 60
]]--
--=============================================================================================
-- Rule table section

local s_rule = mr:section(TypedSection, "rule", translate("Client Rules"))
s_rule.addremove = true
s_rule.anonymous = true
--    s_rule.sortable  = true
s_rule.template = "cbi/tblsection"
-- hidden option
s_rule.defaults.ac_suspend = nil
-- hidden, constant options
s_rule.defaults.enabled = "0"
s_rule.defaults.src     = "*" --"lan", "guest" or enything on local side
s_rule.defaults.dest    = "wan"
s_rule.defaults.target  = "REJECT"
s_rule.defaults.proto    = "0"
s_rule.defaults.extra = "--kerneltz"
s_rule.defaults.force = "0"
-- only AC-related rules
s_rule.filter = function (self, section)
	return self.map:get (section, "ac_enabled") ~= nil
end

-----------------------------------------------------------               

o = s_rule:option(Flag, "ac_enabled", translate("Enabled"))
o.default = '1'
o.rmempty  = false

-- ammend "enabled" and "ac_suspend" optiona, and set weekdays  
function o.write(self, section, value)        
	wd_write (self, section)

	local key = o_global_enable:cbid (o_global_enable.section.section)
	--  "cbid.access_control.general.enabled"
	local enable = (o_global_enable.map:formvalue (key)=='1') and (value=='1')
	if not enable then  --  disabled rule => clear ticket, if any
		self.map:del(section, "ac_suspend")
	else  -- check ticket  
		local ac_susp = self.map:get(section, "ac_suspend")
		if ac_susp then  
			if time_elapsed (ac_susp) then
				self.map:del (section, "ac_suspend")
				ac_susp = nil
			end
		end
		if ac_susp then  --  ticked issued => temporarily disable rule
			enable = false
		end
	end

	self.map:set(section, "enabled", enable and '1' or '0')
	--            self.map:set(section, "src",  "*")
	--            self.map:set(section, "dest", "wan")
	--            self.map:set(section, "target", "REJECT")
	--            self.map:set(section, "proto", "0")
	--            self.map:set(section, "extra", "--kerneltz")
	return Flag.write(self, section, value)
end

-----------------------------------------------------------        
s_rule:option(Value, "name", translate("Description"))

-----------------------------------------------------------        
--[[
o = s_rule:option(Value, "src_mac", translate("MAC address")) 
o.rmempty = false
o.datatype = "macaddr"
luci.sys.net.mac_hints(function(mac, name)
	o:value(mac, "%s (%s)" %{ mac, name })
end)
]]--
o = s_rule:option(Value, "src_ip", translate("ip address")) 
o.rmempty = false
o.datatype = "ip4addr"
luci.sys.net.ipv4_hints(function(v4, name)
	o:value(v4, "%s (%s)" %{ v4, name })
end)
-----------------------------------------------------------        
function validate_time(self, value, section)
	local hh, mm
	hh,mm = string.match (value, "^(%d?%d):(%d%d)$")
	hh = tonumber (hh)
	mm = tonumber (mm)
	if hh and mm and hh <= 23 and mm <= 59 then
		return value
	else
		return nil, translate("Time value must be HH:MM or empty")
	end
end


-- BEGIN Start time
o =  s_rule:option(Value, "start_time", translate("Start Time"))
o.optional = false
o.rmempty = false
o:value("00:00")
o:value("00:30")
o:value("01:00")
o:value("01:30")
o:value("02:00")
o:value("02:30")
o:value("03:00")
o:value("03:30")
o:value("04:00")
o:value("04:30")
o:value("05:00")
o:value("05:30")
o:value("06:00")
o:value("06:30")
o:value("07:00")
o:value("07:30")
o:value("08:00")
o:value("08:30")
o:value("09:00")
o:value("09:30")
o:value("10:00")
o:value("10:30")
o:value("11:00")
o:value("11:30")
o:value("12:00")
o:value("12:30")
o:value("13:00")
o:value("13:30")
o:value("14:00")
o:value("14:30")
o:value("15:00")
o:value("15:30")
o:value("16:00")
o:value("16:30")
o:value("17:00")
o:value("17:30")
o:value("18:00")
o:value("18:30")
o:value("19:00")
o:value("19:30")
o:value("20:00")
o:value("20:30")
o:value("21:00")
o:value("21:30")
o:value("22:00")
o:value("22:30")
o:value("23:00")
o:value("23:30")

--o = s_rule:option(Value, "start_time", translate("Start time"))
o.rmempty = true  -- do not validae blank
o.validate = validate_time 
o.size = 5


-- BEGIN Stop time
o =  s_rule:option(Value, "stop_time", translate("End time"))
o.optional = false
o.rmempty = false
o:value("00:00")
o:value("00:30")
o:value("01:00")
o:value("01:30")
o:value("02:00")
o:value("02:30")
o:value("03:00")
o:value("03:30")
o:value("04:00")
o:value("04:30")
o:value("05:00")
o:value("05:30")
o:value("06:00")
o:value("06:30")
o:value("07:00")
o:value("07:30")
o:value("08:00")
o:value("08:30")
o:value("09:00")
o:value("09:30")
o:value("10:00")
o:value("10:30")
o:value("11:00")
o:value("11:30")
o:value("12:00")
o:value("12:30")
o:value("13:00")
o:value("13:30")
o:value("14:00")
o:value("14:30")
o:value("15:00")
o:value("15:30")
o:value("16:00")
o:value("16:30")
o:value("17:00")
o:value("17:30")
o:value("18:00")
o:value("18:30")
o:value("19:00")
o:value("19:30")
o:value("20:00")
o:value("20:30")
o:value("21:00")
o:value("21:30")
o:value("22:00")
o:value("22:30")
o:value("23:00")
o:value("23:30")

--o = s_rule:option(Value, "stop_time", translate("End time"))
o.rmempty = true  -- do not validae blank
o.validate = validate_time
o.size = 5

-----------------------------------------------------------        
function make_day (nday)
	local day = Days[nday]
	local d = {}
	local _
	_,_,d[1],d[2],d[3],d[4],d[5],d[6],d[7] = string.find(Days1,"(.+),(.+),(.+),(.+),(.+),(.+),(.+)")
	local label = d[nday] 	
	if nday==7 then
		label = '<font color="red">'..label..'</font>'
	end         
	local o = s_rule:option(Flag, day, label)
	o.rmempty = false  --  always call write

	-- read from weekdays actually
	function o.cfgvalue (self, section)
		local days = self.map:get (section, "weekdays")
		if days==nil then
			return '1'
		end
		return string.find (days, day) and '1' or '0'
	end

	--  prevent saveing option in config file   
	function o.write(self, section, value)
		self.map:del (section, self.option)
	end
end

for i=1,7 do   
	make_day (i)
end   

function wd_write(self, section)
	local value=''
	local cnt=0
	for _,day in ipairs (Days) do
		local key = "cbid."..self.map.config.."."..section.."."..day
		if mr:formvalue(key) then
			value = value..' '..day
			cnt = cnt+1
		end
	end
	if cnt==7  then  --all days means no filtering 
		value = ''
	end
	self.map:set(section, "weekdays", value)
end

-----------------------------------------------------------        
--[[
o = s_rule:option(Button, "_ticket", translate("Ticket")) 
o:depends ("ac_enabled", "1")

function o.cfgvalue(self, section)
	local ac_susp = self.map:get(section, "ac_suspend")
	if ac_susp then
		if time_elapsed (ac_susp) then
			self.map:del (section, "ac_suspend")
			ac_susp = nil
		else
			local tend = os.date ("%H:%M", ac_susp)
			self.inputtitle = tend.."\n"
			self.inputtitle = self.inputtitle..translate("Cancel")
			self.inputstyle = 'remove'
		end
	end
	if not ac_susp then
		self.inputtitle = translate("Issue")
		self.inputstyle = 'add'
	end
end

function o.write(self, section, value)
	local ac_susp = self.map:get(section, "ac_suspend")
	--            local key = o_ticket:cbid (o_ticket.section.section)
	--            local t = o_ticket.map:formvalue (key)
	local t = o_ticket.map:get (o_ticket.section.section, o_ticket.option)  --  "general", "ticket"
	t =  tonumber (t) * 60  --  to seconds
	if ac_susp then
		--                ac_susp = ac_susp + t
		ac_susp = ""
	else
		ac_susp = os.time() + t
	end
	self.map:set(section, "ac_suspend", ac_susp)
end
]]--
------------------------------------------------------
o = s_rule:option(Flag, "force_deny", translate("Force deny"))
--o:depends ("force_allow", "0")
o.default = '0'
o.rmempty  = false

o = s_rule:option(Flag, "force_allow", translate("Force allow"))
--o:depends ("force_deny", "0")
o.default = '0'
o.rmempty  = false
--========================================================================================================

if CONFIG_FILE_AC==CONFIG_FILE_RULES then
  return ma
else
  return ma, mr
end

