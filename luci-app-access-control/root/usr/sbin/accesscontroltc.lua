#!/usr/bin/lua

--[[
LuCI - Lua Configuration Interface - Internet access control

Copyright 2015,2016 Krzysztof Szuster.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

  http://www.apache.org/licenses/LICENSE-2.0

$Id$

This daemon restores internet blocking rules after router reboot

edited by funTechCn 2018
]]--
local CONFIG_FILE_AC    = "access_control"
local CONFIG_FILE_TCRULES = "access_control_tc_rule"
--require "uci"
local uci = require "luci.model.uci"
local log = require "luci.log"
local x = uci.cursor()
local enable = x:get(CONFIG_FILE_AC,"general","enabled")


local function checkRule()
	local now=os.date("*t",os.time());
        x:foreach (CONFIG_FILE_TCRULES, "rule",
        function(s)
                if s.ac_enabled=='1' then
                        if s.force_allow == '1' then
                                os.execute ("/usr/sbin/tc.sh -t ip -c del -i "..s.src_ip)
                        end
                        if s.force_deny == '1' then
                                os.execute ("/usr/sbin/tc.sh -t ip -c del -i "..s.src_ip)
                                os.execute ("/usr/sbin/tc.sh -t ip -c add -i "..s.src_ip)
                        end
                        local d=s.weekdays

			local wday=string.lower(os.date("%a",os.time()))
			if string.find(d,wday) ~= nil then
				local sHour, sMin = string.match(s.start_time, "(%d+):(%d+)");
				local sTime= os.time{year=now["year"],month=now["month"],day=now["day"],hour=sHour,min=sMin}	
				
				local eHour, eMin = string.match(s.stop_time, "(%d+):(%d+)");
				local eTime= os.time{year=now["year"],month=now["month"],day=now["day"],hour=eHour,min=eMin}	
			
				if s.force_allow ~= '1' and s.force_deny ~= '1' and sTime < os.time() and eTime > os.time() then
                                os.execute ("/usr/sbin/tc.sh -t ip -c del -i "..s.src_ip)
                                os.execute ("/usr/sbin/tc.sh -t ip -c add -i "..s.src_ip)
				end
			end
                end
        end)



end


if enable == "1" then
	os.execute ("/usr/sbin/tc.sh -t ip -c initTc >>/var/log/luci.output")
	checkRule()
else
	os.execute ("/usr/sbin/tc.sh -t ip -c stopBase >>/var/log/luci.output")
end


