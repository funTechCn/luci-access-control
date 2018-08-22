#!/bin/sh
# xiaoh www.linuxbyte.org
 
#  定义进出设备(eth0 内网，eth1外网)
TYPE="mac"
IDEV="br-lan"
ODEV="pppoe-wan"
TCID=256 
TCPRECHAIN="access_control_pre_chain" 
TCPOSTCHAIN="access_control_post_chain" 
#  定义总的上下带宽
upk=$(uci get access_control.general.tc_uploadLimit)
#u=$(awk "BEGIN{print $upk }")
UP="${upk}kbit"


downk=$(uci get access_control.general.tc_downloadLimit)
#d=$(awk "BEGIN{print $downk }")
DOWN="${downk}kbit"
 
#  定义每个受限制的IP上下带宽
#rate 起始带宽 (默认限制，单IP限制带宽)
UPLOAD="${upk}kbit"
DOWNLOAD="${downk}kbit"

#ceil 最大带宽 （当带宽有富余时单IP可借用的最大带宽，这个也是所有受限IP总带宽）
MUPLOAD="5mbit"
MDOWNLOAD="10mbit"
 
#内网IP段
INET="192.168.5."
 
# 受限IP范围，IPS 起始IP，IPE 结束IP。
IPS="206" 
IPE="206"
 

function initBase(){
	ret="$(cat <<-EOF
	# 清除网卡原有队列规则
	tc qdisc del dev $ODEV root 2>/dev/null
	tc qdisc del dev $IDEV root 2>/dev/null

	# 定义最顶层(根)队列规则，并指定 default 类别编号
	tc qdisc add dev $ODEV root handle 10: htb default $TCID
	tc qdisc add dev $IDEV root handle 10: htb default $TCID

	# 定义第一层的 10:1 类别 (上行/下行 总带宽)
	tc class add dev $ODEV parent 10: classid 10:1 htb rate $UP ceil $UP
	tc class add dev $IDEV parent 10: classid 10:1 htb rate $DOWN ceil $DOWN
	EOF
	)"
	echo "${ret}"
}


function stopBase(){
	ret="$(cat <<-EOF
	#清除原有tc基础root规则
	tc qdisc del dev $ODEV root 2>/dev/null
	tc qdisc del dev $IDEV root 2>/dev/null
	EOF
	)"
	echo "${ret}"
}

function initTcBase(){
	ret="$(cat <<-EOF
	#初始化TC基础规则
	tc class add dev $ODEV parent 10:1 classid 10:2$TCID htb rate $UPLOAD ceil $MUPLOAD prio 1
	tc qdisc add dev $ODEV parent 10:2$TCID handle 10:2$TCID: pfifo
	tc filter add dev $ODEV parent 10: protocol ip prio 100 handle 2$TCID fw classid 10:2$TCID
	tc class add dev $IDEV parent 10:1 classid 10:2$TCID htb rate $DOWNLOAD ceil $MDOWNLOAD prio 1
	tc qdisc add dev $IDEV parent 10:2$TCID handle 10:2$TCID: pfifo
	tc filter add dev $IDEV parent 10: protocol ip prio 100 handle 2$TCID fw classid 10:2$TCID
	EOF
	)"
	echo "${ret}"
}

#初始化iptables链
function initIptablesChain(){
	ret="$(cat <<-EOF
	#初始化iptable链
	iptables -t mangle -N $TCPRECHAIN 
	iptables -t mangle -A PREROUTING -j $TCPRECHAIN
	#iptables -t mangle -A $TCPRECHAIN -j RETURN 
	iptables -t mangle -N $TCPOSTCHAIN 
	iptables -t mangle -A POSTROUTING -j $TCPOSTCHAIN
	#iptables -t mangle -A $TCPOSTCHAIN -j RETURN
	EOF
	)"
	echo "${ret}"
}

function stopIptablesChain(){
		ret="$(cat <<-EOF
		#删除pre链
		iptables -t mangle -F $TCPRECHAIN 
		iptables -t mangle -D PREROUTING -j $TCPRECHAIN
		iptables -t mangle -X $TCPRECHAIN 
		#删除post链	
		iptables -t mangle -F $TCPOSTCHAIN 
		iptables -t mangle -D POSTROUTING -j $TCPOSTCHAIN
		iptables -t mangle -X $TCPOSTCHAIN 
		EOF
		)"
		echo "${ret}"
}
#使用ip tc过滤
function addIpRule(){
		if [ $TYPE = "ip" ] ; then
				ip=$1 
				ret="$(cat <<-EOF
				#添加ip mark过滤规则，打上mark
				iptables -t mangle -A $TCPRECHAIN -s $ip -j MARK --set-mark 2$TCID
				iptables -t mangle -A $TCPRECHAIN -s $ip  -j RETURN
				iptables -t mangle -A $TCPOSTCHAIN -d $ip -j MARK --set-mark 2$TCID
				iptables -t mangle -A $TCPOSTCHAIN -d $ip  -j RETURN
				EOF
				)"
		fi
		echo "${ret}"
}
function delIpRule(){
		if [ $TYPE = "ip" ] ; then
				ip=$1 
				ret="$(cat <<-EOF
				#删除ip mark过滤规则
				iptables -t mangle -D $TCPRECHAIN -s $ip -j MARK --set-mark 2$TCID
				iptables -t mangle -D $TCPRECHAIN -s $ip  -j RETURN
				iptables -t mangle -D $TCPOSTCHAIN -d $ip -j MARK --set-mark 2$TCID
				iptables -t mangle -D $TCPOSTCHAIN -d $ip  -j RETURN
				EOF
				)"
		fi
		echo "${ret}"
}

#使用mac过滤
function addMacRule(){
		if [ $TYPE = "mac" ] ; then
				i=$TCID
				mac=$1 
				ret="$(cat <<-EOF
				#添加mac mark过滤规则，打上mark
				iptables -t mangle -A $TCPRECHAIN -m mac --mac-source $mac -j MARK --set-mark 2$i
				iptables -t mangle -A $TCPRECHAIN -m mac --mac-source $mac -j CONNMARK --save-mark
				iptables -t mangle -A $TCPRECHAIN -m mac --mac-source $mac  -j RETURN
				iptables -t mangle -A $TCPOSTCHAIN -m state --state ESTABLISHED,RELATED -j CONNMARK --restore-mark
				EOF
				)"
		fi
		echo "${ret}"
}
function delMacRule(){
		if [ $TYPE = "mac" ] ; then
				i=$TCID
				mac=$1 
				ret="$(cat <<-EOF
				#删除mac mark过滤规则
				iptables -t mangle -D $TCPRECHAIN -m mac --mac-source $mac -j MARK --set-mark 2$i
				iptables -t mangle -D $TCPRECHAIN -m mac --mac-source $mac  -j RETURN
				iptables -t mangle -D $TCPRECHAIN -m mac --mac-source $mac -j CONNMARK --save-mark
				iptables -t mangle -D $TCPOSTCHAIN -m state --state ESTABLISHED,RELATED -j CONNMARK --restore-mark
				EOF
				)"
		fi
		echo "${ret}"
}
#开始iptables 打标和设置具体规则
function addIpRangeRule(){
		ret=""
		i=$IPS;
		while [ $i -le $IPE ]
		do
				ret=ret+"$(cat <<-EOF
				#添加ip过滤地址 
				tc class add dev $ODEV parent 10:1 classid 10:2$i htb rate $UPLOAD ceil $MUPLOAD prio 1
				tc qdisc add dev $ODEV parent 10:2$i handle 10:2$i: pfifo
				tc filter add dev $ODEV parent 10: protocol ip prio 100 handle 2$i fw classid 10:2$i
				tc class add dev $IDEV parent 10:1 classid 10:2$i htb rate $DOWNLOAD ceil $MDOWNLOAD prio 1
				tc qdisc add dev $IDEV parent 10:2$i handle 10:2$i: pfifo
				tc filter add dev $IDEV parent 10: protocol ip prio 100 handle 2$i fw classid 10:2$i
				iptables -t mangle -A $TCPRECHAIN -s $INET$i -j MARK --set-mark 2$i
				iptables -t mangle -A $TCPRECHAIN -s $INET$i -j RETURN
				iptables -t mangle -A $TCPOSTCHAIN -d $INET$i -j MARK --set-mark 2$i
				iptables -t mangle -A $TCPOSTCHAIN -d $INET$i -j RETURN
				EOF
				)"

				i=`expr $i + 1`
		done
		echo "${ret}"
}
function clearRule(){
		ret="$(cat <<-EOF
		# 清除网卡原有队列规则
		tc qdisc del dev $ODEV root 2>/dev/null
		tc qdisc del dev $IDEV root 2>/dev/null

		#开始清理iptables 打标和设置具体规则

		EOF
		)"
		if [ $TYPE = "iprange" ]
		then
				p=$IPS;
				while [ $p -le $IPE ]
				do
						ret=$ret+"$(cat <<-EOF
						iptables -t mangle -D $TCPRECHAIN -s $INET$p -j MARK --set-mark 2$p
						iptables -t mangle -D $TCPRECHAIN -s $INET$p -j RETURN
						iptables -t mangle -D $TCPOSTCHAIN -d $INET$p -j MARK --set-mark 2$p
						iptables -t mangle -D $TCPOSTCHAIN -d $INET$p -j RETURN
						EOF
						)"
						p=`expr $p + 1`
				done
		fi

		if [ $TYPE = "mac" ]
		then
			ret=$ret+"$(cat <<-EOF
			#clear pre链
			iptables -t mangle -F $TCPRECHAIN
			#clear post链
			iptables -t mangle -F $TCPOSTCHAIN
			EOF
			)"

		fi
		if [ $TYPE = "ip" ]
		then
			ret=$ret+"$(cat <<-EOF
			#clear pre链
			iptables -t mangle -F $TCPRECHAIN
			#clear post链
			iptables -t mangle -F $TCPOSTCHAIN
			EOF
			)"

		fi
		echo "${ret}"
}

if [ $TYPE = "iprange" ] ; then
	IPS=$2
	IPE=$3
	addIpRule 
fi

#if [ $TYPE = "mac" ] ; then
#	for x in ${@:1:3}
#	do
#	echo
		#		addMacRule $x
#	done
#fi

ACTION=""
mac=""
ip=""
script=0
while getopts "t:m:i:c:hsk:" optname
do

	#echo $optname $OPTARG
	
	if [ $optname = "t" ]
	then
		TYPE=$OPTARG
	fi

	if [ $optname = "c" ]
	then
		ACTION=$OPTARG
	fi

	if [ $optname = "m" ]
	then
		mac=$OPTARG
	fi
	
	if [ $optname = "i" ]
	then
		ip=$OPTARG
	fi
	
	if [ $optname = "s" ]
	then
			script=1
	else
			script=0
	fi
	
	if [ $optname = "h" ]
	then
		cat <<-EOF
		
		-t type:[ip|mac]
		-m mac address
		-i ip address
		-c action:[add|del|clear|initTc|stop]
		-s print command instead of execute
		-k keyword for clear crontab
		-h help
		init tc access control:
			tc.sh -t mac -c initTc
		add ip: 
			tc.sh -t ip -i XX:XX:XX:XX:XX:XX -c add
		delete ip: 
			tc.sh -t ip -i XX:XX:XX:XX:XX:XX -c del
		clear ip: 
			tc.sh -t ip -c clear
		add mac: 
			tc.sh -t mac -m XX:XX:XX:XX:XX:XX -c add
		delete mac: 
			tc.sh -t mac -m XX:XX:XX:XX:XX:XX -c del
		stop tc: 
			tc.sh -c stop
		EOF
		exit 0
	fi
done

if [ $ACTION = "initTc" ]
then
		if [ $script -eq 1 ]
		then
				stopIptablesChain
				initBase
				initTcBase
				initIptablesChain
		else
				stopIptablesChain | sh -
				initBase | sh -
				initTcBase | sh -
				initIptablesChain | sh -
		fi
fi

if [ $ACTION = "clear" ]
then
		echo clear mac
		if [ $script -eq 1 ]
		then
				clearRule
		else
				clearRule | sh -
		fi
fi

if [ $TYPE = "mac" -a $ACTION = "add" ]
then
		echo delMacRule and addMacRule $mac
		if [ $script -eq 1 ]
		then
				delMacRule $mac
				addMacRule $mac
		else
				delMacRule $mac | sh -
				addMacRule $mac | sh -
		fi
fi

if [ $TYPE = "mac" -a $ACTION = "del" ]
then
		echo delMacRule $mac
		if [ $script -eq 1 ]
		then
				delMacRule $mac
		else
				delMacRule $mac|sh -
		fi
fi

if [ $TYPE = "mac" -a $ACTION = "stop" ]
then
		echo stop tc access control
		if [ $script -eq 1 ]
		then
				stopIptablesChain
				stopBase
		else
				stopIptablesChain | sh -
				stopBase | sh -
		fi
fi

if [ $TYPE = "ip" -a $ACTION = "add" ]
then
		echo delIpRule and addIpRule $ip
		if [ $script -eq 1 ]
		then
				delIpRule $ip
				addIpRule $ip
		else
				delIpRule $ip | sh -
				addIpRule $ip | sh -
		fi
fi

if [ $TYPE = "ip" -a $ACTION = "del" ]
then
		echo delIpRule $mac
		if [ $script -eq 1 ]
		then
				delIpRule $ip
		else
				delIpRule $ip|sh -
		fi
fi

if [ $TYPE = "ip" -a $ACTION = "stop" ]
then
		echo stop tc access control
		if [ $script -eq 1 ]
		then
				stopIptablesChain
				stopBase
		else
				stopIptablesChain | sh -
				stopBase | sh -
		fi
fi
