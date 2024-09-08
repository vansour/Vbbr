#!/usr/bin/env bash
PATH=/bin:/sbin:/usr/bin:/usr/sbin:/usr/local/bin:/usr/local/sbin:~/bin
export PATH

imgurl=""
headurl=""

Green_font_prefix="\033[32m"
Red_font_prefix="\033[31m"
Font_color_suffix="\033[0m"
Info="${Green_font_prefix}[信息]${Font_color_suffix}"
Error="${Red_font_prefix}[错误]${Font_color_suffix}"
Tip="${Green_font_prefix}[注意]${Font_color_suffix}"

if [ -f "/etc/sysctl.d/bbr.conf" ]; then
  rm -rf /etc/sysctl.d/bbr.conf
fi

# 检查当前用户是否为 root 用户
if [ "$EUID" -ne 0 ]; then
  echo "请使用 root 用户身份运行此脚本"
  exit
fi

apt_update() {
  apt update -y && \
  apt upgrade -y && \
  apt install -y --fix-broken && \
  apt install -y wget curl socat vim jq && \
  apt autoremove -y
}

#下载
download_file() {
  url="$1"
  filename="$2"

  wget "$url" -O "$filename"
  status=$?

  if [ $status -eq 0 ]; then
    echo -e "\e[32m文件下载成功或已经是最新。\e[0m"
  else
    echo -e "\e[31m文件下载失败，退出状态码: $status\e[0m"
    exit 1
  fi
}

#檢查賦值
check_empty() {
  local var_value=$1

  if [[ -z $var_value ]]; then
    echo "$var_value 是空值，退出！"
    exit 1
  fi
}

#安装BBR内核
installbbr() {
  kernel_version="5.9.6"
  bit=$(uname -m)
  rm -rf bbr
  mkdir bbr && cd bbr || exit

  if [[ "${bit}" == "x86_64" ]]; then
    echo -e "如果下载地址出错，可能当前正在更新，超过半天还是出错请反馈，大陆自行解决污染问题"
    github_tag=$(curl -s 'https://api.github.com/repos/ylx2016/kernel/releases' | grep 'Debian_Kernel' | grep '_latest_bbr_' | head -n 1 | awk -F '"' '{print $4}' | awk -F '[/]' '{print $8}')
    github_ver=$(curl -s 'https://api.github.com/repos/ylx2016/kernel/releases' | grep ${github_tag} | grep 'deb' | grep 'headers' | awk -F '"' '{print $4}' | awk -F '[/]' '{print $9}' | awk -F '[-]' '{print $3}' | awk -F '[_]' '{print $1}')   
    check_empty $github_ver
    echo -e "获取的版本号为:${Green_font_prefix}${github_ver}${Font_color_suffix}"
    kernel_version=$github_ver
    detele_kernel_head
    headurl=$(curl -s 'https://api.github.com/repos/ylx2016/kernel/releases' | grep ${github_tag} | grep 'deb' | grep 'headers' | awk -F '"' '{print $4}')
    imgurl=$(curl -s 'https://api.github.com/repos/ylx2016/kernel/releases' | grep ${github_tag} | grep 'deb' | grep -v 'headers' | grep -v 'devel' | awk -F '"' '{print $4}')

    download_file $headurl linux-headers-d12.deb
    download_file $imgurl linux-image-d12.deb
    dpkg -i linux-image-d12.deb
    dpkg -i linux-headers-d12.deb
  else
    echo -e "${Error} 不支持x86_64以外的系统 !" && exit 1
  fi

  cd .. && rm -rf bbr

  detele_kernel
  BBR_grub
  echo -e "${Tip} ${Red_font_prefix}请检查上面是否有内核信息，无内核千万别重启${Font_color_suffix}"
  echo -e "${Tip} ${Red_font_prefix}rescue不是正常内核，要排除这个${Font_color_suffix}"
  echo -e "${Tip} 重启VPS后，请重新运行脚本开启${Red_font_prefix}BBR${Font_color_suffix}"
  check_kernel
  stty erase '^H' && read -p "需要重启VPS后，才能开启BBR，是否现在重启 ? [Y/n] :" yn
  [ -z "${yn}" ] && yn="y"
  if [[ $yn == [Yy] ]]; then
    echo -e "${Info} VPS 重启中..."
    reboot
  fi
}


#启用BBR+fq_pie
startbbrfqpie() {
  remove_bbr_lotserver
  echo "net.core.default_qdisc=fq_pie" >>/etc/sysctl.d/99-sysctl.conf
  echo "net.ipv4.tcp_congestion_control=bbr" >>/etc/sysctl.d/99-sysctl.conf
  sysctl --system
  echo -e "${Info}BBR+FQ_PIE修改成功，重启生效！"
}


#开启ecn
startecn() {
  sed -i '/net.ipv4.tcp_ecn/d' /etc/sysctl.d/99-sysctl.conf
  sed -i '/net.ipv4.tcp_ecn/d' /etc/sysctl.conf

  echo "net.ipv4.tcp_ecn=1" >>/etc/sysctl.d/99-sysctl.conf
  sysctl --system
  echo -e "${Info}开启ecn结束！"
}


#卸载bbr+锐速
remove_bbr_lotserver() {
  sed -i '/net.ipv4.tcp_ecn/d' /etc/sysctl.d/99-sysctl.conf
  sed -i '/net.core.default_qdisc/d' /etc/sysctl.d/99-sysctl.conf
  sed -i '/net.ipv4.tcp_congestion_control/d' /etc/sysctl.d/99-sysctl.conf
  sed -i '/net.ipv4.tcp_ecn/d' /etc/sysctl.conf
  sed -i '/net.core.default_qdisc/d' /etc/sysctl.conf
  sed -i '/net.ipv4.tcp_congestion_control/d' /etc/sysctl.conf
  sysctl --system

  rm -rf bbrmod

  if [[ -e /appex/bin/lotServer.sh ]]; then
    echo | bash <(wget -qO- https://raw.githubusercontent.com/fei5seven/lotServer/master/lotServerInstall.sh) uninstall
  fi
  clear
}

#卸载全部加速
remove_all() {
  rm -rf /etc/sysctl.d/*.conf
  #rm -rf /etc/sysctl.conf
  #touch /etc/sysctl.conf
  if [ ! -f "/etc/sysctl.conf" ]; then
    touch /etc/sysctl.conf
  else
    cat /dev/null >/etc/sysctl.conf
  fi
  sysctl --system
  sed -i '/DefaultTimeoutStartSec/d' /etc/systemd/system.conf
  sed -i '/DefaultTimeoutStopSec/d' /etc/systemd/system.conf
  sed -i '/DefaultRestartSec/d' /etc/systemd/system.conf
  sed -i '/DefaultLimitCORE/d' /etc/systemd/system.conf
  sed -i '/DefaultLimitNOFILE/d' /etc/systemd/system.conf
  sed -i '/DefaultLimitNPROC/d' /etc/systemd/system.conf

  sed -i '/soft nofile/d' /etc/security/limits.conf
  sed -i '/hard nofile/d' /etc/security/limits.conf
  sed -i '/soft nproc/d' /etc/security/limits.conf
  sed -i '/hard nproc/d' /etc/security/limits.conf

  sed -i '/ulimit -SHn/d' /etc/profile
  sed -i '/ulimit -SHn/d' /etc/profile
  sed -i '/required pam_limits.so/d' /etc/pam.d/common-session

  systemctl daemon-reload

  rm -rf bbrmod
  sed -i '/net.ipv4.tcp_retries2/d' /etc/sysctl.conf
  sed -i '/net.ipv4.tcp_slow_start_after_idle/d' /etc/sysctl.conf
  sed -i '/net.ipv4.tcp_fastopen/d' /etc/sysctl.conf
  sed -i '/net.ipv4.tcp_ecn/d' /etc/sysctl.conf
  sed -i '/net.core.default_qdisc/d' /etc/sysctl.conf
  sed -i '/net.ipv4.tcp_congestion_control/d' /etc/sysctl.conf
  sed -i '/fs.file-max/d' /etc/sysctl.conf
  sed -i '/net.core.rmem_max/d' /etc/sysctl.conf
  sed -i '/net.core.wmem_max/d' /etc/sysctl.conf
  sed -i '/net.core.rmem_default/d' /etc/sysctl.conf
  sed -i '/net.core.wmem_default/d' /etc/sysctl.conf
  sed -i '/net.core.netdev_max_backlog/d' /etc/sysctl.conf
  sed -i '/net.core.somaxconn/d' /etc/sysctl.conf
  sed -i '/net.ipv4.tcp_syncookies/d' /etc/sysctl.conf
  sed -i '/net.ipv4.tcp_tw_reuse/d' /etc/sysctl.conf
  sed -i '/net.ipv4.tcp_tw_recycle/d' /etc/sysctl.conf
  sed -i '/net.ipv4.tcp_fin_timeout/d' /etc/sysctl.conf
  sed -i '/net.ipv4.tcp_keepalive_time/d' /etc/sysctl.conf
  sed -i '/net.ipv4.ip_local_port_range/d' /etc/sysctl.conf
  sed -i '/net.ipv4.tcp_max_syn_backlog/d' /etc/sysctl.conf
  sed -i '/net.ipv4.tcp_max_tw_buckets/d' /etc/sysctl.conf
  sed -i '/net.ipv4.tcp_rmem/d' /etc/sysctl.conf
  sed -i '/net.ipv4.tcp_wmem/d' /etc/sysctl.conf
  sed -i '/net.ipv4.tcp_mtu_probing/d' /etc/sysctl.conf
  sed -i '/net.ipv4.ip_forward/d' /etc/sysctl.conf
  sed -i '/fs.inotify.max_user_instances/d' /etc/sysctl.conf
  sed -i '/net.ipv4.tcp_syncookies/d' /etc/sysctl.conf
  sed -i '/net.ipv4.tcp_fin_timeout/d' /etc/sysctl.conf
  sed -i '/net.ipv4.tcp_tw_reuse/d' /etc/sysctl.conf
  sed -i '/net.ipv4.tcp_max_syn_backlog/d' /etc/sysctl.conf
  sed -i '/net.ipv4.ip_local_port_range/d' /etc/sysctl.conf
  sed -i '/net.ipv4.tcp_max_tw_buckets/d' /etc/sysctl.conf
  sed -i '/net.ipv4.route.gc_timeout/d' /etc/sysctl.conf
  sed -i '/net.ipv4.tcp_synack_retries/d' /etc/sysctl.conf
  sed -i '/net.ipv4.tcp_syn_retries/d' /etc/sysctl.conf
  sed -i '/net.core.somaxconn/d' /etc/sysctl.conf
  sed -i '/net.core.netdev_max_backlog/d' /etc/sysctl.conf
  sed -i '/net.ipv4.tcp_timestamps/d' /etc/sysctl.conf
  sed -i '/net.ipv4.tcp_max_orphans/d' /etc/sysctl.conf
  if [[ -e /appex/bin/lotServer.sh ]]; then
    bash <(wget -qO- https://raw.githubusercontent.com/fei5seven/lotServer/master/lotServerInstall.sh) uninstall
  fi
  clear
  echo -e "${Info}:清除加速完成。"
  sleep 1s
}

#优化系统配置
optimizing_system() {
  if [ ! -f "/etc/sysctl.conf" ]; then
    touch /etc/sysctl.conf
  fi
  sed -i '/net.ipv4.tcp_retries2/d' /etc/sysctl.conf
  sed -i '/net.ipv4.tcp_slow_start_after_idle/d' /etc/sysctl.conf
  sed -i '/net.ipv4.tcp_fastopen/d' /etc/sysctl.conf
  sed -i '/fs.file-max/d' /etc/sysctl.conf
  sed -i '/fs.inotify.max_user_instances/d' /etc/sysctl.conf
  sed -i '/net.ipv4.tcp_syncookies/d' /etc/sysctl.conf
  sed -i '/net.ipv4.tcp_fin_timeout/d' /etc/sysctl.conf
  sed -i '/net.ipv4.tcp_tw_reuse/d' /etc/sysctl.conf
  sed -i '/net.ipv4.tcp_max_syn_backlog/d' /etc/sysctl.conf
  sed -i '/net.ipv4.ip_local_port_range/d' /etc/sysctl.conf
  sed -i '/net.ipv4.tcp_max_tw_buckets/d' /etc/sysctl.conf
  sed -i '/net.ipv4.route.gc_timeout/d' /etc/sysctl.conf
  sed -i '/net.ipv4.tcp_synack_retries/d' /etc/sysctl.conf
  sed -i '/net.ipv4.tcp_syn_retries/d' /etc/sysctl.conf
  sed -i '/net.core.somaxconn/d' /etc/sysctl.conf
  sed -i '/net.core.netdev_max_backlog/d' /etc/sysctl.conf
  sed -i '/net.ipv4.tcp_timestamps/d' /etc/sysctl.conf
  sed -i '/net.ipv4.tcp_max_orphans/d' /etc/sysctl.conf
  sed -i '/net.ipv4.ip_forward/d' /etc/sysctl.conf

  echo "net.ipv4.tcp_retries2 = 8
net.ipv4.tcp_slow_start_after_idle = 0
fs.file-max = 1000000
fs.inotify.max_user_instances = 8192
net.ipv4.tcp_syncookies = 1
net.ipv4.tcp_fin_timeout = 30
net.ipv4.tcp_tw_reuse = 1
net.ipv4.ip_local_port_range = 1024 65000
net.ipv4.tcp_max_syn_backlog = 16384
net.ipv4.tcp_max_tw_buckets = 6000
net.ipv4.route.gc_timeout = 100
net.ipv4.tcp_syn_retries = 1
net.ipv4.tcp_synack_retries = 1
net.core.somaxconn = 32768
net.core.netdev_max_backlog = 32768
net.ipv4.tcp_timestamps = 0
net.ipv4.tcp_max_orphans = 32768
# forward ipv4
#net.ipv4.ip_forward = 1" >>/etc/sysctl.conf
  sysctl -p
  echo "*               soft    nofile           1000000
*               hard    nofile          1000000" >/etc/security/limits.conf
  echo "ulimit -SHn 1000000" >>/etc/profile
  read -p "需要重启VPS后，才能生效系统优化配置，是否现在重启 ? [Y/n] :" yn
  [ -z "${yn}" ] && yn="y"
  if [[ $yn == [Yy] ]]; then
    echo -e "${Info} VPS 重启中..."
    reboot
  fi
}

#禁用IPv6
closeipv6() {
  clear
  # 编辑 GRUB 配置文件，添加禁用 IPv6 的参数
  if grep -q "ipv6.disable=1" /etc/default/grub; then
    echo "IPv6 已经被禁用。"
  else
    sudo sed -i 's/GRUB_CMDLINE_LINUX_DEFAULT="/&ipv6.disable=1 /' /etc/default/grub
    sudo update-grub
    echo "IPv6 已禁用，请重启系统以使更改生效。"
  fi
}

#开启IPv6
openipv6() {
  clear
  # 编辑 GRUB 配置文件，移除禁用 IPv6 的参数
  if grep -q "ipv6.disable=1" /etc/default/grub; then
    sudo sed -i 's/ipv6.disable=1 //' /etc/default/grub
    sudo update-grub
    echo "IPv6 已启用，请重启系统以使更改生效。"
  else
    echo "IPv6 已经是启用状态。"
  fi
}


#开始菜单
start_menu() {
  clear
  echo && echo -e " TCP加速 一键安装管理脚本 from ${Red_font_prefix} from blog.vansour.top ${Font_color_suffix} 
 ${Green_font_prefix}1.${Font_color_suffix} 安装 BBR原版内核
 ${Green_font_prefix}2.${Font_color_suffix} 使用BBR+FQ_PIE加速
 ${Green_font_prefix}3.${Font_color_suffix} 开启ECN
 ${Green_font_prefix}4.${Font_color_suffix} 系统配置优化
 ${Green_font_prefix}5.${Font_color_suffix} 禁用IPv6
 ${Green_font_prefix}6.${Font_color_suffix} 开启IPv6
 ${Green_font_prefix}7.${Font_color_suffix} 卸载全部加速
 ${Green_font_prefix}0.${Font_color_suffix} 退出脚本 
————————————————————————————————————————————————————————————————" &&
  check_status
  get_system_info
  echo -e " 系统信息: ${Font_color_suffix}$opsy ${Green_font_prefix}$virtual${Font_color_suffix} $arch ${Green_font_prefix}$kern${Font_color_suffix} "
  if [[ ${kernel_status} == "noinstall" ]]; then
    echo -e " 当前状态: ${Green_font_prefix}未安装${Font_color_suffix} 加速内核 ${Red_font_prefix}请先安装内核${Font_color_suffix}"
  else
    echo -e " 当前状态: ${Green_font_prefix}已安装${Font_color_suffix} ${Red_font_prefix}${kernel_status}${Font_color_suffix} 加速内核 , ${Green_font_prefix}${run_status}${Font_color_suffix}"

  fi
  echo -e " 当前拥塞控制算法为: ${Green_font_prefix}${net_congestion_control}${Font_color_suffix} 当前队列算法为: ${Green_font_prefix}${net_qdisc}${Font_color_suffix} "

  read -p " 请输入数字 :" num
  case "$num" in
  1)
    installbbr
    ;;
  2)
    startbbrfqpie
    ;;
  3)
    startecn
    ;;
  4)
    optimizing_system
    ;;
  5)
    closeipv6
    ;;
  6)
    openipv6
    ;;
  7)
    remove_all
    ;;
  0)
    exit 1
    ;;
  *)
    clear
    echo -e "${Error}:请输入正确数字 [0-99]"
    sleep 5s
    start_menu
    ;;
  esac
}
#############内核管理组件#############

#删除多余内核
detele_kernel() {
  if [[ "${OS_type}" == "CentOS" ]]; then
    rpm_total=$(rpm -qa | grep kernel | grep -v "${kernel_version}" | grep -v "noarch" | wc -l)
    if [ "${rpm_total}" ] >"1"; then
      echo -e "检测到 ${rpm_total} 个其余内核，开始卸载..."
      for ((integer = 1; integer <= ${rpm_total}; integer++)); do
        rpm_del=$(rpm -qa | grep kernel | grep -v "${kernel_version}" | grep -v "noarch" | head -${integer})
        echo -e "开始卸载 ${rpm_del} 内核..."
        rpm --nodeps -e ${rpm_del}
        echo -e "卸载 ${rpm_del} 内核卸载完成，继续..."
      done
      echo --nodeps -e "内核卸载完毕，继续..."
    else
      echo -e " 检测到 内核 数量不正确，请检查 !" && exit 1
    fi
  elif [[ "${OS_type}" == "Debian" ]]; then
    deb_total=$(dpkg -l | grep linux-image | awk '{print $2}' | grep -v "${kernel_version}" | wc -l)
    if [ "${deb_total}" ] >"1"; then
      echo -e "检测到 ${deb_total} 个其余内核，开始卸载..."
      for ((integer = 1; integer <= ${deb_total}; integer++)); do
        deb_del=$(dpkg -l | grep linux-image | awk '{print $2}' | grep -v "${kernel_version}" | head -${integer})
        echo -e "开始卸载 ${deb_del} 内核..."
        apt-get purge -y ${deb_del}
        apt-get autoremove -y
        echo -e "卸载 ${deb_del} 内核卸载完成，继续..."
      done
      echo -e "内核卸载完毕，继续..."
    else
      echo -e " 检测到 内核 数量不正确，请检查 !" && exit 1
    fi
  fi
}

detele_kernel_head() {
  deb_total=$(dpkg -l | grep linux-headers | awk '{print $2}' | grep -v "${kernel_version}" | wc -l)
  if [ "${deb_total}" -gt "1" ]; then
    echo -e "检测到 ${deb_total} 个其余head内核，开始卸载..."
    for ((integer = 1; integer <= ${deb_total}; integer++)); do
      deb_del=$(dpkg -l | grep linux-headers | awk '{print $2}' | grep -v "${kernel_version}" | head -${integer})
      echo -e "开始卸载 ${deb_del} headers内核..."
      apt-get purge -y ${deb_del}
      apt-get autoremove -y
      echo -e "卸载 ${deb_del} 内核卸载完成，继续..."
    done
    echo -e "内核卸载完毕，继续..."
  else
    echo -e " 检测到 内核 数量不正确，请检查 !" && exit 1
  fi
}


#更新引导
BBR_grub() {
  if _exists "update-grub"; then
    update-grub
  elif [ -f "/usr/sbin/update-grub" ]; then
    /usr/sbin/update-grub
  else
    apt install grub2-common -y
    update-grub
  fi
}


#简单的检查内核
check_kernel() {
  if [[ -z "$(find /boot -type f -name 'vmlinuz-*' ! -name 'vmlinuz-*rescue*')" ]]; then
    echo -e "\033[0;31m警告: 未发现内核文件，请勿重启系统，不卸载内核版本选择30安装默认内核救急！\033[0m"
  else
    echo -e "\033[0;32m发现内核文件，看起来可以重启。\033[0m"
  fi
}


#############内核管理组件#############

#############系统检测组件#############

#检查系统
check_sys() {
  if [[ -f /etc/debian_version ]]; then
    debian_version=$(cat /etc/debian_version)
    if [[ "${debian_version}" == "12"* ]]; then
      OS_type="Debian"
      echo "检测为Debian 12系统。"
    else
      echo "检测到非Debian 12系统，脚本退出。"
      exit 1
    fi
  else
    echo "检测到非Debian系统，脚本退出。"
    exit 1
  fi

  #from https://github.com/oooldking

  _exists() {
    local cmd="$1"
    if eval type type >/dev/null 2>&1; then
      eval type "$cmd" >/dev/null 2>&1
    elif command >/dev/null 2>&1; then
      command -v "$cmd" >/dev/null 2>&1
    else
      which "$cmd" >/dev/null 2>&1
    fi
    local rt=$?
    return ${rt}
  }

  get_opsy() {
    if [ -f /etc/os-release ]; then
      awk -F'[= "]' '/PRETTY_NAME/{print $3,$4,$5}' /etc/os-release
    elif [ -f /etc/lsb-release ]; then
      awk -F'[="]+' '/DESCRIPTION/{print $2}' /etc/lsb-release
    elif [ -f /etc/system-release ]; then
      cat /etc/system-release | awk '{print $1,$2}'
    fi
  }

  get_system_info() {
    opsy=$(get_opsy)
    arch=$(uname -m)
    kern=$(uname -r)
    virt_check
  }

  # from LemonBench
  virt_check() {
    if [ -f "/usr/bin/systemd-detect-virt" ]; then
      Var_VirtType="$(/usr/bin/systemd-detect-virt)"
      # 虚拟机检测
      case "${Var_VirtType}" in
        qemu) virtual="QEMU" ;;
        kvm) virtual="KVM" ;;
        zvm) virtual="S390 Z/VM" ;;
        vmware) virtual="VMware" ;;
        microsoft) virtual="Microsoft Hyper-V" ;;
        xen) virtual="Xen Hypervisor" ;;
        bochs) virtual="BOCHS" ;;
        uml) virtual="User-mode Linux" ;;
        parallels) virtual="Parallels" ;;
        bhyve) virtual="FreeBSD Hypervisor" ;;
        openvz) virtual="OpenVZ" ;;
        lxc) virtual="LXC" ;;
        lxc-libvirt) virtual="LXC (libvirt)" ;;
        systemd-nspawn) virtual="Systemd nspawn" ;;
        docker) virtual="Docker" ;;
        rkt) virtual="RKT" ;;
        none)
          virtual="None"
          local Var_BIOSVendor
          Var_BIOSVendor="$(dmidecode -s bios-vendor)"
          if [ "${Var_BIOSVendor}" = "SeaBIOS" ]; then
            virtual="Unknown with SeaBIOS BIOS"
          else
            virtual="Dedicated with ${Var_BIOSVendor} BIOS"
          fi
          ;;
        *) virtual="Unknown" ;;
      esac
    elif [ -f "/.dockerenv" ]; then
      virtual="Docker"
    elif [ -c "/dev/lxss" ]; then
      virtual="Windows Subsystem for Linux (WSL)"
    else
      Var_VirtType="$(virt-what | xargs)"
      local Var_VirtTypeCount
      Var_VirtTypeCount="$(echo $Var_VirtTypeCount | wc -l)"
      if [ "${Var_VirtTypeCount}" -gt "1" ]; then
        virtual="echo ${Var_VirtType}"
        Var_VirtType="$(echo ${Var_VirtType} | head -n1)"
      elif [ "${Var_VirtTypeCount}" -eq "1" ] && [ "${Var_VirtType}" != "" ]; then
        virtual="${Var_VirtType}"
      else
        local Var_BIOSVendor
        Var_BIOSVendor="$(dmidecode -s bios-vendor)"
        if [ "${Var_BIOSVendor}" = "SeaBIOS" ]; then
          virtual="Unknown with SeaBIOS BIOS"
        else
          virtual="Dedicated with ${Var_BIOSVendor} BIOS"
        fi
      fi
    fi
  }

  #检查依赖
  if [[ "${OS_type}" == "Debian" ]]; then
    # 检查是否安装了 ca-certificates 包，如果未安装则安装
    if ! dpkg-query -W ca-certificates >/dev/null; then
      echo '正在安装 ca-certificates 包...'
      apt-get update || apt-get --allow-releaseinfo-change update && apt-get install ca-certificates -y
      update-ca-certificates
    fi
    echo 'CA证书检查OK'

    # 检查并安装 curl、wget 和 dmidecode 包
    for pkg in curl wget dmidecode; do
      if ! type $pkg >/dev/null 2>&1; then
        echo "未安装 $pkg，正在安装..."
        apt-get update || apt-get --allow-releaseinfo-change update && apt-get install $pkg -y
      else
        echo "$pkg 已安装。"
      fi
    done

    if [ -x "$(command -v lsb_release)" ]; then
      echo "lsb_release 已安装"
    else
      echo "lsb_release 未安装，现在开始安装..."
      apt-get install lsb-release -y
    fi

  else
    echo "不支持的操作系统发行版：${release}"
    exit 1
  fi
}

#检查系统当前状态
check_status() {
  kernel_version=$(uname -r)
  kernel_version_base=$(echo "${kernel_version}" | awk -F "-" '{print $1}')
  net_congestion_control=$(cat /proc/sys/net/ipv4/tcp_congestion_control)
  net_qdisc=$(cat /proc/sys/net/core/default_qdisc)

  if [[ ${kernel_version} == *bbrplus* ]]; then
    kernel_status="BBRplus"
  elif [[ ${kernel_version} == *4.9.0-4* || ${kernel_version} == *4.15.0-30* || ${kernel_version} == *4.8.0-36* || ${kernel_version} == *3.16.0-77* || ${kernel_version} == *3.16.0-4* || ${kernel_version} == *3.2.0-4* || ${kernel_version} == *4.11.2-1* || ${kernel_version} == *2.6.32-504* || ${kernel_version} == *4.4.0-47* || ${kernel_version} == *3.13.0-29* ]]; then
    kernel_status="Lotserver"
  elif [[ ${kernel_version_base} =~ ^(4\.9|4\.1[5-9]|4\.[2-9]|5\.|6\.) ]]; then
    kernel_status="BBR"
  else
    kernel_status="noinstall"
  fi

  case ${kernel_status} in
    "BBR")
      if [[ ${net_congestion_control} == "bbr" ]]; then
        run_status="BBR启动成功"
      elif [[ ${net_congestion_control} == "bbr2" ]]; then
        run_status="BBR2启动成功"
      elif [[ ${net_congestion_control} == "tsunami" ]]; then
        if lsmod | grep -q "tcp_tsunami"; then
          run_status="BBR魔改版启动成功"
        else
          run_status="BBR魔改版启动失败"
        fi
      elif [[ ${net_congestion_control} == "nanqinlang" ]]; then
        if lsmod | grep -q "tcp_nanqinlang"; then
          run_status="暴力BBR魔改版启动成功"
        else
          run_status="暴力BBR魔改版启动失败"
        fi
      else
        run_status="未安装加速模块"
      fi
      ;;
    "Lotserver")
      if [[ -e /appex/bin/lotServer.sh ]]; then
        if bash /appex/bin/lotServer.sh status | grep -q "running!"; then
          run_status="启动成功"
        else
          run_status="启动失败"
        fi
      else
        run_status="未安装加速模块"
      fi
      ;;
    "BBRplus")
      if [[ ${net_congestion_control} == "bbrplus" ]]; then
        run_status="BBRplus启动成功"
      elif [[ ${net_congestion_control} == "bbr" ]]; then
        run_status="BBR启动成功"
      else
        run_status="未安装加速模块"
      fi
      ;;
    *)
      run_status="未安装加速模块"
      ;;
  esac

#############系统检测组件#############
apt_update
check_sys
[[ "${OS_type}" == "Debian" ]] && [[ "${OS_type}" == "CentOS" ]] && echo -e "${Error} 本脚本不支持当前系统 ${release} !" && exit 1
start_menu