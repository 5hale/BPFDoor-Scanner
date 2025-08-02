#!/bin/sh
#------------------------------------------------------------------------------
# KISA BPFDoor 악성코드 점검 스크립트 (POSIX 호환 쉘 스크립트)
# 작성: 한국인터넷진흥원(KISA) 'BPFDoor 악성코드 점검 가이드' 기준으로 작성
# 배포일: 2025년 5월 12일 (가이드 문서 기준)
# 참고: BPFDoor는 리눅스 시스템에 은밀히 상주하는 백도어 악성코드로,
#       Berkeley Packet Filter(BPF) 기술을 악용하여 포트를 열지 않고 명령을 수신합니다.
#       아래 스크립트는 BPFDoor 감염 여부를 종합적으로 점검합니다.
# 요구사항:
#  1. 모든 점검 항목(뮤텍스 락파일, 자동실행, BPF 필터, RAW 소켓, 환경변수, 포트, 위장 프로세스)을 포함
#  2. 실행 시 메뉴를 제공하여 개별 점검 또는 전체 점검 선택 가능
#  3. 각 점검 전에 어떤 검사인지 설명을 출력
#  4. 검사 결과 요약은 콘솔에 '의심 항목 있음' 또는 '정상' 또는 '검사 실패'로 표시
#     (상세 결과는 별도 로그 파일에 기록)
#  5. sh 단독 실행 가능 (필요시 sudo 권한 사용 명령은 스크립트에 명시)
#  6. bpfdoor_env.sh, bpfdoor_bpf.sh 스크립트의 기능을 내장 (외부 파일 불필요)
#  7. 명령어 실패 시 에러 메시지는 사용자 콘솔에 표시하지 않고 로그에만 기록, 콘솔에는 '검사 실패' 출력
#  8. 각 점검 블록에 번호, 설명, 주의사항 등을 주석으로 포함 (한국어)
#------------------------------------------------------------------------------


# 0. (사전 체크) 관리자 권한 확인
if [ "$(id -u)" -ne 0 ]; then
  echo "※ 관리자(root) 권한으로 실행해 주세요. (sudo 사용 또는 root로 로그인)"
  exit 1
fi

# 로그 파일 설정 (/tmp/bpfdoor_check_YYYYMMDD_HHMMSS.txt)
LOG_FILE="/tmp/bpfdoor_check_$(date '+%Y%m%d_%H%M%S').txt"
# 로그 파일 생성
touch "$LOG_FILE" 2>/dev/null
if [ $? -ne 0 ]; then
  echo "로그 파일 생성 실패: $LOG_FILE"
  exit 1
fi

#--- 각 검사 항목을 함수로 정의 ------------------------------------------------
check_1() {
    echo "[1] 락파일 점검 - /var/run 디렉터리의 0바이트 뮤텍스/락 파일 존재 여부 확인"
    #--- (점검 설명): /var/run/*.pid 또는 *.lock 중 크기 0인 파일을 찾고, 권한이 644인 경우 악성코드 생성 락파일로 의심
    #--- (주의사항): 정상 PID 파일은 프로세스 ID를 포함하여 0바이트가 아니므로 0바이트이면 비정상.
    #               파일 권한이 rw-r--r-- (644)로 설정된 0바이트 파일은 BPFDoor 악성코드 락파일일 가능성이 높음.

    # /var/run에서 *.pid, *.lock 파일 중 크기가 0인 파일 목록 추출
    suspicious_lock_files=""
    for file in /var/run/*.pid /var/run/*.lock; do
        # 글로빈 경로에 매칭되는 파일이 없을 경우 그대로 루프 진행
        [ -e "$file" ] || continue
        # 파일 크기가 0인지 검사
        if [ -f "$file" ] && [ ! -s "$file" ]; then
            # 파일 권한 확인 (8진수 모드 추출). stat 명령 사용 (stat은 GNU coreutils, POSIX에는 없으나 대부분 Linux에 존재)
            perm=$(stat -c '%a' "$file" 2>>"$LOG_FILE")
            if [ "$perm" = "644" ]; then
                suspicious_lock_files="$suspicious_lock_files\n$file (size=0, mode=644)"
            fi
        fi
    done

    # 결과 처리
    if [ -n "$suspicious_lock_files" ]; then
        echo "의심 항목 있음"
        # 로그에 상세 결과 기록
        echo "===== [1] 락파일 점검 =====" >> "$LOG_FILE"
        echo "다음 0바이트 락/뮤텍스 파일이 발견되었습니다 (권한 644):" >> "$LOG_FILE"
        # suspicious_lock_files 변수에 누적된 목록 출력 (처음에 개행 문자가 있을 수 있으므로 sed로 정리)
        echo -e "$suspicious_lock_files" | sed '/^$/d' >> "$LOG_FILE"
    else
        echo "정상"
        echo "===== [1] 락파일 점검 =====" >> "$LOG_FILE"
        echo "정상 - 0바이트 락파일이 발견되지 않았습니다." >> "$LOG_FILE"
    fi
}

check_2() {
    echo "[2] 자동실행 점검 - /etc/sysconfig 디렉터리 내 악성 스크립트 등록 여부 확인"
    #--- (점검 설명): /etc/sysconfig/ 경로 아래에 악성코드 실행을 위한 명령이 등록되어 있는지 검색
    #                (예: "[ -f /malware_path ] && /malware_path" 형태로 파일 존재 시 실행하도록 한 행)
    #--- (주의사항): /etc/sysconfig/* 대부분 설정파일이며, 위와 같은 실행 명령이 존재하면 악성코드 자동실행을 의심.
    #                grep 사용시 호환성 문제 발생 시 find+egrep 방식 사용.

    echo "의심 명령어 패턴을 검색 중... (grep 이용)" >> "$LOG_FILE"
    # /etc/sysconfig 내 '[ -f /... ] && /...' 패턴 검색 (악성 경로 등록 패턴)
    # - 패턴: "[" 로 시작하여 "-f <절대경로>" 확인 후 "&& <절대경로 실행>"로 이어지는 문자열
    auto_matches=$(grep -R -E '\[\s*-f\s+/.+\]\s*&&\s*/' /etc/sysconfig/ 2>>"$LOG_FILE")
    # grep 종료 코드 2: 오류 (디렉터리 없음 등), 1: 매치 없음, 0: 매치 발견
    grep_status=$?
    echo "grep 종료 코드: $grep_status" >> "$LOG_FILE"
    if [ $grep_status -ne 0 ] && [ $grep_status -ne 1 ]; then
        # grep 실행 자체에 실패한 경우 (옵션 미지원 등) - find와 egrep 대체 사용
        echo "grep -R 실행에 문제가 발생하여 find로 재시도" >> "$LOG_FILE"
        auto_matches=$(find /etc/sysconfig/ -type f -exec grep -E '\[\s*-f\s+/.+\]\s*&&\s*/' {} + 2>>"$LOG_FILE")
        grep_status=$?
        echo "find|grep 종료 코드: $grep_status" >> "$LOG_FILE"
    fi

    if [ -n "$auto_matches" ]; then
        echo "의심 항목 있음"
        echo "===== [2] 자동실행 점검 =====" >> "$LOG_FILE"
        echo "/etc/sysconfig 내 악성코드 자동실행 의심 항목:" >> "$LOG_FILE"
        # 다중 라인이 담겼을 수 있으므로 각각 출력
        echo "$auto_matches" >> "$LOG_FILE"
        echo "(※ 위 파일에서 악성 경로 실행 명령을 발견)" >> "$LOG_FILE"
    else
        echo "정상"
        echo "===== [2] 자동실행 점검 =====" >> "$LOG_FILE"
        echo "정상 - /etc/sysconfig 내 특이한 자동실행 명령을 찾지 못했습니다." >> "$LOG_FILE"
    fi
}

check_3() {
    echo "[3] BPF 필터 점검 - ss 명령어를 통해 커널 BPF 백도어 필터 존재 여부 확인"
    #--- (점검 설명): 현재 시스템 소켓에 BPF 필터가 설정되었는지 확인.
    #                ss 명령으로 소켓 상세정보(-0 옵션) 및 프로세스(-p), BPF필터(-b)를 조회하여
    #                악성코드에서 사용하는 매직 넘버(필터 내 특정 상수 값) 존재 여부 검사.
    #--- (주의사항): Linux 커널 3.2 이상 + iproute2 4.0 이상에서만 BPF 필터 정보 확인 가능.
    #                (구형 시스템(CentOS6 등)에서는 이 검사를 건너뜀)
    #                발견되는 매직 넘버는 위협 행위자가 변경 가능하므로 참고용이며, 존재 시 악성 의심.
    #                (예: 21139, 29269, 960051513, 36204, 40783 등의 숫자 또는 0x5293, 0x7255 등)
    #                ss 명령이 실패하면 '검사 실패' 처리.
    BPF_MAGIC_DEC="21139|29269|960051513|36204|40783"
    BPF_MAGIC_HEX="0x5293|0x7255|0x39393939|0x8D6C|0x9F4F"
    # ss 명령 실행 (stderr는 로그로, stdout은 변수로 저장)
    bpf_output=$(ss -0pb 2>>"$LOG_FILE")
    ss_status=$?
    if [ $ss_status -ne 0 ]; then
        # ss 명령 실패 (예: 지원 안됨 또는 권한 문제 등)
        echo "검사 실패"
        echo "===== [3] BPF 필터 점검 =====" >> "$LOG_FILE"
        echo "오류: ss 명령 실행에 실패했습니다. (iproute2 미설치 또는 커널 미지원)" >> "$LOG_FILE"
        else
        # ss 명령 성공 -> BPF 필터 내용에 매직 넘버 존재 여부 검색
        echo "$bpf_output" | grep -Eq "$BPF_MAGIC_DEC|$BPF_MAGIC_HEX"
        if [ $? -eq 0 ]; then
            echo "의심 항목 있음"
            echo "===== [3] BPF 필터 점검 =====" >> "$LOG_FILE"
            echo "ss -0pb 출력 내 악성 의심 BPF 매직넘버를 발견했습니다:" >> "$LOG_FILE"
            # 의심 부분 추출하여 로그에 기록 (매직넘버가 포함된 라인과 바로 위 소켓 정보 라인)
            echo "$bpf_output" | grep -E -B1 "$BPF_MAGIC_DEC|$BPF_MAGIC_HEX" >> "$LOG_FILE"
            echo "(※ 위 ss 출력에서 붉은색 표시된 숫자가 악성 의심 BPF 필터 값)" >> "$LOG_FILE"
        else
            echo "정상"
            echo "===== [3] BPF 필터 점검 =====" >> "$LOG_FILE"
            echo "정상 - BPF 필터에 악성 의심 패턴이 발견되지 않았습니다." >> "$LOG_FILE"
        fi
    fi
}

check_4() {
    echo "[4] RAW 소켓 점검 - RAW/PACKET 소켓을 사용하는 프로세스 목록 확인"
    #--- (점검 설명): 시스템 내 RAW 소켓(SOCK_RAW) 또는 패킷 소켓(SOCK_DGRAM, AF_PACKET)을 사용 중인 프로세스를 탐지.
    #                BPFDoor 악성코드는 포트를 열지 않고도 패킷을 수신하기 위해 RAW 소켓을 개방하므로 해당 프로세스로 의심 가능.
    #--- (주의사항): 네트워크 스NI퍼, 모니터링 데몬 등 정상 서비스도 RAW/패킷 소켓을 사용할 수 있어 오탐 가능.
    #                특히 "IP type=SOCK_DGRAM" (UDP 소켓) 항목은 정상 프로세스(DBUS 등)도 포착될 수 있으므로 결과 해석에 주의.
    #                또한 /proc 전체를 검색하므로 시스템 부하가 걸릴 수 있음.
    #                (필요시 ①락파일 발견 ②BPF 없음 ③RAW 1차결과 없음인 경우만 2차 검사를 수행하는 방식 권장)
    #  -> 본 스크립트에서는 포착된 RAW/패킷 소켓 보유 프로세스를 모두 로그에 기록하고, 한 건이라도 존재 시 '의심 항목 있음'으로 표시.
    has_lsof=0; has_ss_cmd=0
    command -v lsof >/dev/null 2>&1 && has_lsof=1
    command -v ss   >/dev/null 2>&1 && has_ss_cmd=1

    suspicious_raw=0   # RAW 소켓 사용 의심 존재 여부
    raw_pid_list=""    # SOCK_RAW/IP (또는 SOCK_DGRAM(IP)) 사용 프로세스 PIDs
    packet_pid_list="" # PACKET 소켓 사용 프로세스 PIDs

    # 4-1. lsof 명령으로 RAW/DGRAM 소켓 사용 프로세스 확인 (lsof이 있을 경우)
    if [ $has_lsof -eq 1 ]; then
        # lsof 출력에서 "IP type=SOCK_RAW" 또는 "IP type=SOCK_DGRAM" 문자열을 grep
        raw_pids=$(lsof -nP 2>/dev/null | grep -E "IP\s+type=(SOCK_RAW|SOCK_DGRAM)" | awk '{print $2}' | sort -u)
        if [ -n "$raw_pids" ]; then
            suspicious_raw=1
            raw_pid_list="$raw_pids"
        fi
    else
        echo "(참고) lsof 명령을 사용할 수 없습니다. ss 명령으로 대체합니다." >> "$LOG_FILE"
        # 4-3. (대체) ss 명령으로 RAW 소켓 탐지 (IPPROTO_ICMP=1, TCP=6, UDP=17 프로토콜의 raw 소켓)
        # ss -apn 출력에서 " <IP>:1 ", " <IP>:6 ", " <IP>:17 " 형태를 찾음 (ICMP, TCP, UDP의 raw 소켓)
        raw_pids=$(ss -apn 2>>"$LOG_FILE" | awk '/:[1|6|17] / { if(match($0, /pid=([0-9]+)/, a)) print a[1] }' | sort -u)
        if [ -n "$raw_pids" ]; then
            suspicious_raw=1
            raw_pid_list="$raw_pids"
        fi
    fi

    # 4-2. /proc/net/packet을 이용한 PACKET 소켓 사용 프로세스 확인 (AF_PACKET 소켓 탐지)
    # /proc/net/packet 파일에서 프로토콜 0800(IPv4) & 패밀리 0(AF_PACKET)의 inode 추출
    packet_inodes=$(awk '$4=="0800" && $5=="0" {print $9}' /proc/net/packet 2>>"$LOG_FILE")
    if [ -n "$packet_inodes" ]; then
    for inode in $packet_inodes; do
        # 해당 inode를 사용 중인 프로세스 PID 찾기 (/proc/*/fdinfo/* 파일 내 "ino:<inode>" 검색)
        pid_matches=$(grep -R -E "ino:\s*$inode" /proc/*/fdinfo 2>/dev/null | awk -F/ '{print $3}')
        if [ -n "$pid_matches" ]; then
            packet_pid_list="$packet_pid_list $pid_matches"
        fi
    done
    # 중복 PID 정리
    packet_pid_list=$(echo "$packet_pid_list" | tr ' ' '\n' | sort -u | xargs)
        if [ -n "$packet_pid_list" ]; then
            suspicious_raw=1
        fi
    fi

    # 결과 출력 및 로그 기록
    if [ $suspicious_raw -eq 1 ]; then
        echo "의심 항목 있음"
        echo "===== [4] RAW 소켓 점검 =====" >> "$LOG_FILE"
        if [ -n "$raw_pid_list" ]; then
            echo "[*] SOCK_RAW/SOCK_DGRAM 소켓 사용 프로세스 목록:" >> "$LOG_FILE"
            # 각 PID의 프로세스 정보를 ps로 출력
            # (lsof/ss 기반 탐지 결과 - Raw IP 소켓 또는 UDP DGRAM 소켓 사용 프로세스)
            ps -fp $(echo "$raw_pid_list" | tr ' ' ' ') >> "$LOG_FILE"
        fi
        if [ -n "$packet_pid_list" ]; then
            echo "[*] PACKET 소켓(AF_PACKET) 사용 프로세스 목록:" >> "$LOG_FILE"
            ps -fp $(echo "$packet_pid_list" | tr ' ' ' ') >> "$LOG_FILE"
        fi
        echo "(※ 위 프로세스 중 정상 시스템 서비스가 포함될 수 있으므로 추가 분석 필요)" >> "$LOG_FILE"
    else
        echo "정상"
        echo "===== [4] RAW 소켓 점검 =====" >> "$LOG_FILE"
        echo "정상 - RAW/패킷 소켓을 사용 중인 비정상 프로세스를 발견하지 못했습니다." >> "$LOG_FILE"
    fi
}

check_5() {
    echo "[5] 환경변수 점검 - 프로세스 환경에 의심스러운 값 존재 여부 확인"
    #--- (점검 설명): 모든 실행 중인 프로세스의 환경 변수에서 공격자에 의해 설정되는 이상징후 값을 검사.
    #                (BPFDoor 악성코드가 셸 연결 시 사용하는 환경변수: HOME=/tmp, HISTFILE=/dev/null, MYSQL_HISTFILE=/dev/null)
    #--- (주의사항): 해당 값 모두가 설정된 프로세스는 악성코드에 의해 실행된 쉘일 가능성이 높음.
    #                (일반적으로 시스템 프로세스의 HOME은 /tmp가 아니며, HISTFILE 등을 /dev/null로 지정하는 경우는 드묾)
    #                root 권한으로 실행해야 모든 프로세스의 환경을 확인 가능.

    suspicious_env_pids=""  # 의심 환경변수 발견된 프로세스 PID들
    # 목표 패턴들
    target1="HOME=/tmp"
    target2="HISTFILE=/dev/null"
    target3="MYSQL_HISTFILE=/dev/null"
    for pid_dir in /proc/[0-9]*; do
        pid=${pid_dir#/proc/}
        # /proc/<pid>/environ 파일 읽기 (NUL-separated 환경변수 문자열)
        # strings 명령으로 가독성 있게 추출 (대신 tr로 NUL -> newline 대체 가능)
        if [ -r "/proc/$pid/environ" ]; then
            env_strings=$(tr '\0' '\n' < "/proc/$pid/environ")
            # 모든 타겟 문자열을 포함하는지 검사
            echo "$env_strings" | grep -q "^${target1}$" && \
            echo "$env_strings" | grep -q "^${target2}$" && \
            echo "$env_strings" | grep -q "^${target3}$"
            if [ $? -eq 0 ]; then
                suspicious_env_pids="$suspicious_env_pids $pid"
            fi
        fi
    done

    if [ -n "$suspicious_env_pids" ]; then
        echo "의심 항목 있음"
        echo "===== [5] 환경변수 점검 =====" >> "$LOG_FILE"
        echo "HOME=/tmp, HISTFILE=/dev/null 등 모든 의심 환경변수를 포함한 프로세스 발견:" >> "$LOG_FILE"
        # 중복 정리 및 ps 출력
        suspicious_env_pids=$(echo "$suspicious_env_pids" | tr ' ' '\n' | sort -u | xargs)
        ps -fp $(echo "$suspicious_env_pids" | tr ' ' ' ') >> "$LOG_FILE"
        # 해당 프로세스 실행 파일 경로 확인
        for pid in $suspicious_env_pids; do
            exe_link=$(readlink "/proc/$pid/exe")
            echo "PID $pid -> Executable: $exe_link" >> "$LOG_FILE"
        done
        echo "(※ 위 프로세스는 모든 의심 환경변수를 갖고 있어 악성 셸 프로세스로 의심됩니다.)" >> "$LOG_FILE"
    else
        echo "정상"
        echo "===== [5] 환경변수 점검 =====" >> "$LOG_FILE"
        echo "정상 - 의심 환경변수(HOME=/tmp 등)를 가진 프로세스를 발견하지 못했습니다." >> "$LOG_FILE"
    fi
}

check_6() {
    echo "[6] 포트 사용 점검 - 특정 포트 범위(42391~43390, 8000) 사용 프로세스 확인"
    #--- (점검 설명): BPFDoor 악성코드에서 사용된 것으로 알려진 포트(42391-43390 사이, 8000)를 사용 중인 프로세스를 탐지.
    #                (주로 악성코드가 Bind Shell로 열어놓은 포트 또는 C2 통신 포트)
    #--- (주의사항): 이 포트들을 정상적으로 사용하는 서비스도 있을 수 있으므로 발견 시 추가 분석 필요.
    #                (예: 8000 포트 - 웹 프록시나 테스트 서버 등)
    has_ss=0; has_netstat=0
    command -v ss >/dev/null 2>&1 && has_ss=1
    command -v netstat >/dev/null 2>&1 && has_netstat=1

    port_pattern=':(4239[1-9]|42[4-9][0-9]{2}|43[0-2][0-9]{2}|433[0-8][0-9]|43390)\b|:8000\b'
    suspicious_ports_output=""
    if [ $has_ss -eq 1 ]; then
        suspicious_ports_output=$(ss -atunp 2>>"$LOG_FILE" | grep -E "$port_pattern")
    elif [ $has_netstat -eq 1 ]; then
        suspicious_ports_output=$(netstat -anp 2>>"$LOG_FILE" | grep -E -w "tcp|udp" | grep -E "$port_pattern")
    else
        echo "검사 실패"
        echo "===== [6] 포트 사용 점검 =====" >> "$LOG_FILE"
        echo "오류: ss 또는 netstat 명령을 사용할 수 없어 포트 점검을 수행하지 못했습니다." >> "$LOG_FILE"
        break  # case문 종료 (혹은 exit 1)
    fi

    if [ -n "$suspicious_ports_output" ]; then
        echo "의심 항목 있음"
        echo "===== [6] 포트 사용 점검 =====" >> "$LOG_FILE"
        echo "다음 포트(42391~43390, 8000)를 사용 중인 프로세스를 발견:" >> "$LOG_FILE"
        echo "$suspicious_ports_output" >> "$LOG_FILE"
        echo "(※ 상기 포트 사용은 악성코드 활동 의심 징후이며, 정상 프로세스인 경우 오탐 가능성 있음)" >> "$LOG_FILE"
    else
        echo "정상"
        echo "===== [6] 포트 사용 점검 =====" >> "$LOG_FILE"
        echo "정상 - 해당 포트 범위를 사용 중인 프로세스를 찾지 못했습니다." >> "$LOG_FILE"
    fi
}

check_7() {
    echo "[7] 위장 프로세스 점검 - 정상 프로세스로 가장한 악성 프로세스 여부 확인"
    #--- (점검 설명): 악성코드가 시스템의 정상 프로세스 이름으로 위장해 실행 중인지 확인.
    #                (예: abrtd, cmathreshd, pickup 등 프로세스가 보이지만 실제 실행파일 경로가 /dev/shm 등 비정상 경로인 경우)
    #--- (주의사항): /dev/shm는 메모리 상 임시 파일 시스템으로, 여기에 실행 파일을 올려두고 실행 후 파일을 삭제하는 기법이 악성코드에서 사용됨.
    #                해당 경로에서 동작 중인 바이너리 발견 시 악성으로 강하게 의심됨.
    #                (일부 프로세스는 파일 삭제 후 (deleted)로 표시될 수 있음)
    suspicious_masked_pids=""
    for pid_dir in /proc/[0-9]*; do
        pid=${pid_dir#/proc/}
        if [ -L "/proc/$pid/exe" ]; then
            exe_path=$(readlink "/proc/$pid/exe" 2>/dev/null)
            # exe_path가 /dev/shm 경로를 포함하는지 확인
            if [ -n "$exe_path" ] && echo "$exe_path" | grep -q "^/dev/shm"; then
                suspicious_masked_pids="$suspicious_masked_pids $pid"
            fi
        fi
    done

    if [ -n "$suspicious_masked_pids" ]; then
        echo "의심 항목 있음"
        echo "===== [7] 위장 프로세스 점검 =====" >> "$LOG_FILE"
        echo "/dev/shm 경로에서 실행 중인 위장 프로세스 발견:" >> "$LOG_FILE"
        # 중복 PID 제거
        suspicious_masked_pids=$(echo "$suspicious_masked_pids" | tr ' ' '\n' | sort -u | xargs)
        # 각 PID의 프로세스명과 경로 기록
        for pid in $suspicious_masked_pids; do
            proc_name=$(ps -p "$pid" -o comm=)
            exe_link=$(readlink "/proc/$pid/exe")
            echo "PID $pid - Name: $proc_name -> Executable: $exe_link" >> "$LOG_FILE"
        done
        echo "(※ 상기 프로세스들은 정상 시스템 경로가 아닌 /dev/shm 에서 실행되고 있어 악성으로 의심됩니다.)" >> "$LOG_FILE"
    else
        echo "정상"
        echo "===== [7] 위장 프로세스 점검 =====" >> "$LOG_FILE"
        echo "정상 - /dev/shm 경로에서 실행 중인 의심 프로세스를 발견하지 못했습니다." >> "$LOG_FILE"
    fi
}

all_checks() {
  echo "[0] 전체 점검을 시작합니다..."
  check_1; echo
  check_2; echo
  check_3; echo
  check_4; echo
  check_5; echo
  check_6; echo
  check_7; echo
}
#-------------------------------------------------------------------------
# 메뉴 출력
echo "================================================="
echo " BPFDoor 악성코드 점검 메뉴"
echo "-------------------------------------------------"
echo " 1. 락파일 점검 (뮤텍스/락 0바이트 파일 확인)"
echo " 2. 자동실행 점검 (/etc/sysconfig 악성 등록 확인)"
echo " 3. BPF 필터 점검 (BPF 프로그램 존재 여부 확인)"
echo " 4. RAW 소켓 점검 (SOCK_RAW/DGRAM 프로세스 확인)"
echo " 5. 환경변수 이상 점검 (HOME=/tmp 등 확인)"
echo " 6. 포트 사용 점검 (42391~43390, 8000 포트 확인)"
echo " 7. 위장 프로세스 점검 (/dev/shm에서 실행 여부)"
echo " 0. 전체 점검 (1~7 모두 실행)"
echo "================================================="
echo "※ 자세한 검사 결과는 로그 파일에 저장됩니다: $LOG_FILE"
echo

# 사용자 입력 받기
printf "원하는 검사 번호를 선택하세요: "
read -r choice

# 입력된 선택에 따라 해당 검사 수행 (case 문 사용)
case "$choice" in
  1) check_1 ;;     # 1. 락파일 점검
  2) check_2 ;;     # 2. 자동실행 점검
  3) check_3 ;;     # 3. BPF 필터 점검
  4) check_4 ;;     # 4. RAW 소켓 사용 프로세스 탐지
  5) check_5 ;;     # 5. 환경 변수 이상 여부 점검
  6) check_6 ;;     # 6. 의심 포트 사용 탐지
  7) check_7 ;;     # 7. 위장 프로세스명 확인
  0) all_checks ;;  # 0. 전체 점검 (1~7 순서대로 실행)
  *) echo "잘못된 선택입니다. 스크립트를 종료합니다.";; # 그 외 입력 -> 잘못된 선택 처리
esac

# 스크립트 종료 시 안내 메시지
echo
echo "※ 점검이 완료되었습니다. 상세 결과 로그: $LOG_FILE"
