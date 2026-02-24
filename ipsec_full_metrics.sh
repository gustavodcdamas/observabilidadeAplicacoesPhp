#!/bin/bash
# /usr/local/bin/ipsec_full_metrics.sh

OUTPUT="/var/lib/node_exporter/ipsec.prom"
TEMP="${OUTPUT}.tmp"
LOCK="/var/run/ipsec_exporter.lock"
TIMEOUT=50

# Lock para evitar execuções simultâneas
exec 200>"$LOCK"
flock -n 200 || { echo "Script já em execução" >&2; exit 1; }

trap 'rm -f "$TEMP" "$LOCK"' EXIT

# Função para sanitizar nomes
sanitize() {
    echo "$1" | tr -d '"{}' | tr ' /' '_-' | tr -cd '[:alnum:]_-' | sed 's/^-\+//;s/-\+$//'
}

# Função para executar comando com timeout
run_with_timeout() {
    timeout "$TIMEOUT" "$@" 2>/dev/null
}

# ==============================================================
# DESCOBERTA AUTOMÁTICA DE IPs REMOTOS
# ==============================================================

discover_remote_ips() {
    declare -gA REMOTE_IPS
    
    echo "# Descobrindo IPs remotos..." >&2
    
    # Método 1: Extrair da configuração do IPSec
    if [ -d /etc/ipsec.d ]; then
        while IFS= read -r file; do
            [ ! -f "$file" ] && continue
            
            conn_name=""
            right_ip=""
            right_subnet=""
            
            while IFS= read -r line; do
                # Nome da conexão
                if [[ $line =~ ^conn[[:space:]]+(.+)$ ]]; then
                    conn_name=$(sanitize "${BASH_REMATCH[1]}")
                fi
                
                # IP remoto (right)
                if [[ $line =~ right=([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+) ]]; then
                    right_ip="${BASH_REMATCH[1]}"
                fi
                
                # Subnet remota (rightsubnet)
                if [[ $line =~ rightsubnet=([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+) ]]; then
                    right_subnet="${BASH_REMATCH[1]}"
                fi
                
            done < "$file"
            
            # Armazenar IPs descobertos
            if [ -n "$conn_name" ]; then
                # Priorizar subnet (geralmente é o IP que queremos pingar)
                if [ -n "$right_subnet" ]; then
                    REMOTE_IPS["$conn_name"]="$right_subnet"
                    echo " ✓ $conn_name -> $right_subnet (subnet)" >&2
                elif [ -n "$right_ip" ]; then
                    REMOTE_IPS["$conn_name"]="$right_ip"
                    echo " ✓ $conn_name -> $right_ip (gateway)" >&2
                fi
            fi
        done < <(find /etc/ipsec.d -type f -name "*.conf" 2>/dev/null)
    fi
    
    # Método 2: Extrair do ipsec.conf principal
    if [ -f /etc/ipsec.conf ]; then
        conn_name=""
        right_ip=""
        right_subnet=""
        
        while IFS= read -r line; do
            if [[ $line =~ ^conn[[:space:]]+(.+)$ ]]; then
                # Salvar conexão anterior
                if [ -n "$conn_name" ] && [ -z "${REMOTE_IPS[$conn_name]}" ]; then
                    if [ -n "$right_subnet" ]; then
                        REMOTE_IPS["$conn_name"]="$right_subnet"
                        echo " ✓ $conn_name -> $right_subnet (subnet)" >&2
                    elif [ -n "$right_ip" ]; then
                        REMOTE_IPS["$conn_name"]="$right_ip"
                        echo " ✓ $conn_name -> $right_ip (gateway)" >&2
                    fi
                fi
                
                # Nova conexão
                conn_name=$(sanitize "${BASH_REMATCH[1]}")
                right_ip=""
                right_subnet=""
            fi
            
            [[ $line =~ right=([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+) ]] && right_ip="${BASH_REMATCH[1]}"
            [[ $line =~ rightsubnet=([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+) ]] && right_subnet="${BASH_REMATCH[1]}"
            
        done < /etc/ipsec.conf
        
        # Última conexão
        if [ -n "$conn_name" ] && [ -z "${REMOTE_IPS[$conn_name]}" ]; then
            if [ -n "$right_subnet" ]; then
                REMOTE_IPS["$conn_name"]="$right_subnet"
                echo " ✓ $conn_name -> $right_subnet (subnet)" >&2
            elif [ -n "$right_ip" ]; then
                REMOTE_IPS["$conn_name"]="$right_ip"
                echo " ✓ $conn_name -> $right_ip (gateway)" >&2
            fi
        fi
    fi
    
    # Método 3: Extrair de túneis ativos (fallback)
    while IFS= read -r line; do
        if [[ $line =~ \"([^\"]+)\".*===([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+) ]]; then
            tunnel=$(sanitize "${BASH_REMATCH[1]}")
            ip="${BASH_REMATCH[2]}"
            
            if [ -n "$tunnel" ] && [ -n "$ip" ] && [ -z "${REMOTE_IPS[$tunnel]}" ]; then
                REMOTE_IPS["$tunnel"]="$ip"
                echo " ✓ $tunnel -> $ip (ativo)" >&2
            fi
        fi
    done < <(run_with_timeout ipsec status)
    
    echo "# Total de IPs descobertos: ${#REMOTE_IPS[@]}" >&2
}

# ==============================================================
# PING PARALELO OTIMIZADO
# ==============================================================

ping_remote_ips() {
    declare -gA TUNNEL_LATENCY
    
    if [ ${#REMOTE_IPS[@]} -eq 0 ]; then
        echo "# Nenhum IP remoto para pingar" >&2
        return
    fi
    
    echo "# Pingando ${#REMOTE_IPS[@]} destinos remotos..." >&2
    
    local pids=()
    local results_dir="/tmp/ipsec_ping_$$"
    mkdir -p "$results_dir"
    
    # Função para pingar em background
    ping_host() {
        local tunnel="$1"
        local ip="$2"
        local output="$3"
        
        # Ping com timeout curto
        latency=$(timeout 2 ping -c 1 -W 1 -q "$ip" 2>/dev/null | \
                  awk -F'/' '/^rtt/ {print $5}' || echo "0")
        
        if [ -n "$latency" ] && [ "$latency" != "0" ]; then
            echo "${tunnel}|${ip}|${latency}" > "$output"
        fi
    }
    
    # Iniciar pings em paralelo (máximo 20 simultâneos)
    local count=0
    local max_parallel=20
    
    for tunnel in "${!REMOTE_IPS[@]}"; do
        ip="${REMOTE_IPS[$tunnel]}"
        output="$results_dir/${tunnel}.result"
        
        ping_host "$tunnel" "$ip" "$output" &
        pids+=($!)
        
        ((count++))
        
        # Limitar paralelismo
        if [ $count -ge $max_parallel ]; then
            wait "${pids[@]}"
            pids=()
            count=0
        fi
    done
    
    # Aguardar últimos processos
    [ ${#pids[@]} -gt 0 ] && wait "${pids[@]}"
    
    # Coletar resultados
    for result_file in "$results_dir"/*.result; do
        [ ! -f "$result_file" ] && continue
        
        while IFS='|' read -r tunnel ip latency; do
            TUNNEL_LATENCY["${tunnel}|${ip}"]="$latency"
            echo " ✓ $tunnel ($ip): ${latency}ms" >&2
        done < "$result_file"
    done
    
    rm -rf "$results_dir"
    echo "# Pings concluídos: ${#TUNNEL_LATENCY[@]} respostas" >&2
}

# ==============================================================
# COLETA DE DADOS PRINCIPAL
# ==============================================================

declare -A TUNNELS_UP TUNNELS_DOWN
declare -A TUNNEL_BYTES_IN TUNNEL_BYTES_OUT
declare -A TUNNEL_PACKETS_IN TUNNEL_PACKETS_OUT
declare -A TUNNEL_UPTIME ROUTES

{
    echo "# ========================================" >&2
    echo "# Iniciando coleta de métricas IPSec" >&2
    echo "# $(date)" >&2
    echo "# ========================================" >&2
    
    # Descobrir IPs remotos automaticamente
    discover_remote_ips
    
    # 1. Status dos túneis
    echo "# Coletando status dos túneis..." >&2
    while IFS= read -r line; do
        if [[ $line =~ \{([^}]+)\} ]]; then
            tunnel=$(sanitize "${BASH_REMATCH[1]}")
            [ -n "$tunnel" ] && TUNNELS_UP["$tunnel"]=1
        fi
    done < <(run_with_timeout ipsec status | grep "IPsec SA established")
    
    # 2. Todos os túneis configurados
    ALL_TUNNELS=()
    while IFS= read -r tunnel; do
        tunnel=$(sanitize "$tunnel")
        [ -n "$tunnel" ] && ALL_TUNNELS+=("$tunnel")
    done < <(run_with_timeout ipsec status | grep -oP '(?<=")[^"]+(?=")' | sort -u)
    
    echo " ✓ Túneis UP: ${#TUNNELS_UP[@]}" >&2
    echo " ✓ Túneis configurados: ${#ALL_TUNNELS[@]}" >&2
    
    # 3. Identificar túneis DOWN
    for tunnel in "${ALL_TUNNELS[@]}"; do
        if [ -z "${TUNNELS_UP[$tunnel]}" ]; then
            TUNNELS_DOWN["$tunnel"]=1
        fi
    done
    
    # 4. Tráfego
    echo "# Coletando tráfego..." >&2
    while IFS= read -r line; do
        if [[ $line =~ \"([^\"]+)\".*inBytes=([0-9]+).*outBytes=([0-9]+) ]]; then
            tunnel=$(sanitize "${BASH_REMATCH[1]}")
            bytes_in="${BASH_REMATCH[2]}"
            bytes_out="${BASH_REMATCH[3]}"
            
            if [ -n "$tunnel" ]; then
                TUNNEL_BYTES_IN["$tunnel"]="$bytes_in"
                TUNNEL_BYTES_OUT["$tunnel"]="$bytes_out"
                TUNNEL_PACKETS_IN["$tunnel"]=$((bytes_in / 1400))
                TUNNEL_PACKETS_OUT["$tunnel"]=$((bytes_out / 1400))
            fi
        fi
    done < <(run_with_timeout ipsec whack --trafficstatus)
    
    # 5. Uptime
    echo "# Coletando uptime..." >&2
    current_time=$(date +%s)
    while IFS= read -r line; do
        if [[ $line =~ newest\ IPSEC.*\{([^}]+)\} ]]; then
            tunnel=$(sanitize "${BASH_REMATCH[1]}")
            
            if [[ $line =~ ([0-9]+)s\ ago ]]; then
                uptime="${BASH_REMATCH[1]}"
                [ "$uptime" -ge 0 ] && TUNNEL_UPTIME["$tunnel"]="$uptime"
            elif [[ $line =~ ([0-9]+)m([0-9]+)s\ ago ]]; then
                minutes="${BASH_REMATCH[1]}"
                seconds="${BASH_REMATCH[2]}"
                uptime=$((minutes * 60 + seconds))
                TUNNEL_UPTIME["$tunnel"]="$uptime"
            elif [[ $line =~ ([0-9]+)h([0-9]+)m([0-9]+)s\ ago ]]; then
                hours="${BASH_REMATCH[1]}"
                minutes="${BASH_REMATCH[2]}"
                seconds="${BASH_REMATCH[3]}"
                uptime=$((hours * 3600 + minutes * 60 + seconds))
                TUNNEL_UPTIME["$tunnel"]="$uptime"
            fi
        fi
    done < <(run_with_timeout ipsec status)
    
    # 6. Rotas
    echo "# Verificando rotas..." >&2
    for tunnel in "${ALL_TUNNELS[@]}"; do
        subnet=$(run_with_timeout ipsec status | grep -A5 "\"$tunnel\"" | grep -oP '\d+\.\d+\.\d+\.\d+/\d+' | head -1)
        
        if [ -n "$subnet" ]; then
            if ip route 2>/dev/null | grep -q "$subnet"; then
                ROUTES["${tunnel}|${subnet}"]=1
            else
                ROUTES["${tunnel}|${subnet}"]=0
            fi
        fi
    done
    
    # 7. Latência (ping paralelo)
    ping_remote_ips
    
    # ==============================================================
    # EXPORTAÇÃO DAS MÉTRICAS
    # ==============================================================
    
    echo "# Exportando métricas..." >&2
    
    # STATUS DOS TÚNEIS
    echo "# HELP ipsec_tunnel_status Status do túnel (1=established, 0=down)"
    echo "# TYPE ipsec_tunnel_status gauge"
    for tunnel in "${!TUNNELS_UP[@]}"; do
        echo "ipsec_tunnel_status{tunnel=\"$tunnel\",state=\"established\"} 1"
    done
    for tunnel in "${!TUNNELS_DOWN[@]}"; do
        echo "ipsec_tunnel_status{tunnel=\"$tunnel\",state=\"down\"} 0"
    done
    
    # BYTES
    echo "# HELP ipsec_tunnel_bytes_in Bytes recebidos pelo túnel"
    echo "# TYPE ipsec_tunnel_bytes_in counter"
    for tunnel in "${!TUNNEL_BYTES_IN[@]}"; do
        echo "ipsec_tunnel_bytes_in{tunnel=\"$tunnel\"} ${TUNNEL_BYTES_IN[$tunnel]}"
    done
    
    echo "# HELP ipsec_tunnel_bytes_out Bytes enviados pelo túnel"
    echo "# TYPE ipsec_tunnel_bytes_out counter"
    for tunnel in "${!TUNNEL_BYTES_OUT[@]}"; do
        echo "ipsec_tunnel_bytes_out{tunnel=\"$tunnel\"} ${TUNNEL_BYTES_OUT[$tunnel]}"
    done
    
    # PACKETS
    echo "# HELP ipsec_tunnel_packets_in Pacotes recebidos pelo túnel"
    echo "# TYPE ipsec_tunnel_packets_in counter"
    for tunnel in "${!TUNNEL_PACKETS_IN[@]}"; do
        echo "ipsec_tunnel_packets_in{tunnel=\"$tunnel\"} ${TUNNEL_PACKETS_IN[$tunnel]}"
    done
    
    echo "# HELP ipsec_tunnel_packets_out Pacotes enviados pelo túnel"
    echo "# TYPE ipsec_tunnel_packets_out counter"
    for tunnel in "${!TUNNEL_PACKETS_OUT[@]}"; do
        echo "ipsec_tunnel_packets_out{tunnel=\"$tunnel\"} ${TUNNEL_PACKETS_OUT[$tunnel]}"
    done
    
    # ROTAS
    echo "# HELP ipsec_route_status Status das rotas IPSec (1=presente, 0=ausente)"
    echo "# TYPE ipsec_route_status gauge"
    for key in "${!ROUTES[@]}"; do
        IFS='|' read -r tunnel subnet <<< "$key"
        echo "ipsec_route_status{tunnel=\"$tunnel\",subnet=\"$subnet\"} ${ROUTES[$key]}"
    done
    
    # DAEMON
    echo "# HELP ipsec_daemon_up Status do daemon IPSec (1=running, 0=down)"
    echo "# TYPE ipsec_daemon_up gauge"
    if systemctl is-active --quiet ipsec 2>/dev/null; then
        echo "ipsec_daemon_up 1"
    else
        echo "ipsec_daemon_up 0"
    fi
    
    # TOTAIS
    echo "# HELP ipsec_total_tunnels_configured Total de túneis configurados"
    echo "# TYPE ipsec_total_tunnels_configured gauge"
    echo "ipsec_total_tunnels_configured ${#ALL_TUNNELS[@]}"
    
    echo "# HELP ipsec_total_tunnels_active Total de túneis ativos"
    echo "# TYPE ipsec_total_tunnels_active gauge"
    echo "ipsec_total_tunnels_active ${#TUNNELS_UP[@]}"
    
    # ERROS
    echo "# HELP ipsec_errors_last_hour Erros nos logs na última hora"
    echo "# TYPE ipsec_errors_last_hour gauge"
    errors=$(journalctl -u ipsec --since "1 hour ago" 2>/dev/null | grep -icE "error|failed|timeout" || echo "0")
    echo "ipsec_errors_last_hour $errors"
    
    # LATÊNCIA
    if [ ${#TUNNEL_LATENCY[@]} -gt 0 ]; then
        echo "# HELP ipsec_tunnel_latency_ms Latência do túnel em ms"
        echo "# TYPE ipsec_tunnel_latency_ms gauge"
        for key in "${!TUNNEL_LATENCY[@]}"; do
            IFS='|' read -r tunnel ip <<< "$key"
            echo "ipsec_tunnel_latency_ms{tunnel=\"$tunnel\",remote_ip=\"$ip\"} ${TUNNEL_LATENCY[$key]}"
        done
    fi
    
    # UPTIME
    if [ ${#TUNNEL_UPTIME[@]} -gt 0 ]; then
        echo "# HELP ipsec_tunnel_uptime_seconds Tempo que o túnel está ativo"
        echo "# TYPE ipsec_tunnel_uptime_seconds gauge"
        for tunnel in "${!TUNNEL_UPTIME[@]}"; do
            echo "ipsec_tunnel_uptime_seconds{tunnel=\"$tunnel\"} ${TUNNEL_UPTIME[$tunnel]}"
        done
    fi
    
    echo "# ========================================" >&2
    echo "# Coleta concluída com sucesso" >&2
    echo "# ========================================" >&2
    
} > "$TEMP" 2>/var/log/ipsec_exporter.log

# Validar e mover
if [ -s "$TEMP" ]; then
    mv "$TEMP" "$OUTPUT"
    chmod 644 "$OUTPUT"
    exit 0
else
    echo "ERRO: Arquivo de métricas vazio!" >&2
    rm -f "$TEMP"
    exit 1
fi