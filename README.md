

Servidor MCP que expõe operações de monitoramento, diagnóstico e manutenção de sistemas Linux como ferramentas tipadas, utilizáveis por agentes de IA. Opera na máquina local e em máquinas remotas da mesma rede.


As ferramentas se dividem em três tipos de operação:

- **Monitorar** — leitura de estado, sem efeito colateral
- **Diagnosticar** — correlação entre métricas e histórico, sem efeito colateral
- **Agir** — altera o estado do sistema; sujeita a `dry_run`, allowlist e registro de auditoria

---

# Categorias

## 1. Processos

**Monitorar**

| Tool | Descrição |
|---|---|
| `list_processes` | PID, nome, usuário, CPU%, RSS, estado, uptime, cmdline |
| `get_process_details` | Threads, file descriptors, conexões, cgroup, filhos |
| `get_process_tree` | Hierarquia pai/filho |
| `find_resource_hogs` | Maiores consumidores de CPU, RAM, I/O ou FDs |
| `detect_zombie_processes` | Zumbis, órfãos e processos em `D` state |

**Diagnosticar**

| Tool | Descrição |
|---|---|
| `analyze_process_behavior` | Evolução do consumo do processo no tempo |
| `identify_runaway_process` | Processo com crescimento de consumo sem convergência |
| `classify_process_criticality` | Classifica em essencial, descartável ou interativo |

**Agir**

| Tool | Risco | Descrição |
|---|---|---|
| `limit_process_resources` | baixo | cgroup v2: `cpu.max`, `memory.high` |
| `set_process_priority` | baixo | `renice` / `ionice` |
| `protect_process` | baixo | Ajusta `oom_score_adj` |
| `suspend_process` / `resume_process` | médio | SIGSTOP / SIGCONT |
| `kill_process` | alto | SIGTERM com timeout antes de SIGKILL |

---

## 2. Memória

**Monitorar**

| Tool | Descrição |
|---|---|
| `get_memory_status` | Total, usado, disponível, buffers, cache, swap |
| `get_memory_by_process` | Ranking por RSS / PSS / USS |
| `get_swap_activity` | Taxa de swap in/out e processos envolvidos |
| `get_oom_history` | Eventos do OOM killer no journal e no dmesg |

**Diagnosticar**

| Tool | Descrição |
|---|---|
| `analyze_memory_pressure` | PSI em `/proc/pressure/memory` e tendência |
| `detect_memory_leaks` | Crescimento monotônico de RSS por processo |
| `diagnose_oom_risk` | Estimativa de tempo até o próximo OOM |

**Agir**

| Tool | Risco | Descrição |
|---|---|---|
| `apply_memory_limit` | baixo | `memory.high` no processo ou no slice do usuário |
| `adjust_swappiness` | baixo | Altera `vm.swappiness` |
| `drop_caches` | médio | Libera page cache, dentries e inodes |
| `clear_swap` | médio | Esvazia e reativa a swap |

---

## 3. CPU, térmico e energia

**Monitorar**

| Tool | Descrição |
|---|---|
| `get_cpu_status` | Uso por core, load average, iowait, steal, frequência |
| `get_thermal_status` | Temperatura por sensor e estado de throttling |
| `get_cpu_governor` | Governor ativo e estados P/C |
| `get_battery_status` | Carga, ciclos, capacidade atual vs. de projeto |
| `get_power_consumption` | Consumo em watts e processos que mais contribuem |
| `get_power_profile` | Perfil ativo (power-saver / balanced / performance) |

**Diagnosticar**

| Tool | Descrição |
|---|---|
| `diagnose_cpu_saturation` | Separa carga real, iowait, throttling e contenção |
| `diagnose_battery_drain` | Cruza consumo por processo, wakeups, brilho e dispositivos |
| `diagnose_thermal_throttling` | Correlaciona temperatura, frequência e desempenho |
| `estimate_battery_runtime` | Autonomia estimada para o padrão de uso atual |

**Agir**

| Tool | Risco | Descrição |
|---|---|---|
| `set_screen_brightness` | baixo | Ajusta brilho |
| `set_power_profile` | baixo | Troca o perfil de energia |
| `set_cpu_governor` | baixo | Define o governor |
| `apply_cpu_quota` | baixo | Limita percentual de CPU de processo ou serviço |
| `toggle_device` | médio | Liga/desliga Bluetooth, Wi-Fi, webcam |

---

## 4. Disco e I/O

**Monitorar**

| Tool | Descrição |
|---|---|
| `get_disk_usage` | Espaço e inodes por mountpoint |
| `get_io_stats` | Throughput, latência por device, processos com mais I/O |
| `get_disk_health` | SMART: setores realocados, wear leveling, horas de uso |
| `find_large_files` | Maiores arquivos sob um diretório |
| `find_old_files` | Arquivos sem acesso há N dias |
| `get_cache_sizes` | `~/.cache`, cache de pacotes, journal, Docker, lixeira |

**Diagnosticar**

| Tool | Descrição |
|---|---|
| `diagnose_disk_full` | Identifica onde o espaço foi consumido e o que cresceu |
| `analyze_io_pressure` | PSI de I/O e processo que domina a fila |
| `predict_disk_exhaustion` | Projeção de saturação pela taxa de crescimento |
| `assess_disk_failure_risk` | Classificação de risco a partir dos atributos SMART |

**Agir**

| Tool | Risco | Descrição |
|---|---|---|
| `throttle_process_io` | baixo | `io.max` via cgroup |
| `cleanup_package_cache` | baixo | Cache do gerenciador de pacotes |
| `cleanup_journal_logs` | baixo | `journalctl --vacuum-size` / `--vacuum-time` |
| `cleanup_temp_files` | baixo | `/tmp`, `/var/tmp`, lixeira |
| `clear_app_caches` | baixo | Caches de navegador, thumbnails, `~/.cache` |
| `cleanup_docker` | médio | Imagens, volumes e containers dangling |
| `remove_old_kernels` | alto | Mantém os N kernels mais recentes |

---

## 5. Sistema e serviços

**Monitorar**

| Tool | Descrição |
|---|---|
| `get_system_overview` | Distro, kernel, uptime, desktop environment, init |
| `list_services` | Estado das unidades systemd |
| `get_failed_units` | Unidades em falha |
| `get_boot_analysis` | `systemd-analyze blame` e `critical-chain` |
| `list_startup_apps` | Autostart do desktop e unidades de usuário |
| `get_kernel_messages` | `dmesg` filtrado por severidade |

**Diagnosticar**

| Tool | Descrição |
|---|---|
| `diagnose_boot_slowness` | Unidades que atrasam o boot e dependências bloqueantes |
| `diagnose_service_failure` | Cruza estado da unidade, logs e dependências |
| `detect_restart_loops` | Serviços em reinício repetido |
| `audit_startup_impact` | Custo de cada item de inicialização |

**Agir**

| Tool | Risco | Descrição |
|---|---|---|
| `reload_daemon` | baixo | `systemctl daemon-reload` |
| `disable_startup_app` | baixo | Remove item do autostart |
| `start_service` / `restart_service` | médio | Controle de unidades |
| `stop_service` | médio | Para uma unidade |
| `enable_service` / `disable_service` | médio | Habilitação no boot |
| `mask_service` | alto | Impede ativação da unidade |

---

## 6. Rede

**Monitorar**

| Tool | Descrição |
|---|---|
| `get_network_status` | Interfaces, IPs, rotas, Wi-Fi (SSID, sinal, link rate) |
| `list_connections` | Conexões ativas com PID associado |
| `get_bandwidth_by_process` | Consumo de banda por processo |
| `test_connectivity` | DNS, gateway, latência, perda de pacotes |
| `get_dns_config` | Resolvers configurados e em uso |

**Diagnosticar**

| Tool | Descrição |
|---|---|
| `diagnose_network_issue` | Verificação por camada: link, IP, DNS, rota, internet |
| `diagnose_slow_connection` | Separa problema de link, DNS, provedor ou saturação local |
| `detect_bandwidth_abuse` | Processo com consumo de banda desproporcional |
| `analyze_wifi_quality` | Sinal, ruído, retransmissões, interferência de canal |

**Agir**

| Tool | Risco | Descrição |
|---|---|---|
| `flush_dns_cache` | baixo | Limpa cache DNS |
| `limit_process_bandwidth` | baixo | Limite de banda por processo |
| `set_dns_servers` | médio | Define resolvers |
| `reconnect_wifi` | médio | Reconecta à rede sem fio |
| `restart_network` | médio | Reinicia o NetworkManager |

---

## 7. Pacotes e atualizações

**Monitorar**

| Tool | Descrição |
|---|---|
| `list_outdated_packages` | apt/dnf/pacman, snap, flatpak |
| `check_security_updates` | Separa atualizações de segurança |
| `find_orphan_packages` | Candidatos a autoremove |
| `get_package_info` | Versão, origem, dependências, data de instalação |

**Diagnosticar**

| Tool | Descrição |
|---|---|
| `assess_update_risk` | Avalia impacto de atualizar kernel, driver ou DE |
| `detect_broken_dependencies` | Dependências quebradas e pacotes semiconfigurados |
| `correlate_update_with_regression` | Relaciona falha recente a atualizações do período |

**Agir**

| Tool | Risco | Descrição |
|---|---|---|
| `update_packages` | médio | Com flag `security_only` opcional |
| `install_package` | médio | Instala pacote |
| `rollback_package` | médio | Retorna à versão anterior |
| `fix_broken_packages` | médio | Repara estado do gerenciador |
| `remove_package` | alto | Remove pacote |

---

## 8. Logs e eventos

**Monitorar**

| Tool | Descrição |
|---|---|
| `search_logs` | journald com filtro por unidade, prioridade e janela |
| `get_error_summary` | Erros agregados por unidade nas últimas N horas |
| `get_crash_reports` | Coredumps e relatórios de crash |
| `tail_logs` | Acompanhamento contínuo com filtro |

**Diagnosticar**

| Tool | Descrição |
|---|---|
| `build_event_timeline` | Linha do tempo de eventos correlacionados |
| `detect_log_anomalies` | Picos de erro e mensagens inéditas em relação ao histórico |
| `find_error_patterns` | Agrupa erros recorrentes por assinatura |

**Agir**

| Tool | Risco | Descrição |
|---|---|---|
| `set_log_level` | baixo | Verbosidade de uma unidade |
| `export_diagnostic_bundle` | baixo | Empacota logs e métricas de um período |
| `cleanup_journal_logs` | baixo | Vacuum por tamanho ou idade |

---

## 9. Diagnóstico combinado

Ferramentas que atravessam as categorias anteriores.

| Tool | Descrição |
|---|---|
| `health_check_full` | Varredura completa; retorna score e achados ordenados por severidade |
| `diagnose_slowness` | Correlaciona CPU, memória, I/O, PSI e térmico; indica o gargalo dominante |
| `root_cause_analysis` | Recebe sintoma e janela de tempo; monta timeline causal |
| `detect_anomalies` | Compara o estado atual com a baseline da máquina |
| `recommend_actions` | Plano de remediação com comando, risco, reversibilidade e impacto |
| `explain_finding` | Reescreve um achado técnico em linguagem acessível |

---

## 10. Histórico e auditoria

| Tool | Descrição |
|---|---|
| `record_baseline` | Registra snapshot do sistema em estado considerado saudável |
| `get_metrics_history` | Série temporal de métricas coletadas (SQLite) |
| `compare_with_baseline` | Diferenças entre estado atual e baseline |
| `watch_metric` | Monitor em background com disparo por threshold |
| `get_action_log` | Registro append-only das ações executadas |

---

## 11. Reversão

| Tool | Descrição |
|---|---|
| `create_snapshot` | Timeshift, btrfs ou restic |
| `list_snapshots` | Snapshots disponíveis com data e tamanho |
| `rollback_snapshot` | Restaura estado anterior |
| `undo_last_action` | Desfaz a última ação registrada no audit log |
| `simulate_action` | Executa qualquer ação em `dry_run` e retorna o impacto previsto |

---

## 12. Máquinas remotas

**Monitorar**

| Tool | Descrição |
|---|---|
| `list_hosts` | Inventário: hostname, IP, OS, status, última coleta |
| `ping_host` | Latência, versão do agent, clock drift |
| `fleet_dashboard` | Estado consolidado dos nós |

**Diagnosticar**

| Tool | Descrição |
|---|---|
| `fleet_health_check` | Health check paralelo ordenado por severidade |
| `fleet_compare` | Diferenças de configuração entre máquinas |
| `detect_config_drift` | Divergências em relação à baseline do grupo |
| `find_common_issues` | Problema presente em múltiplos nós |
| `collect_logs` | Agrega logs de vários nós em timeline única |

**Agir**

| Tool | Risco | Descrição |
|---|---|---|
| `tag_host` | baixo | Agrupamento lógico |
| `register_host` | médio | Enrollment com token de uso único |
| `remove_host` | médio | Revoga certificado e remove do inventário |
| `sync_config` | médio | Propaga arquivo de configuração para um grupo |
| `update_agent` / `restart_agent` | médio | Ciclo de vida do nodeagent |
| `fleet_rollout` | alto | Execução em ondas, com `abort_on_failure` |

---

## 13. Realocação de carga

Quando uma máquina satura, uma carga pode ser reexecutada em outro nó com recursos livres.

| Classe | Exemplos | Tratamento |
|---|---|---|
| A — relançável | build, testes, `ffmpeg`, scripts de dados | Elegível a realocação |
| B — conteinerizada | Docker, Podman | Elegível a realocação |
| C — interativa ou stateful | navegador, IDE, banco, sessão gráfica | Apenas contenção de recursos |

Cargas elegíveis são declaradas em manifesto:

```yaml
jobs:
  - name: build-projeto
    match: ["cargo build", "make -j"]
    offloadable: true
    class: A
    workdir: ~/dev/projeto
    sync: [src/, Cargo.toml]
    requires: [rust, 8GB_ram]
    restart_command: "cargo build --release"

  - name: navegador
    match: ["chrome", "firefox"]
    offloadable: false
    on_pressure: throttle
```

**Monitorar**

| Tool | Descrição |
|---|---|
| `classify_process` | Classe A, B ou C |
| `check_offloadable` | `{offloadable, motivo, job_definition}` |
| `capture_process_context` | cmdline, cwd, env filtrado, FDs, usuário |
| `check_host_capability` | RAM livre, CPU ocioso, dependências, GPU, bateria |

**Diagnosticar**

| Tool | Descrição |
|---|---|
| `select_best_host` | Ordena destinos por recurso disponível, latência e energia |
| `estimate_offload_benefit` | Compara custo de transferência com o alívio esperado |
| `relieve_pressure` | Propõe plano combinando realocação, limites e suspensões |

**Agir**

| Tool | Risco | Descrição |
|---|---|---|
| `stage_workload` | baixo | Sincroniza entradas para o destino |
| `track_job` | baixo | Status, progresso e logs |
| `retrieve_artifacts` | baixo | Traz as saídas de volta |
| `start_remote_job` | médio | Executa sob cgroup com limites, em scope ou container |
| `offload_process` | alto | Orquestra o fluxo completo |

O processo local só é encerrado após confirmação de que o job iniciou no destino.

