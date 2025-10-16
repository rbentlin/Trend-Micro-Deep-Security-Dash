import pandas as pd
import streamlit as st
import plotly.express as px
import os
import time
import re
from datetime import datetime
import requests
import ipaddress  # para filtrar IPs internos


# Logo customizado da empresa
logo_path = os.path.join(os.path.dirname(__file__), "esaferlogo.png")
st.image(logo_path, width=110)


# ==================== CONFIGURAÇÃO GERAL ====================
st.set_page_config(page_title="Trend Micro Deep Security Dashboard", layout="wide")
st.title("🛡️ Trend Micro Deep Security Dashboard")

# ==================== API FIXA ====================
ABUSEIPDB_API_KEY = "7afe767896f2a938d3f11fd3c770a992d853355e9bb55d3998a57781739ffc5cb2667872448915b6"

# ==================== FUNÇÃO GENÉRICA ====================
def normalizar_colunas(df):
    df.columns = [c.strip() for c in df.columns]
    return df


@st.cache_data(ttl=60 * 60 * 24)  # cache 24h por IP+janela
def abuseipdb_check(ip: str, api_key: str, max_age_days: int = 90):
    """Consulta AbuseIPDB /check para um IP. Retorna dict com campos essenciais."""
    try:
        url = "https://api.abuseipdb.com/api/v2/check"
        headers = {"Key": api_key, "Accept": "application/json"}
        params = {"ipAddress": ip, "maxAgeInDays": str(max_age_days)}
        r = requests.get(url, headers=headers, params=params, timeout=10)
        if r.status_code != 200:
            return {"ip": ip, "error": f"HTTP {r.status_code}"}
        data = r.json().get("data", {})
        return {
            "ip": ip,
            "abuse_confidence": data.get("abuseConfidenceScore"),
            "total_reports": data.get("totalReports"),
            "last_reported_at": data.get("lastReportedAt"),
            "country_code": data.get("countryCode"),
            "isp": data.get("isp"),
            "domain": data.get("domain"),
            "usage_type": data.get("usageType"),
            "is_whitelisted": data.get("isWhitelisted"),
        }
    except Exception as e:
        return {"ip": ip, "error": str(e)}


# ==================== TABS PRINCIPAIS ====================
tab1, tab2, tab3 = st.tabs(["🧬 Antimalware", "🔥 Firewall", "🧱 Intrusion Prevention"])

# ==================== ABA ANTIMALWARE ====================
with tab1:
    am_file = st.file_uploader("Importe o CSV do Antimalware", type="csv", key="am")

    st.subheader("🧬 Antimalware Events")
    st.markdown("""
    O módulo **Antimalware** da Trend Micro é responsável por detectar, limpar e bloquear arquivos e processos maliciosos no endpoint.
    Ele utiliza assinaturas, heurísticas e aprendizado de máquina para identificar ameaças conhecidas e novas, executando ações automáticas
    como limpeza, quarentena ou exclusão, protegendo o sistema em tempo real.
    """)

    if am_file:
        df_am = pd.read_csv(am_file)
        df_am = normalizar_colunas(df_am)

        # Auto-detecção de colunas
        col_host = next((c for c in df_am.columns if "host" in c.lower() or "computer" in c.lower()), None)
        col_action = next((c for c in df_am.columns if "result" in c.lower() or "action" in c.lower()), None)
        col_file = next((c for c in df_am.columns if "file" in c.lower()), None)
        col_malw = next((c for c in df_am.columns if "malware" in c.lower() or "virus" in c.lower()), None)

        # KPIs
        total_eventos = len(df_am)
        total_hosts = df_am[col_host].nunique() if col_host else 0
        total_malwares = df_am[col_malw].nunique() if col_malw else 0

        k1, k2, k3 = st.columns(3)
        k1.metric("Eventos Totais", total_eventos)
        k2.metric("Hosts Afetados", total_hosts)
        k3.metric("Malwares Únicos", total_malwares)

        st.markdown("---")

        # === Gráfico: Top 10 Computadores ===
        if col_host:
            s_hosts = df_am[col_host].value_counts().head(10)
            fig_host = px.bar(
                s_hosts, y=s_hosts.index, x=s_hosts.values, orientation="h",
                color=s_hosts.values, color_continuous_scale="Blues",
                labels={"y": "Hostname", "x": "Detecções"}
            )
            fig_host.update_layout(
                title="💻 **Top 10 Computadores com Maior Quantidade de Malware**",
                title_font=dict(size=18, color="black"),
                font=dict(size=13),
                yaxis={'categoryorder': 'total ascending'}
            )
            st.plotly_chart(fig_host, use_container_width=True)

        st.markdown("---")

        # === Gráfico: Top 10 Arquivos Infectados ===
        if col_file:
            s_files = df_am[col_file].value_counts().head(10)
            fig_files = px.bar(
                s_files, y=s_files.index, x=s_files.values, orientation="h",
                color=s_files.values, color_continuous_scale="Viridis",
                labels={"y": "Arquivo", "x": "Ocorrências"}
            )
            fig_files.update_layout(
                title="📁 **Top 10 Arquivos Infectados**",
                title_font=dict(size=18, color="black"),
                font=dict(size=13),
                yaxis={'categoryorder': 'total ascending'}
            )
            st.plotly_chart(fig_files, use_container_width=True)

        st.markdown("---")

        # === Distribuição das ações + descrições dinâmicas ===
        if col_action:
            st.markdown("""
                <style>
                  .chart-title { font-size:18px; font-weight:700; color:black; margin-bottom:8px; }
                  .desc-box {
                      background-color:#f9f9f9;
                      padding:12px 18px;
                      border-radius:10px;
                      border:1px solid #ddd;
                      margin-left:20px;
                      line-height:1.6;
                  }
                </style>
            """, unsafe_allow_html=True)

            # Obter as ações detectadas
            action_counts = df_am[col_action].fillna("Desconhecida").value_counts()
            detected_actions = list(action_counts.index)

            # Descrições com ícones coloridos
            action_descriptions = {
                "Cleaned": "🟢 O arquivo infectado foi limpo com sucesso e permanece no sistema.",
                "Deleted": "🟢 O arquivo infectado foi removido completamente.",
                "Quarantined": "🟠 O arquivo foi isolado em quarentena, impedindo execução.",
                "Terminate": "🟢 O processo malicioso foi encerrado.",
                "Terminate Failed": "🔴 Falha ao encerrar o processo — possível malware ativo.",
                "Access Denied": "🟡 O acesso ao arquivo foi bloqueado.",
                "Clean Failed": "🔴 Falha na tentativa de limpeza.",
                "Passed": "🟢 Nenhuma ação necessária; arquivo limpo.",
                "Desconhecida": "⚪ Ação não identificada pelo relatório."
            }

            filtered_descriptions = {k: v for k, v in action_descriptions.items() if k in detected_actions}

            c1, c2 = st.columns([1.1, 0.9])

            with c1:
                st.markdown("<div class='chart-title'>🧩 <b>**Principais Ações de Antimalware**</b></div>",
                            unsafe_allow_html=True)
                fig_action = px.pie(
                    action_counts,
                    values=action_counts.values,
                    names=action_counts.index,
                    color_discrete_sequence=px.colors.qualitative.Set2,
                    hole=0.4
                )
                fig_action.update_layout(
                    margin=dict(t=0),
                    legend=dict(
                        orientation="h",
                        yanchor="bottom",
                        y=-0.25,
                        xanchor="center",
                        x=0.5
                    )
                )
                st.plotly_chart(fig_action, use_container_width=True)

            with c2:
                st.markdown("<div class='chart-title'>📊 <b>**Quantidade por Ação**</b></div>", unsafe_allow_html=True)

                # DataFrame com ações e quantidades
                df_action_grid = pd.DataFrame({
                    "Ação": action_counts.index,
                    "Quantidade": action_counts.values
                })

                st.dataframe(
                    df_action_grid.style.format({"Quantidade": "{:,.0f}"}),
                    use_container_width=True,
                    hide_index=True
                )

                #st.markdown("<div class='chart-title'>🧾 <b>Descrições das Ações</b></div>", unsafe_allow_html=True)
                if filtered_descriptions:
                    desc_html = "<div class='desc-box'>"
                    for action, desc in filtered_descriptions.items():
                        desc_html += f"<b>{action}:</b> {desc}<br>"
                    desc_html += "</div>"
                    st.markdown(desc_html, unsafe_allow_html=True)
                else:
                    st.info("Nenhuma ação detectada para exibir descrições.")

# ==================== ABA FIREWALL ====================

with tab2:
    fw_file = st.file_uploader("Importe o CSV do Firewall", type="csv", key="fw")
    st.subheader("🔥 Firewall Events")
    st.markdown("""
    O módulo **Firewall** do Deep Security fornece uma camada adicional de defesa controlando o tráfego de rede
    entre endpoints e sistemas externos. Ele bloqueia conexões não autorizadas, aplica políticas baseadas em IP,
    porta e protocolo, ajudando a prevenir movimentações laterais e tentativas de exploração.
    """)

    if fw_file:
        df_fw = pd.read_csv(fw_file)
        df_fw = normalizar_colunas(df_fw)

        # === Detecta colunas automaticamente ===
        col_src = next((c for c in df_fw.columns if "source" in c.lower() and "ip" in c.lower()), None)
        col_src_port = next((c for c in df_fw.columns if "source port" in c.lower()), None)
        col_action = next((c for c in df_fw.columns if "action" in c.lower() or "result" in c.lower()), None)
        col_frametype = next((c for c in df_fw.columns if "frame" in c.lower() and "type" in c.lower()), None)
        col_reason = next((c for c in df_fw.columns if "reason" in c.lower()), None)
        col_host = next((c for c in df_fw.columns if "host" in c.lower() or "computer" in c.lower()), None)

        # === Cálculo de métricas do Firewall ===
        total_eventos = len(df_fw)

        # Contagem por tipo de ação (Deny, Log Only, Fail Open: Deny)
        if col_action:
            df_fw[col_action] = df_fw[col_action].astype(str).str.strip()
            total_deny = (df_fw[col_action].str.lower() == "deny").sum()
            total_logonly = (df_fw[col_action].str.lower() == "log only").sum()
            total_failopen = (df_fw[col_action].str.lower() == "fail open: deny").sum()
        else:
            total_deny = total_logonly = total_failopen = 0

        # Contagem de IPs bloqueados únicos (apenas Deny)
        if col_src and col_action:
            df_deny = df_fw[df_fw[col_action].astype(str).str.lower() == "deny"]
            total_ips_bloqueados = df_deny[col_src].nunique()
        else:
            total_ips_bloqueados = 0

        # === KPIs do Firewall ===
        colA, colB, colC, colD = st.columns(4)
        colA.metric("Eventos Totais", total_eventos)
        colB.metric("Deny", total_deny)
        colC.metric("Log Only", total_logonly)
        colD.metric("Fail Open: Deny", total_failopen)



        st.markdown("""
                       - **Deny**: Tráfego bloqueado de acordo com a política configurada.  
                       - **Log Only**: Evento apenas registrado para auditoria, sem bloqueio.  
                       - **Fail Open: Deny**: Quando o modo *Fail-Open* está ativo e o sistema encontra uma falha, o pacote é logado e tratado como bloqueado (Deny).  
                       """)

        st.markdown("---")

        # === Top 10 Endereços de Origem IPv4 (Separando Internos e Externos) ===
        if col_src:
            df_ip_plot = df_fw.copy()

            # Filtra apenas IPv4 válidos
            df_ip_plot = df_ip_plot[df_ip_plot[col_src].notna()]
            df_ip_plot = df_ip_plot[
                df_ip_plot[col_src].astype(str).str.match(
                    r"^(?:\d{1,3}\.){3}\d{1,3}$", na=False
                )
            ]

            # Se existir coluna Frame Type, mantém apenas IPv4
            if col_frametype in df_fw.columns:
                df_ip_plot = df_ip_plot[
                    df_ip_plot[col_frametype].astype(str).str.strip().str.upper() == "IP"
                    ]

            # Divide entre IPs internos e externos
            ip_privados = []
            ip_publicos = []
            for ip in df_ip_plot[col_src].unique():
                try:
                    ip_obj = ipaddress.ip_address(ip)
                    if ip_obj.is_private:
                        ip_privados.append(ip)
                    elif ip_obj.is_global:
                        ip_publicos.append(ip)
                except ValueError:
                    continue

            # --- Gráfico de IPs Externos ---
            df_publicos = df_ip_plot[df_ip_plot[col_src].isin(ip_publicos)]
            if not df_publicos.empty:
                top_publicos = df_publicos[col_src].value_counts().head(10)
                fig_publicos = px.bar(
                    top_publicos,
                    y=top_publicos.index,
                    x=top_publicos.values,
                    orientation='h',
                    color=top_publicos.values,
                    color_continuous_scale="Reds",
                    title="🌐 **Top 10 Endereços de Origem Externos (Endereços Públicos)**",
                    labels={"y": "IP Público de Origem", "x": "Tentativas"}
                )
                fig_publicos.update_layout(
                    yaxis={'categoryorder': 'total ascending'},
                    title_font=dict(size=18, color="black"),
                    font=dict(size=13),
                    coloraxis_showscale=False
                )
                st.plotly_chart(fig_publicos, use_container_width=True)
            else:
                st.warning("Nenhum IP público encontrado no dataset.")

            st.markdown("---")

            # --- Gráfico de IPs Internos ---
            df_privados = df_ip_plot[df_ip_plot[col_src].isin(ip_privados)]
            if not df_privados.empty:
                top_privados = df_privados[col_src].value_counts().head(10)
                fig_privados = px.bar(
                    top_privados,
                    y=top_privados.index,
                    x=top_privados.values,
                    orientation='h',
                    color=top_privados.values,
                    color_continuous_scale="Blues",
                    title="🏠 **Top 10 Endereços de Origem Internos (Endereços Privados)**",
                    labels={"y": "IP Interno de Origem", "x": "Tentativas"}
                )
                fig_privados.update_layout(
                    yaxis={'categoryorder': 'total ascending'},
                    title_font=dict(size=18, color="black"),
                    font=dict(size=13),
                    coloraxis_showscale=False
                )
                st.plotly_chart(fig_privados, use_container_width=True)
            else:
                st.info("Nenhum IP interno encontrado no dataset.")



            # === Top 10 Portas de Origem (Source Port) — com filtro de IPv6 ===
            if col_src_port:
                st.markdown("---")


                df_ports = df_fw.copy()

                # 🔍 Remove eventos com Reason contendo "Invalid IPv6 Address"
                if col_reason:
                    df_ports = df_ports[
                        ~df_ports[col_reason].astype(str).str.contains("Invalid IPv6 Address", case=False, na=False)]

                # Conta as portas
                s_ports = (
                    df_ports[col_src_port]
                    .dropna()
                    .astype(str)
                    .value_counts()
                    .head(10)
                    .rename_axis("Porta de Origem")
                    .reset_index(name="Ocorrências")
                    .sort_values("Ocorrências", ascending=True)
                )

                fig_ports = px.bar(
                    s_ports,
                    y="Porta de Origem",
                    x="Ocorrências",
                    orientation="h",
                    color="Ocorrências",
                    color_continuous_scale="Reds",
                    title="🔌 **Top 10 Portas de Origem Mais Frequentes (IPv6 Inválidos Removidos)**",
                    labels={"Porta de Origem": "Porta", "Ocorrências": "Quantidade de Eventos"}
                )

                fig_ports.update_traces(
                    text=s_ports["Ocorrências"],
                    textposition="outside",
                    hovertemplate="Porta: %{y}<br>Ocorrências: %{x}<extra></extra>"
                )

                fig_ports.update_layout(
                    yaxis=dict(
                        type="category",
                        categoryorder="array",
                        categoryarray=s_ports["Porta de Origem"].tolist()
                    ),
                    title_font=dict(size=18, color="black"),
                    font=dict(size=13),
                    coloraxis_showscale=False,
                    margin=dict(t=40, b=60)
                )

                st.plotly_chart(fig_ports, use_container_width=True)

            # === Gráfico: Máquinas com alertas de Invalid IPv6 Address ===
        st.markdown("---")

        # Detecta colunas possíveis
        col_host = next((c for c in df_fw.columns if "host" in c.lower() or "computer" in c.lower()), None)
        col_reason = next((c for c in df_fw.columns if "reason" in c.lower()), None)

        if not col_frametype or not col_reason or not col_host:
            st.info("Não foi possível identificar colunas de 'Frame Type', 'Reason' ou 'Host' para gerar o gráfico.")
        else:
            # Filtra eventos IPv6 com razão "Invalid IPv6 Address"
            df_ipv6_invalid = df_fw[
                (df_fw[col_frametype].astype(str).str.strip().str.upper() == "IPV6") &
                (df_fw[col_reason].astype(str).str.contains("Invalid IPv6 Address", case=False, na=False))
                ]

            if df_ipv6_invalid.empty:
                st.warning("Nenhum alerta de 'Invalid IPv6 Address' encontrado.")
            else:
                top_hosts_ipv6 = df_ipv6_invalid[col_host].value_counts().head(50)
                fig_ipv6 = px.bar(
                    top_hosts_ipv6,
                    y=top_hosts_ipv6.index,
                    x=top_hosts_ipv6.values,
                    orientation='h',
                    color=top_hosts_ipv6.values,
                    color_continuous_scale="Tealgrn",
                    labels={"y": "Hostname", "x": "Quantidade de Alertas"},
                    title="🌐 **Principais servidores com Alertas 'Invalid IPv6 Address'**"
                )
                fig_ipv6.update_layout(
                    yaxis={'categoryorder': 'total ascending'},
                    title_font=dict(size=18, color="black"),
                    font=dict(size=13)
                )
                st.plotly_chart(fig_ipv6, use_container_width=True)

        # ==================== ENRIQUECIMENTO – AbuseIPDB ====================
        st.markdown("---")
        st.markdown("### 🧠 Análise de Reputação (AbuseIPDB)")
        st.caption("🔑 API do AbuseIPDB carregada automaticamente.")

        if not col_src:
            st.info("Não foi possível detectar a coluna de IP de origem no CSV.")
        else:
            with st.expander("Configurar análise (AbuseIPDB)"):
                top_n = st.number_input("Quantidade de IPs do Top a enriquecer", min_value=5, max_value=50, value=10, step=1)
                max_age_days = st.slider("Janela de dias (maxAgeInDays)", min_value=7, max_value=365, value=90, step=1)
                do_enrich = st.button("Enriquecer com AbuseIPDB")

            if do_enrich:
                api_key = ABUSEIPDB_API_KEY
                df_ip_enrich = df_fw.copy()
                if col_frametype:
                    df_ip_enrich = df_ip_enrich[df_ip_enrich[col_frametype].astype(str).str.strip().str.upper() == "IP"]

                # Filtrar apenas IPs públicos
                ip_list_raw = df_ip_enrich[col_src].dropna().astype(str).value_counts().index.tolist()
                ip_publics, ip_privates = [], []

                for ip in ip_list_raw:
                    try:
                        if ipaddress.ip_address(ip).is_global:
                            ip_publics.append(ip)
                        else:
                            ip_privates.append(ip)
                    except ValueError:
                        continue

                top_ip_list = ip_publics[:top_n]

                st.info(f"🌐 IPs públicos detectados: {len(ip_publics)} | 🔒 IPs internos ignorados: {len(ip_privates)}")

                if not top_ip_list:
                    st.warning("Nenhum IP público encontrado para análise no AbuseIPDB.")
                else:
                    results = []
                    progress = st.progress(0)
                    for i, ip in enumerate(top_ip_list, start=1):
                        res = abuseipdb_check(ip, api_key, max_age_days=max_age_days)
                        results.append(res)
                        progress.progress(int(i / len(top_ip_list) * 100))
                        time.sleep(0.3)

                    df_rep = pd.DataFrame(results)

                    if "error" in df_rep.columns and df_rep["error"].notna().any():
                        st.warning("Algumas consultas retornaram erro. Veja a tabela abaixo.")

                    if "abuse_confidence" in df_rep.columns:
                        plot_df = df_rep.dropna(subset=["abuse_confidence"]).copy()
                        plot_df["abuse_confidence"] = plot_df["abuse_confidence"].astype(int)
                        plot_df = plot_df.sort_values("abuse_confidence", ascending=True)

                        fig_rep = px.bar(
                            plot_df,
                            y="ip",
                            x="abuse_confidence",
                            orientation="h",
                            color="abuse_confidence",
                            color_continuous_scale="Reds",
                            labels={"ip": "IP", "abuse_confidence": "Abuse Confidence Score"},
                            title="🧨 **Top IPs Públicos por Abuse Confidence Score (AbuseIPDB)**"
                        )
                        fig_rep.update_layout(yaxis={'categoryorder': 'array', 'categoryarray': plot_df["ip"].tolist()})
                        st.plotly_chart(fig_rep, use_container_width=True)

                    nice_cols = ["ip", "abuse_confidence", "total_reports", "last_reported_at",
                                 "country_code", "isp", "domain", "usage_type", "is_whitelisted", "error"] \
                                 if "error" in df_rep.columns else \
                                 ["ip", "abuse_confidence", "total_reports", "last_reported_at",
                                  "country_code", "isp", "domain", "usage_type", "is_whitelisted"]
                    st.dataframe(df_rep[nice_cols], use_container_width=True)






# ==================== ABA IPS ====================
with tab3:
    ips_file = st.file_uploader("Importe o CSV do IPS", type="csv", key="ips")
    st.subheader("🧱 Intrusion Prevention Events")
    st.markdown("""
    O módulo **Intrusion Prevention System (IPS)** da Trend Micro analisa o tráfego e atividades no host,
    bloqueando tentativas de exploração e vulnerabilidades em tempo real.
    """)

    if ips_file:
        df_ips = pd.read_csv(ips_file)
        df_ips = normalizar_colunas(df_ips)

        col_attack = next((c for c in df_ips.columns if "attack" in c.lower()), None)
        col_host = next((c for c in df_ips.columns if "host" in c.lower() or "computer" in c.lower()), None)
        col_severity = next((c for c in df_ips.columns if "severity" in c.lower()), None)

        total_eventos = len(df_ips)
        total_hosts = df_ips[col_host].nunique() if col_host else 0
        total_assinaturas = df_ips["Reason"].nunique() if "Reason" in df_ips.columns else 0

        colA, colB, colC = st.columns(3)
        colA.metric("Eventos Totais", total_eventos)
        colB.metric("Hosts Alvos", total_hosts)
        colC.metric("Assinaturas Exploradas", total_assinaturas)

        st.markdown("---")

        # === Top 10 Hosts Alvos de Ataques IPS ===
        if col_host and col_host in df_ips.columns:
            top_hosts = (
                df_ips[col_host]
                .astype(str)
                .value_counts()
                .head(10)
            )

            fig_ips_hosts = px.bar(
                top_hosts,
                y=top_hosts.index,
                x=top_hosts.values,
                orientation='h',
                color=top_hosts.values,
                color_continuous_scale="Plasma",
                title="💻 **Top 10 Hosts Alvos de Ataques IPS**",
                labels={"y": "Hostname", "x": "Detecções"}
            )
            fig_ips_hosts.update_layout(
                yaxis={'categoryorder': 'total ascending'},
                title_font=dict(size=18, color="black"),
                font=dict(size=13),
                coloraxis_showscale=False
            )
            fig_ips_hosts.update_traces(hovertemplate="Host: %{y}<br>Detecções: %{x}<extra></extra>")
            st.plotly_chart(fig_ips_hosts, use_container_width=True)
        else:
            st.info("Coluna de Host não identificada para o IPS (ex.: 'Host', 'Computer Name').")

        st.markdown("---")

        # === Gráfico: Principais Regras de IPS (coluna Reason) ===

        if "Reason" not in df_ips.columns:
            st.warning("❗ A coluna 'Reason' não foi encontrada no CSV.")
            st.write("Colunas disponíveis:", list(df_ips.columns))
        else:
            df_rules = (
                df_ips["Reason"]
                .astype(str)
                .value_counts()
                .head(10)
                .rename_axis("Regra IPS")
                .reset_index(name="Eventos")
                .sort_values("Eventos", ascending=True)
            )

            fig_rules = px.bar(
                df_rules,
                y="Regra IPS",
                x="Eventos",
                orientation="h",
                color="Eventos",
                color_continuous_scale="Purples",
                title="🧱 **Top 10 Assinaturas IPS Mais Acionadas**",
                labels={"Regra IPS": "Nome da Regra (Reason)", "Eventos": "Quantidade de Detecções"}
            )
            fig_rules.update_layout(
                yaxis={"categoryorder": "array", "categoryarray": df_rules["Regra IPS"].tolist()},
                title_font=dict(size=18, color="black"),
                font=dict(size=13),
                coloraxis_showscale=False
            )
            st.plotly_chart(fig_rules, use_container_width=True)




        # === Distribuição das Ações IPS (coluna Action) ===
        st.markdown("---")
        st.markdown("### ⚙️ Distribuição das Ações IPS")

        col_action_ips = next((c for c in df_ips.columns if "action" in c.lower()), None)

        if not col_action_ips:
            st.warning("❗ Coluna 'Action' não encontrada no CSV.")
            st.write("Colunas disponíveis:", list(df_ips.columns))
        else:
            s_actions = df_ips[col_action_ips].astype(str).value_counts().reset_index()
            s_actions.columns = ["Ação", "Quantidade"]

            c1, c2 = st.columns([0.6, 0.4])

            with c1:
                fig_top_actions = px.pie(
                    s_actions,
                    names="Ação",
                    values="Quantidade",
                    color_discrete_sequence=px.colors.qualitative.Set2,
                    title="⚙️ **Distribuição das Ações IPS**",
                    hole=0.35
                )
                fig_top_actions.update_traces(
                    textposition="inside",
                    textinfo="percent",
                    hovertemplate="Ação: %{label}<br>Quantidade: %{value}<extra></extra>"
                )
                fig_top_actions.update_layout(
                    title_font=dict(size=18, color="black"),
                    font=dict(size=13),
                    showlegend=True,
                    legend_title_text="Ações IPS",
                    legend=dict(
                        orientation="h",
                        yanchor="bottom",
                        y=-0.25,
                        xanchor="center",
                        x=0.5
                    ),
                    margin=dict(t=40, b=80)
                )
                st.plotly_chart(fig_top_actions, use_container_width=True)

            with c2:
                st.markdown(
                    "<h3 style='font-size:18px; font-weight:700; color:black; text-align:center;'>📊 **Quantidade por Ação**</h3>",
                    unsafe_allow_html=True
                )
                st.dataframe(
                    s_actions.style.format({"Quantidade": "{:,.0f}"}),
                    use_container_width=True,
                    hide_index=True
                )




        # ==================== Integração CVE (NVD + fallback CIRCL) ====================
        import re

        NVD_BASE = "https://services.nvd.nist.gov/rest/json/cve/1.0/"
        NVD_API_KEY = "1D7F288C-79A4-F011-8362-0EBF96DE670D"

        @st.cache_data(ttl=60*60*24)
        def fetch_cve(cve_id: str):
            """Busca dados do CVE na NVD com fallback automático."""
            headers = {"apiKey": NVD_API_KEY, "User-Agent": "TrendMicroDashboard/1.0"}
            try:
                r = requests.get(f"{NVD_BASE}{cve_id}", headers=headers, timeout=10)
                if r.status_code == 200:
                    j = r.json()
                    item = j.get("result", {}).get("CVE_Items", [])[0]
                    desc = item["cve"]["description"]["description_data"][0]["value"]
                    score = item.get("impact", {}).get("baseMetricV3", {}).get("cvssV3", {}).get("baseScore")
                    refs = [r["url"] for r in item["cve"]["references"]["reference_data"]][:3]
                    return {
                        "source": "NVD",
                        "description": desc,
                        "score": score,
                        "refs": refs,
                        "nvd_url": f"https://nvd.nist.gov/vuln/detail/{cve_id}"
                    }
            except Exception:
                pass
            # fallback CIRCL
            try:
                r = requests.get(f"https://cve.circl.lu/api/cve/{cve_id}", timeout=10)
                if r.status_code == 200:
                    j = r.json()
                    return {
                        "source": "CIRCL.lu",
                        "description": j.get("summary", ""),
                        "score": j.get("cvss", None),
                        "refs": j.get("references", [])[:3],
                        "nvd_url": f"https://nvd.nist.gov/vuln/detail/{cve_id}"
                    }
            except Exception:
                pass
            return {"source": "Desconhecida", "description": "", "score": None, "refs": []}

        # --- Detecção de CVEs nas assinaturas ---
        cve_regex = re.compile(r"(CVE-\d{4}-\d{4,7})", flags=re.IGNORECASE)
        detected_reasons = df_ips["Reason"].astype(str).unique().tolist()
        cves_detectadas = sorted({m.group(1).upper() for r in detected_reasons for m in cve_regex.finditer(r)})

        if cves_detectadas:
            st.markdown("---")
            st.markdown("### 🔎 Detalhes das CVEs Detectadas nas Assinaturas IPS")

            def cvss_color(score):
                if not score:
                    return "#b0b0b0"
                score = float(score)
                if score < 4.0: return "#6cc24a"
                elif score < 7.0: return "#f4c542"
                elif score < 9.0: return "#ff7f27"
                else: return "#e53935"

            for cve in cves_detectadas:
                data = fetch_cve(cve)
                color = cvss_color(data["score"])
                desc_curta = data["description"].split(".")[0] + "." if data["description"] else "(sem descrição)"
                refs_html = "".join(f"<br>🔗 <a href='{r}' target='_blank' style='color:#1a73e8;text-decoration:none;'>{r}</a>" for r in data["refs"])

                st.markdown(f"""
                <div style="
                    border:1px solid #ddd;
                    border-left:8px solid {color};
                    border-radius:10px;
                    padding:15px 20px;
                    margin-bottom:12px;
                    background-color:#fafafa;
                    box-shadow:1px 1px 4px rgba(0,0,0,0.05);
                ">
                    <h4 style="margin-bottom:6px;">{cve}</h4>
                    <p style="margin:0; font-size:15px; color:#333;">
                        <b>CVSSv3:</b> 
                        <span style="color:{color}; font-weight:700;">{data['score'] if data['score'] else 'N/A'}</span>
                        &nbsp;•&nbsp;<b>Fonte:</b> {data['source']}
                    </p>
                    <p style="margin-top:6px; color:#444;">{desc_curta}</p>
                    🔗 <a href="{data['nvd_url']}" target="_blank" style="color:#1a73e8;">Ver detalhes na NVD</a>
                    {refs_html}
                </div>
                """, unsafe_allow_html=True)
        else:
            st.info("Nenhum CVE detectado automaticamente nas assinaturas IPS.")





# ==================== RODAPÉ ====================
st.markdown("---")
st.markdown(
    f"""
    <div style="text-align:center; font-size:13px; color:gray;">
        <img src="https://www.trendmicro.com/content/dam/trendmicro/global/en/global/logo-red.svg" width="120"><br>
        Trend Micro Deep Security Dashboard © {datetime.now().year} — Gerado em {datetime.now().strftime('%d/%m/%Y %H:%M:%S')} Versão 0.1 — Desenvolvido por Renan Bentlin
    </div>
    """,
    unsafe_allow_html=True
)
