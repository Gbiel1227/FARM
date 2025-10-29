# beta0.py
import streamlit as st
import json
import os
import uuid
import hashlib
from typing import Dict

st.set_page_config(page_title="Carteira de Moedas Fictícias - Login", layout="wide")

# -----------------------------
# Configuração de moedas e taxas (base: Libra)
# -----------------------------
CURRENCIES = ["Libra", "Ducado", "Florim", "Denário", "Coroa"]
SYMBOLS = {"Libra": "£", "Ducado": "Ð", "Florim": "ƒ", "Denário": "d", "Coroa": "¤"}
RATES_TO_LIBRA = {
    "Libra": 1.0,
    "Ducado": 1 / 1.5,
    "Florim": 1 / 1.3,
    "Denário": 1 / 1.8,
    "Coroa": 1 / 1.2,
}

def convert(amount: float, from_cur: str, to_cur: str) -> float:
    if from_cur == to_cur:
        return amount
    amount_in_libra = amount * RATES_TO_LIBRA[from_cur]
    return amount_in_libra / RATES_TO_LIBRA[to_cur]

# -----------------------------
# Arquivo de armazenamento
# -----------------------------
DB_FILE = "carteiras.txt"

def load_all() -> Dict[str, Dict]:
    data = {}
    if not os.path.exists(DB_FILE):
        return data
    try:
        with open(DB_FILE, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    entry = json.loads(line)
                    if entry.get("type") == "user" and "username" in entry:
                        data[entry["username"]] = entry
                except Exception:
                    continue
    except Exception:
        pass
    return data

def save_all(records: Dict[str, Dict]):
    tmp = DB_FILE + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        for username, rec in records.items():
            f.write(json.dumps(rec, ensure_ascii=False) + "\n")
    os.replace(tmp, DB_FILE)

def hash_password(password: str, salt: str) -> str:
    h = hashlib.sha256()
    h.update((salt + password).encode("utf-8"))
    return h.hexdigest()

def make_wallet_template():
    return {cur: 0.0 for cur in CURRENCIES}

# -----------------------------
# Sessão e estado
# -----------------------------
if "auth_user" not in st.session_state:
    st.session_state.auth_user = None
if "auth_salt" not in st.session_state:
    st.session_state.auth_salt = None

# variável local de leitura/escrita do arquivo
records = load_all()

# -----------------------------
# Funções de fluxo de autenticação (sem chamar rerun)
# -----------------------------
def signup(username: str, password: str, auto_login: bool = False):
    uname = username.strip()
    if not uname:
        st.error("Usuário inválido.")
        return
    if uname in records:
        st.error("Usuário já existe.")
        return
    salt = uuid.uuid4().hex
    pwd_hash = hash_password(password, salt)
    rec = {"type": "user", "username": uname, "pwd_hash": pwd_hash, "salt": salt, "wallet": make_wallet_template()}
    records[uname] = rec
    save_all(records)
    st.success("Cadastro realizado.")
    if auto_login:
        st.session_state.auth_user = uname
        st.session_state.auth_salt = salt

def login(username: str, password: str):
    uname = username.strip()
    rec = records.get(uname)
    if not rec:
        st.error("Usuário não encontrado.")
        return
    salt = rec.get("salt", "")
    expected = rec.get("pwd_hash", "")
    if hash_password(password, salt) != expected:
        st.error("Senha incorreta.")
        return
    st.session_state.auth_user = uname
    st.session_state.auth_salt = salt

def logout():
    st.session_state.auth_user = None
    st.session_state.auth_salt = None

# -----------------------------
# Utilitários
# -----------------------------
def parse_float_input(s: str):
    """Converte string para float; retorna None se inválido ou vazia."""
    if s is None:
        return None
    s = s.strip()
    if s == "":
        return None
    try:
        s = s.replace(",", ".")
        return float(s)
    except Exception:
        return None

# -----------------------------
# Interface: sempre renderiza os formulários; a carteira aparece quando auth_user é setado
# -----------------------------
st.title("Carteira de Moedas Fictícias")

# Recarrega registros do arquivo sempre no começo para evitar divergências
records = load_all()

# Colunas de Acesso (login e cadastro)
st.header("Acesso")
cola, colb = st.columns(2)

with cola:
    st.subheader("Entrar")
    login_user = st.text_input("Usuário (login)", key="login_user")
    login_pwd = st.text_input("Senha", type="password", key="login_pwd")
    if st.button("Login"):
        login(login_user, login_pwd)

with colb:
    st.subheader("Cadastrar")
    new_user = st.text_input("Usuário (novo)", key="new_user")
    new_pwd = st.text_input("Senha", type="password", key="new_pwd")
    new_pwd2 = st.text_input("Confirmar senha", type="password", key="new_pwd2")
    auto_login_checkbox = st.checkbox("Entrar automaticamente após cadastro", value=False, key="auto_login")
    if st.button("Cadastrar"):
        if not new_user.strip():
            st.error("Informe um nome de usuário.")
        elif not new_pwd:
            st.error("Informe uma senha.")
        elif new_pwd != new_pwd2:
            st.error("As senhas não coincidem.")
        else:
            signup(new_user, new_pwd, auto_login=auto_login_checkbox)

st.markdown("---")
st.caption("Os dados são gravados no arquivo 'carteiras.txt' no diretório atual. Cada linha é um JSON representando um usuário e sua carteira.")

# Se autenticado, mostrar a carteira na mesma execução (sem rerun)
if st.session_state.auth_user is not None:
    # recarrega registros para pegar versão mais recente
    records = load_all()
    username = st.session_state.auth_user
    user_rec = records.get(username)
    if not user_rec:
        st.error("Registro do usuário não encontrado. Faça login novamente.")
        st.session_state.auth_user = None
    else:
        st.header(f"Carteira de {username}")
        if st.button("Sair"):
            logout()
        wallet = user_rec.get("wallet", make_wallet_template())

        col1, col2 = st.columns([3, 2])

        with col1:
            st.subheader("Saldos (visual) e entrada vazia para atualizar")
            st.markdown("Cada linha exibe saldo, campo vazio para novo valor e botão Atualizar. O campo é limpo após salvar.")
            # para cada moeda: alinhar em uma linha: saldo | input vazio (placeholder) | botão Atualizar
            # --- substitua o loop antigo por este ---
            for cur in CURRENCIES:
                cur_sym = SYMBOLS.get(cur, "")
                current = float(wallet.get(cur, 0.0))

                # chaves para input, botão e flag de limpeza
                inp_key = f"{username}_{cur}_set"
                btn_key = f"{username}_btn_set_{cur}"
                clear_flag = f"{inp_key}_to_clear"

                # se a flag de limpeza estiver setada, limpe o valor antes de instanciar o widget
                if st.session_state.get(clear_flag, False):
                    st.session_state[inp_key] = ""
                    st.session_state[clear_flag] = False

                # cria 3 colunas em uma linha: saldo | input | botão
                c_left, c_mid, c_right = st.columns([2, 2, 1])
                with c_left:
                    if abs(current) > 1e-12:
                        st.write(f"**{cur}**: {current:.2f} {cur_sym}")
                    else:
                        st.write(f"**{cur}**: {current:.2f} {cur_sym}")

                # garante que exista uma chave no session_state (valor inicial vazio)
                if inp_key not in st.session_state:
                    st.session_state[inp_key] = ""

                placeholder = f"{current:.2f} {cur_sym}" if abs(current) > 1e-12 else "Informe novo valor"
                with c_mid:
                    # o text_input usa o valor já guardado em session_state (normalmente "")
                    val_str = st.text_input("", placeholder=placeholder, key=inp_key)

                with c_right:
                    if st.button("Atualizar", key=btn_key):
                        parsed = parse_float_input(st.session_state.get(inp_key, ""))
                        if parsed is None:
                            st.error("Valor inválido. Use apenas números, exemplo: 123.45")
                        else:
                            wallet[cur] = float(parsed)
                            user_rec["wallet"] = wallet
                            records = load_all()
                            records[username] = user_rec
                            save_all(records)
                            st.success(f"Saldo de {cur} atualizado para {parsed:.2f} {cur_sym}")
                            # marca a flag para que, no próximo rerun, o campo seja esvaziado antes de instanciar o widget
                            st.session_state[clear_flag] = True
            # --- fim do loop ---

            st.markdown("---")
            st.subheader("Salvar carteira (persistir todas alterações locais)")
            if st.button("Salvar carteira"):
                user_rec["wallet"] = wallet
                records = load_all()
                records[username] = user_rec
                save_all(records)
                st.success("Carteira salva.")

            st.markdown("---")
            st.subheader("Operações rápidas")
            op_amt = st.number_input("Quantidade", value=0.0, format="%.2f", step=0.1, key=f"{username}_op_amt")
            op_cur = st.selectbox("Moeda", CURRENCIES, key=f"{username}_op_cur")
            op_type = st.radio("Tipo", ("Adicionar", "Subtrair"), key=f"{username}_op_type")
            if st.button("Aplicar operação"):
                if op_type == "Adicionar":
                    wallet[op_cur] = wallet.get(op_cur, 0.0) + float(op_amt)
                else:
                    wallet[op_cur] = wallet.get(op_cur, 0.0) - float(op_amt)
                user_rec["wallet"] = wallet
                records = load_all()
                records[username] = user_rec
                save_all(records)
                st.success("Operação aplicada e carteira salva.")

        with col2:
            st.subheader("Visão consolidada")
            target = st.selectbox("Converter valores para", CURRENCIES, index=0, key=f"{username}_target")
            st.markdown("**Saldos detalhados convertidos**")
            total_in_target = 0.0
            for cur in CURRENCIES:
                amt = float(wallet.get(cur, 0.0))
                converted = convert(amt, cur, target)
                total_in_target += converted
                st.write(f"- **{cur}**: {amt:.2f} {SYMBOLS.get(cur,'')}  →  {converted:.2f} {SYMBOLS.get(target,'')}")

            st.markdown("---")
            st.subheader(f"Total em {target} ({SYMBOLS.get(target,'')}): {total_in_target:.2f}")

            st.markdown("---")
            st.subheader("Export / Import")
            if st.button("Recarregar dados do arquivo"):
                records = load_all()
                user_rec = records.get(username, user_rec)
                wallet = user_rec.get("wallet", wallet)
                st.success("Dados recarregados.")

            st.markdown("Linha JSON desta conta em carteiras.txt:")
            st.code(json.dumps(user_rec, ensure_ascii=False), language="json")

        st.markdown("---")
        st.caption("Use 'Sair' para terminar a sessão. Para produção, considere usar um banco de dados e políticas de segurança mais robustas.")
