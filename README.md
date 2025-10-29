# Carteiras Fictícias — App Streamlit

App simples em Streamlit para gerenciamento de carteiras com moedas fictícias.  
Funcionalidades principais:
- Cadastro e login por usuário (senha com salt + hash SHA‑256).
- Carteira por usuário com saldos para moedas: **Libra, Ducado, Florim, Denário, Coroa**.
- Conversão entre moedas com base em taxas definidas (base: Libra).
- Edição visual de saldos, operações rápidas (adicionar/subtrair) e export/import JSON por usuário.
- Armazenamento em arquivo texto chamado **carteiras.txt** (cada linha é um JSON).

---

## Arquivos principais
- **beta0.py** — código do app Streamlit (arquivo principal).
- **requirements.txt** — dependências (conteúdo mínimo acima).
- **carteiras.txt** — arquivo de dados (não deve ser comitado com dados sensíveis).

---

## Como executar localmente

1. Clonar o repositório:
```bash
git clone https://github.com/SEU_USUARIO/NOME_REPO.git
cd NOME_REPO
```

2. Criar ambiente virtual e ativar:
- Linux / macOS:
```bash
python -m venv .venv
source .venv/bin/activate
```
- Windows (PowerShell):
```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
```

3. Instalar dependências:
```bash
pip install -r requirements.txt
```

4. Rodar o app:
```bash
streamlit run beta0.py
```

O app abrirá no navegador em http://localhost:8501 por padrão.

---

## Deploy (resumo rápido)
Opções simples:
- Streamlit Community Cloud: conectar repositório GitHub e fazer deploy indicando `beta0.py` como script de execução.
- Render / Railway: usar o comando de start
```bash
streamlit run beta0.py --server.port $PORT --server.enableCORS false
```
e configurar o build command `pip install -r requirements.txt`.

Observação: em plataformas gerenciadas, o arquivo `carteiras.txt` fica no sistema do contêiner e pode não persistir entre deploys; para persistência duradoura, migre para SQLite / banco externo.

---

## Segurança e boas práticas
- Não comite `carteiras.txt` com dados reais. Adicione-o ao `.gitignore`.
- Para produção, use hashing forte (bcrypt/argon2) e transporte seguro (HTTPS).
- Considere migrar para SQLite, Postgres ou armazenamento em nuvem para concorrência, backups e escalabilidade.

---

## Licença e contato
- Arquivo de código: livre para uso e adaptação. Adapte conforme necessidade.
- Se quiser, posso gerar um arquivo adicional `.gitignore` e um exemplo de workflow para deploy automático.
