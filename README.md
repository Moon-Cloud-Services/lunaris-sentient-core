# Lunaris Sentient Core

Lunaris Sentient Core é um sistema de detecção de malware baseado em aprendizado de máquina. Ele permite o treinamento de modelos de detecção de malware e o escaneamento de arquivos para identificar possíveis ameaças.

## Tabela de Conteúdos

- [Instalação](#instalação)
- [Uso](#uso)

## Instalação

### Pré-requisitos

- Python 3.8 ou superior
- pip (gerenciador de pacotes do Python)

### Passos para Instalação

1. Clone o repositório:

    ```sh
    git clone https://github.com/Moon-Cloud-Services/lunaris-sentient-core.git
    cd lunaris-sentient-core
    ```

2. Crie um ambiente virtual:

    ```sh
    python -m venv venv
    source venv/bin/activate  # No Windows, use `venv\Scripts\activate`
    ```

3. Instale as dependências:

    ```sh
    pip install -r requirements.txt
    ```

4. Configure as variáveis de ambiente:

    Crie um arquivo `.env` na raiz do projeto e adicione as seguintes variáveis:

    ```env
    SECRET_KEY=sua_chave_secreta
    ```

## Uso

### Executando o Servidor

Para iniciar o servidor Flask, execute:

```sh
python -m lunaris-system.lunaris-core.app.main
```

### Acessando a Aplicação

Abra o navegador e acesse `http://127.0.0.1:5000/`.

### Treinando o Modelo

1. Acesse a página de upload em `http://127.0.0.1:5000/upload_page`.
2. Faça o upload de arquivos de malware e não-malware para treinamento.
3. Clique no botão "Train Model" para treinar o modelo.

### Escaneando Arquivos

1. Acesse a página de upload em `http://127.0.0.1:5000/upload_page`.
2. Faça o upload de um arquivo para escaneamento.
3. O resultado do escaneamento será exibido na página.
