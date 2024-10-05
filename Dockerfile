# Use uma imagem base oficial do Python
FROM python:3.8-slim-buster

# Define o diretório de trabalho no container
WORKDIR /app

# Copia os arquivos de requisitos para o diretório de trabalho
COPY requirements.txt .

# Instala as dependências do projeto
RUN pip install --no-cache-dir -r requirements.txt

# Copia o código do projeto para o diretório de trabalho
COPY . .

# Expõe a porta que a aplicação usará
EXPOSE 5000

# Define as variáveis de ambiente
ENV DEBUG=False
ENV HOST=0.0.0.0
ENV PORT=5000

# Comando para rodar a aplicação
CMD ["python", "app/main.py"]