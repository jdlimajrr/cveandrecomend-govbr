# Definindo a imagem base
FROM python:3.9-slim

# Definindo o diretório de trabalho
WORKDIR /app

# Copiando o código fonte para o diretório de trabalho
COPY . .

# Instalando as dependências
RUN pip install --no-cache-dir -r requirements.txt

# Expondo a porta 80
EXPOSE 80

# Executando o script Python
CMD ["python", "main.py"]
