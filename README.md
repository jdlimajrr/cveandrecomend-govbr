Projeto de monitoramento de vulnerabilidades
Este projeto é uma ferramenta de monitoramento de vulnerabilidades baseada em Python que busca periodicamente por novas vulnerabilidades críticas em produtos de diversos fabricantes.

O projeto utiliza a API do National Vulnerability Database (NVD) para buscar informações sobre as vulnerabilidades mais recentes e críticas. Caso seja encontrada uma nova vulnerabilidade crítica, a ferramenta envia uma mensagem para um grupo do Telegram informando sobre a vulnerabilidade.

Requisitos
Python 3.9 ou superior
Uma chave de API válida para acessar a API do NVD
Um token de bot do Telegram e um chat_id válido para receber as mensagens de alerta
Configuração
Clone este repositório em sua máquina local:
git clone https://github.com/jdlimajrr/cveandrecomend-govbr.git
Crie um arquivo secrets.py na raiz do projeto com as seguintes informações:
NVD_API_KEY = 'sua chave de API do NVD'
TELEGRAM_BOT_TOKEN = 'seu token de bot do Telegram'
TELEGRAM_CHAT_ID = 'seu chat_id do Telegram'
Execute o script main.py com o seguinte comando:
python main.py
Personalização
O script pode ser personalizado para buscar informações sobre produtos de outros fabricantes, adicionando ou removendo nomes de fabricantes na lista manufacturers dentro do arquivo main.py.

Contribuição
Contribuições são bem-vindas! Sinta-se à vontade para criar um pull request com suas melhorias ou correções.

Para utilizar este projeto como um contêiner Docker, siga as seguintes instruções:

Certifique-se de ter o Docker instalado na sua máquina.

Clone o repositório do projeto para a sua máquina.

Navegue até o diretório do projeto.

Crie a imagem do Docker executando o comando:

docker build -t nome_da_imagem .
Substitua "nome_da_imagem" pelo nome que você deseja dar para a imagem.

Para executar o contêiner, você pode usar o comando docker run e fornecer as portas a serem expostas, como -p 8080:80, que irá mapear a porta 80 do contêiner para a porta 8080 do host. O comando completo seria algo como:

docker run -p 8080:80 my_image_name
Isso irá executar o contêiner e deixar o script em execução, permitindo que você acesse os resultados por meio do Telegram.

Nota: Certifique-se de que o arquivo main.py esteja presente no diretório raiz do seu projeto e que todas as dependências estejam listadas no arquivo requirements.txt.
