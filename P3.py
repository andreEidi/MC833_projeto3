from scapy.all import *
import numpy as np

def analisar_pcap(file):
    # Ler o arquivo PCAP
    pacotes = rdpcap(file)
    
    # Filtragem dos pacotes, quereomos analisar somente os pacotes ICMP
    pacotes_icmp = []
    for pct in pacotes:
        if ICMP in pct:
            pacotes_icmp.append(pct)

    # cria listas para melhor organizar os dados
    ip_origem = []
    ip_destino = []
    marcadores_tempo = []
    tamanho_pacotes = []

    # Extrai informações de cada pacote
    for pct in pacotes_icmp:
        ip_origem.append(pct[IP].src)
        ip_destino.append(pct[IP].dst)
        marcadores_tempo.append(pct.time)
        tamanho_pacotes.append(len(pct))

    # Conta a quantidade de pacotes ICMP registrados
    contagem_pacotes = len(pacotes_icmp)

    # Calcular a taxa de transferência (throughput) média em bytes por segundo
    if contagem_pacotes > 1:
        tempo_total = marcadores_tempo[-1] - marcadores_tempo[0]
        tamanho_total = sum(tamanho_pacotes)
        throughput = tamanho_total / tempo_total if tempo_total > 0 else 0
    else:
        throughput = 0

    # Calcular o intervalo médio entre pacotes
    if contagem_pacotes > 1:
        intervalos = np.diff(marcadores_tempo).astype(float)
        intervalo_medio = np.mean(intervalos)
    else:
        intervalo_medio = 0


    print(f"Endereços IP de origem: {set(ip_origem)}")
    print(f"Endereços IP de destino: {set(ip_destino)}")
    print(f"Contagem de pacotes: {contagem_pacotes}")
    print(f"Throughput médio (bytes/s): {throughput}")
    print(f"Intervalo médio entre pacotes (s): {intervalo_medio}")

if __name__ == "__main__":
    file = "h2h4_500.pcap"
    resultado = analisar_pcap(file)
