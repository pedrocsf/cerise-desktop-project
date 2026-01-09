# 4 Rede (Networking)

Observabilidade de tráfego no nível de processo.

## Scripts

**tcp_established.bt**: conexão TCP bem sucedida  
**tcp_v4_connect.bt**: tentativas de conexões TCP  
**tcp_destroy.bt**: conexão TCP encerrada  
**tcp_send_reset.bt** e **tcp_receive_reset.bt**: resets de TCP (fim anormal de conexão)  
**tcp_retransmit_skb.bt**: retransmissão de pacotes TCP (novo envio de pacote)  
**tcp_retransmit.bt**: rastreamento de retransmissões TCP  
**tcp_bad_csum.bt**: erros de checksum (pacote TCP chega corrompido)  
**tcp_cong_state_set.bt**: mudança de estado de controle de congestionamento TCP  
**udp_traffic.bt**: monitoramento de tráfego UDP (envio e recebimento)

## O que monitora

- Criação de sockets
- Conexões TCP/UDP
- DNS
- Quantidade de bytes enviados/recebidos
- Processo ↔ IP ↔ Porta

