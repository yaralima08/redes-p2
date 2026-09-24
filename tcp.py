import asyncio
import random      
from tcputils import *


class Servidor:
    def __init__(self, rede, porta):
        self.rede = rede
        self.porta = porta
        self.conexoes = {}
        self.callback = None
        self.rede.registrar_recebedor(self._rdt_rcv)

    def registrar_monitor_de_conexoes_aceitas(self, callback):
        self.callback = callback

    def _rdt_rcv(self, src_addr, dst_addr, segment):
        src_port, dst_port, seq_no, ack_no, \
            flags, window_size, checksum, urg_ptr = read_header(segment)

        if dst_port != self.porta:
            return
        if not self.rede.ignore_checksum and calc_checksum(segment, src_addr, dst_addr) != 0:
            print('descartando segmento com checksum incorreto')
            return

        payload = segment[4*(flags>>12):]
        id_conexao = (src_addr, src_port, dst_addr, dst_port)

    
        #PASSO 1 Handshake TCP (Trata o segmento SYN)
    
        if (flags & FLAGS_SYN) == FLAGS_SYN:
            seq_no_servidor = random.randint(0, 0xFFFF)
            conexao = self.conexoes[id_conexao] = Conexao(self, id_conexao, seq_no_servidor, seq_no + 1)
            
            header = make_header(dst_port, src_port, seq_no_servidor, seq_no + 1, FLAGS_SYN | FLAGS_ACK)
            segmento_syn_ack = fix_checksum(header, dst_addr, src_addr)
            self.rede.enviar(segmento_syn_ack, src_addr)

            if self.callback:
                self.callback(conexao)

        elif id_conexao in self.conexoes:
            self.conexoes[id_conexao]._rdt_rcv(seq_no, ack_no, flags, payload)
        else:
            print('%s:%d -> %s:%d (pacote associado a conexão desconhecida)' %
                  (src_addr, src_port, dst_addr, dst_port))


class Conexao:

    #PASSO 1 Inicialização e estado da conexão

    def __init__(self, servidor, id_conexao, seq_no, ack_no):
        self.servidor = servidor
        self.id_conexao = id_conexao
        self.callback = None

        self.seq_no = seq_no + 1 
        self.ack_no = ack_no    

    def _rdt_rcv(self, seq_no, ack_no, flags, payload):
        src_addr, src_port, dst_addr, dst_port = self.id_conexao

        #PASSO 4 Trata pedido de fechamento do cliente (FIN)
    
        if flags & FLAGS_FIN:
            self.ack_no = seq_no + 1  # FIN consome 1 número de sequência
            
            # Envia ACK confirmando o recebimento do FIN
            header = make_header(dst_port, src_port, self.seq_no, self.ack_no, FLAGS_ACK)
            segmento_ack = fix_checksum(header, dst_addr, src_addr)
            self.servidor.rede.enviar(segmento_ack, src_addr)

            if self.callback:
                self.callback(self, b'')
            
            # Remove a conexão encerrada da tabela de conexões do servidor
            if self.id_conexao in self.servidor.conexoes:
                del self.servidor.conexoes[self.id_conexao]
            return

    
        #PASSO 2 Recebimento de dados e envio de ACK
    
        if payload and seq_no == self.ack_no:
            self.ack_no += len(payload)

            header = make_header(dst_port, src_port, self.seq_no, self.ack_no, FLAGS_ACK)
            segmento_ack = fix_checksum(header, dst_addr, src_addr)
            self.servidor.rede.enviar(segmento_ack, src_addr)

            if self.callback:
                self.callback(self, payload)

    def registrar_recebedor(self, callback):
        self.callback = callback


    #PASSO 3 Envio de dados pela aplicação

    def enviar(self, dados):
        src_addr, src_port, dst_addr, dst_port = self.id_conexao

        for i in range(0, len(dados), MSS):
            payload = dados[i:i + MSS]
            header = make_header(dst_port, src_port, self.seq_no, self.ack_no, FLAGS_ACK)
            segmento = fix_checksum(header + payload, dst_addr, src_addr)

            self.servidor.rede.enviar(segmento, src_addr)
            self.seq_no += len(payload)


    #PASSO 4 Fechamento ativamente iniciado pelo servidor
    def fechar(self):
        src_addr, src_port, dst_addr, dst_port = self.id_conexao

        # Monta e envia o segmento com a flag FIN ativada
        header = make_header(dst_port, src_port, self.seq_no, self.ack_no, FLAGS_FIN | FLAGS_ACK)
        segmento_fin = fix_checksum(header, dst_addr, src_addr)

        self.servidor.rede.enviar(segmento_fin, src_addr)
        self.seq_no += 1