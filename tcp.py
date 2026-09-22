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

        #PASSO 1 Trata abertura de conexão (Handshake SYN)
        if (flags & FLAGS_SYN) == FLAGS_SYN:
            # Seleciona número de sequência inicial para o servidor
            seq_no_servidor = random.randint(0, 0xFFFF)
            
            # Instancia a conexão salvando seq_no e ack_no
            conexao = self.conexoes[id_conexao] = Conexao(self, id_conexao, seq_no_servidor, seq_no + 1)
            
            # Monta o cabeçalho com a flag SYN+ACK e responde ao cliente
            header = make_header(dst_port, src_port, seq_no_servidor, seq_no + 1, FLAGS_SYN | FLAGS_ACK)
            segmento_syn_ack = fix_checksum(header, dst_addr, src_addr)
            self.rede.enviar(segmento_syn_ack, src_addr)

            if self.callback:
                self.callback(conexao)

        elif id_conexao in self.conexoes:
            # Se a conexão já existe, repassa o segmento para ela tratar
            self.conexoes[id_conexao]._rdt_rcv(seq_no, ack_no, flags, payload)
        else:
            print('%s:%d -> %s:%d (pacote associado a conexão desconhecida)' %
                  (src_addr, src_port, dst_addr, dst_port))


class Conexao:
    #PASSO 1 Guardar estado dos números de sequência
    def __init__(self, servidor, id_conexao, seq_no, ack_no):
        self.servidor = servidor
        self.id_conexao = id_conexao
        self.callback = None

        self.seq_no = seq_no + 1  
        self.ack_no = ack_no     

    def _rdt_rcv(self, seq_no, ack_no, flags, payload):
        #PASSO 2 Recebimento de dados em ordem e envio de ACK
        src_addr, src_port, dst_addr, dst_port = self.id_conexao

        # Checa se vieram dados e se estão na ordem esperada (seq_no == self.ack_no)
        if payload and seq_no == self.ack_no:
            # Atualiza a contagem de bytes recebidos para o próximo ACK
            self.ack_no += len(payload)

            # Envia confirmação (ACK) com payload vazio de volta para o cliente
            header = make_header(dst_port, src_port, self.seq_no, self.ack_no, FLAGS_ACK)
            segmento_ack = fix_checksum(header, dst_addr, src_addr)
            self.servidor.rede.enviar(segmento_ack, src_addr)

            # Notifica a camada de aplicação passando os dados recebidos
            if self.callback:
                self.callback(self, payload)

    def registrar_recebedor(self, callback):
        self.callback = callback

    def enviar(self, dados):
        pass

    def fechar(self):
        pass