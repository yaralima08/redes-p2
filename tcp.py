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
        """
        Usado pela camada de aplicação para registrar uma função para ser chamada
        sempre que uma nova conexão for aceita
        """
        self.callback = callback

    def _rdt_rcv(self, src_addr, dst_addr, segment):
        src_port, dst_port, seq_no, ack_no, \
            flags, window_size, checksum, urg_ptr = read_header(segment)

        if dst_port != self.porta:
            # Ignora segmentos que não são destinados à porta do nosso servidor
            return
        if not self.rede.ignore_checksum and calc_checksum(segment, src_addr, dst_addr) != 0:
            print('descartando segmento com checksum incorreto')
            return

        payload = segment[4*(flags>>12):]
        id_conexao = (src_addr, src_port, dst_addr, dst_port)

       
        #PASSO 1 Trata a solicitação de abertura de conexão (SYN)
        if (flags & FLAGS_SYN) == FLAGS_SYN:
            # Seleciona um número de sequência inicial (ISN) para o servidor
            seq_no_servidor = random.randint(0, 0xFFFF)
            
            # Instancia a conexão passando os números de sequência e confirmação atualizados
            conexao = self.conexoes[id_conexao] = Conexao(self, id_conexao, seq_no_servidor, seq_no + 1)
            
            # Monta o cabeçalho SYN+ACK
            header = make_header(dst_port, src_port, seq_no_servidor, seq_no + 1, FLAGS_SYN | FLAGS_ACK)
            segmento_syn_ack = fix_checksum(header, dst_addr, src_addr)
            
            # Responde ao cliente através da camada de rede
            self.rede.enviar(segmento_syn_ack, src_addr)

            if self.callback:
                self.callback(conexao)

        elif id_conexao in self.conexoes:
            # Passa para a conexão adequada se ela já estiver estabelecida
            self.conexoes[id_conexao]._rdt_rcv(seq_no, ack_no, flags, payload)
        else:
            print('%s:%d -> %s:%d (pacote associado a conexão desconhecida)' %
                  (src_addr, src_port, dst_addr, dst_port))


class Conexao:
    # PASSO 1 - Construtor recebe os números de sequência e confirmação
    def __init__(self, servidor, id_conexao, seq_no, ack_no):
        self.servidor = servidor
        self.id_conexao = id_conexao
        self.callback = None

        # O segmento SYN enviado/recebido consome 1 número de sequência
        self.seq_no = seq_no + 1
        self.ack_no = ack_no

    def _rdt_rcv(self, seq_no, ack_no, flags, payload):
        # A ser preenchido nos próximos passos
        print('recebido payload: %r' % payload)


    def registrar_recebedor(self, callback):
        """
        Usado pela camada de aplicação para registrar uma função para ser chamada
        sempre que dados forem corretamente recebidos
        """
        self.callback = callback

    def enviar(self, dados):
        """
        Usado pela camada de aplicação para enviar dados
        """
        pass

    def fechar(self):
        """
        Usado pela camada de aplicação para fechar a conexão
        """
        pass