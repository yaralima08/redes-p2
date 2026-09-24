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

        #PASSO 1Handshake TCP (SYN handling)
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
    def __init__(self, servidor, id_conexao, seq_no, ack_no):
        self.servidor = servidor
        self.id_conexao = id_conexao
        self.callback = None

        self.seq_no = seq_no + 1  
        self.ack_no = ack_no     

        #PASSO 5  Estado para temporizador e retransmissões
        self.pacotes_nao_confirmados = [] 
        self.timer = None
        self.timeout_interval = 0.5  

    def _rdt_rcv(self, seq_no, ack_no, flags, payload):
        src_addr, src_port, dst_addr, dst_port = self.id_conexao

        #PASSO 5 Processar confirmações (ACKs) recebidas
        if flags & FLAGS_ACK:
            self._processar_ack(ack_no)

        #PASSO 4 Tratar solicitação de encerramento do cliente 
        if flags & FLAGS_FIN:
            self.ack_no = seq_no + 1
            
            header = make_header(dst_port, src_port, self.seq_no, self.ack_no, FLAGS_ACK)
            segmento_ack = fix_checksum(header, dst_addr, src_addr)
            self.servidor.rede.enviar(segmento_ack, src_addr)

            if self.callback:
                self.callback(self, b'')
            
            if self.id_conexao in self.servidor.conexoes:
                del self.servidor.conexoes[self.id_conexao]
            return

        #PASSO 2 Recebimento de dados em ordem
        if payload and seq_no == self.ack_no:
            self.ack_no += len(payload)

            header = make_header(dst_port, src_port, self.seq_no, self.ack_no, FLAGS_ACK)
            segmento_ack = fix_checksum(header, dst_addr, src_addr)
            self.servidor.rede.enviar(segmento_ack, src_addr)

            if self.callback:
                self.callback(self, payload)

    def registrar_recebedor(self, callback):
        self.callback = callback

    #PASSO 3 + PASSO 5 Envio de dados com buffer de retransmissão
    def enviar(self, dados):
        src_addr, src_port, dst_addr, dst_port = self.id_conexao

        for i in range(0, len(dados), MSS):
            payload = dados[i:i + MSS]
            header = make_header(dst_port, src_port, self.seq_no, self.ack_no, FLAGS_ACK)
            segmento = fix_checksum(header + payload, dst_addr, src_addr)

            self.servidor.rede.enviar(segmento, src_addr)

            self.pacotes_nao_confirmados.append((self.seq_no, segmento, len(payload)))
            self.seq_no += len(payload)

            #PASSO 5 Inicia o temporizador se ele não estiver rodando
            if self.timer is None:
                self._iniciar_timer()

    def _iniciar_timer(self):
        if self.timer:
            self.timer.cancel()
        self.timer = asyncio.get_event_loop().call_later(
            self.timeout_interval, self._timeout
        )

    def _parar_timer(self):
        if self.timer:
            self.timer.cancel()
            self.timer = None

    def _timeout(self):
        self.timer = None
        if self.pacotes_nao_confirmados:
            # Retransmite o pacote mais antigo ainda não confirmado
            _, segmento, _ = self.pacotes_nao_confirmados[0]
            src_addr = self.id_conexao[0]
            self.servidor.rede.enviar(segmento, src_addr)
            
            # Reinicia o temporizador para a retransmissão
            self._iniciar_timer()

    def _processar_ack(self, ack_no):
        # Remove da lista de pendentes todos os pacotes totalmente confirmados pelo ack_no
        pacotes_restantes = []
        for seq, segmento, tamanho in self.pacotes_nao_confirmados:
            if seq + tamanho <= ack_no:
                continue  # Pacote foi confirmado
            pacotes_restantes.append((seq, segmento, tamanho))

        self.pacotes_nao_confirmados = pacotes_restantes

        # Reinicia ou para o temporizador dependendo do estado do buffer
        if self.pacotes_nao_confirmados:
            self._iniciar_timer()
        else:
            self._parar_timer()

    #PASSO 4 Fechamento ativamente iniciado pelo servidor
    def fechar(self):
        src_addr, src_port, dst_addr, dst_port = self.id_conexao

        header = make_header(dst_port, src_port, self.seq_no, self.ack_no, FLAGS_FIN | FLAGS_ACK)
        segmento_fin = fix_checksum(header, dst_addr, src_addr)

        self.servidor.rede.enviar(segmento_fin, src_addr)
        self.seq_no += 1